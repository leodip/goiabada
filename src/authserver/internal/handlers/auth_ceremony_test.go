package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// testCeremonyId is the id the step handlers' cases share: the auth context holds it, the submitted
// form names it in its body, and the page load names it in the URL, which is what a browser sends
// from a page that ceremony rendered or a redirect it followed. A case that means to be refused
// departs from it deliberately (#79, #246). It has the shape of a real one, so it passes
// ceremony.IsWellFormedId.
//
// Here rather than in one handler's test file, because every step's cases use it and none of them
// owns the mechanism.
const testCeremonyId = "test-ceremony-id-0123456789abcde"

// assertStepLocation asserts that a redirect goes to a ceremony route under the base URL and names
// the ceremony it came from, and returns the id it names. Every redirect between two ceremony routes
// carries it (#246 decision 22), and this is the one place a handler case says so for a redirect
// whose id it cannot spell out: /auth/authorize draws a fresh one, so a case that holds the context
// it saved compares the id it gets back with that context's. msgAndArgs are testify's.
func assertStepLocation(t testing.TB, location string, path string, msgAndArgs ...interface{}) string {
	t.Helper()

	parsed, err := url.Parse(location)
	require.NoError(t, err, msgAndArgs...)
	assert.Equal(t, testBaseURL+path, parsed.Scheme+"://"+parsed.Host+parsed.Path, msgAndArgs...)

	query := parsed.Query()
	assert.Len(t, query, 1, "the redirect names the ceremony and nothing else")
	ids := query[ceremony.QueryParameter]
	require.Len(t, ids, 1, "the redirect must name exactly one ceremony")
	assert.True(t, ceremony.IsWellFormedId(ids[0]),
		"the ceremony a redirect names is an id and not a value copied from anywhere: %q", ids[0])
	return ids[0]
}

// expectCeremonyMismatch sets the two calls rejectCeremonyMismatch makes, and asserts the page it
// renders is the 400 error page rather than anything belonging to the flow that was submitted.
func expectCeremonyMismatch(t *testing.T, pageRenderer *handlersmocks.PageRenderer,
	auditLogger *handlersmocks.AuditLogger, rr *httptest.ResponseRecorder, req *http.Request) {
	t.Helper()

	auditLogger.On("Log", mock.Anything, audit.EventAuthCeremonyMismatch, mock.Anything).Return().Once()
	pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["_httpStatus"] == http.StatusBadRequest &&
				data["title"] != "" && data["error"] != ""
		})).Return(nil).Once()
}

// holdingCeremony is the ceremony store as the auth server builds it, over an in-memory backend, with
// held stored in a browser session as /auth/authorize stores it, and the cookies naming that session.
// A case whose request is refused for the ceremony it names is driven through it, so the rule that
// decides which ceremony a request names is the store's own (ceremony.RequestedId) and not a mock's.
func holdingCeremony(t *testing.T, held *ceremony.AuthContext) (*ceremony.Store, []*http.Cookie) {
	t.Helper()
	ceremonyStore, _ := newRealCeremonyStore(t)
	seed := httptest.NewRecorder()
	require.NoError(t, ceremonyStore.AddAuthContext(seed, httptest.NewRequest(http.MethodGet, "/auth/authorize", nil), held))
	cookies := seed.Result().Cookies()
	require.Len(t, cookies, 1)
	return ceremonyStore, cookies
}

// expectCeremonyMismatchOf is expectCeremonyMismatch with the audit event's details pinned to the
// ceremony the browser most recently wrote, which is what the event records whatever the request
// named (#246 decision 5).
func expectCeremonyMismatchOf(t *testing.T, pageRenderer *handlersmocks.PageRenderer,
	auditLogger *handlersmocks.AuditLogger, rr *httptest.ResponseRecorder, req *http.Request,
	latest *ceremony.AuthContext) {
	t.Helper()

	auditLogger.On("Log", mock.Anything, audit.EventAuthCeremonyMismatch,
		mock.MatchedBy(func(details map[string]interface{}) bool {
			userId, named := details["user_id"]
			return details["client_identifier"] == latest.ClientId &&
				details["auth_state"] == string(latest.AuthState) &&
				named == (latest.UserId != 0) && (!named || userId == latest.UserId)
		})).Return().Once()
	pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["_httpStatus"] == http.StatusBadRequest &&
				data["title"] == i18n.T(req.Context(), "auth_error.ceremony_mismatch.title") &&
				data["error"] == i18n.T(req.Context(), "auth_error.ceremony_mismatch.message")
		})).Return(nil).Once()
}

// assertStillHeld asserts that the browser session still holds want as it was, which is what a
// refused request leaves it: the ceremony the user is working on in another tab, untouched.
func assertStillHeld(t *testing.T, ceremonyStore *ceremony.Store, cookies []*http.Cookie, want *ceremony.AuthContext) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/level1", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	held, err := ceremonyStore.LatestAuthContext(req)
	require.NoError(t, err)
	assert.Equal(t, want, held)
}

// expectCeremonyNoLongerActive sets the one call renderCeremonyNoLongerActive makes, and asserts it
// is the ceremony mismatch pair at 400. It sets no audit expectation: /auth/completed answers a stale
// bind with this page and records no ceremony mismatch, because the request named its ceremony
// correctly (#538).
func expectCeremonyNoLongerActive(t *testing.T, pageRenderer *handlersmocks.PageRenderer,
	rr *httptest.ResponseRecorder, req *http.Request) {
	t.Helper()

	pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["_httpStatus"] == http.StatusBadRequest &&
				data["title"] == i18n.T(req.Context(), "auth_error.ceremony_mismatch.title") &&
				data["error"] == i18n.T(req.Context(), "auth_error.ceremony_mismatch.message")
		})).Return(nil).Once()
}

// expectAuthStateMismatch sets the one call requireAuthState makes on a refusal, and asserts the
// page it renders is the 400 error page rather than a 500 with a stack, which is what ten of these
// eleven sites answered before #279 decision 21 and /auth/level1completed until #436.
//
// It asserts the state_mismatch pair specifically and not merely "some title": the ceremony
// mismatch page beside it says the sign-in can no longer continue, which is not what the Back button
// did, and a helper that accepted either would let the two pages be confused.
func expectAuthStateMismatch(t *testing.T, pageRenderer *handlersmocks.PageRenderer,
	rr *httptest.ResponseRecorder, req *http.Request) {
	t.Helper()

	pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["_httpStatus"] == http.StatusBadRequest &&
				data["title"] == i18n.T(req.Context(), "auth_error.state_mismatch.title") &&
				data["error"] == i18n.T(req.Context(), "auth_error.state_mismatch.message")
		})).Return(nil).Once()
}

// stateMismatchPageRenderer is a real render.Renderer over the two templates the state-mismatch page
// renders through, so a case sees the status on the wire and the page's text rather than a bind
// map handed to a mock.
func stateMismatchPageRenderer() *render.Renderer {
	return render.New(fstest.MapFS{
		"layouts/no_menu_layout.html": {Data: []byte(`<html>{{template "content" .}}</html>`)},
		"auth_error.html":             {Data: []byte(`{{define "content"}}<h1>{{.title}}</h1><p>{{.error}}</p>{{end}}`)},
	}, nil)

}

// The gate's own table, which the eleven handler cases cannot own: they assert through a mocked
// writer, so nothing there sees the status on the wire or the log line. The predicate's table is
// ceremony's TestInState; this one owns what the gate does with its answer.
//
// The status is asserted on a real recorder through a real render.Renderer rather than on the bind map,
// because "_httpStatus" is only a request to RenderTemplate and a helper that passed 400 to a
// writer which ignored it would satisfy the map assertion (#279 decision 21, #436 seam 3).
func TestRequireAuthState(t *testing.T) {
	t.Run("an accepted state passes, writing and logging nothing", func(t *testing.T) {
		logged := logtest.CaptureSlog(t)

		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/pwd")
		authContext := &ceremony.AuthContext{AuthState: ceremony.AuthStateLevel1Password}

		ok := testCeremonyBoundary(stateMismatchPageRenderer(), nil, nil).requireAuthState(rr, req, authContext,
			ceremony.AuthStateLevel1Password)

		assert.True(t, ok)
		assert.Empty(t, rr.Body.String(), "the route answers, not the gate")
		assert.Empty(t, rr.Header(), "the route answers, not the gate")
		assert.Empty(t, logged.Records())
		assert.Equal(t, ceremony.AuthStateLevel1Password, authContext.AuthState)
	})

	t.Run("any one of several accepted states passes", func(t *testing.T) {
		for _, actual := range []ceremony.AuthState{
			ceremony.AuthStateLevel1PasswordCompleted, ceremony.AuthStateLevel1ExistingSession,
		} {
			t.Run(string(actual), func(t *testing.T) {
				logged := logtest.CaptureSlog(t)

				rr := httptest.NewRecorder()
				req := renderableRequest("/auth/level1completed")

				ok := testCeremonyBoundary(stateMismatchPageRenderer(), nil, nil).requireAuthState(rr, req,
					&ceremony.AuthContext{AuthState: actual},
					ceremony.AuthStateLevel1PasswordCompleted, ceremony.AuthStateLevel1ExistingSession)

				assert.True(t, ok)
				assert.Empty(t, rr.Body.String())
				assert.Empty(t, logged.Records())
			})
		}
	})

	t.Run("a refused state answers 400 with the state mismatch page", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/pwd")
		authContext := &ceremony.AuthContext{AuthState: ceremony.AuthStateLevel1PasswordCompleted}

		ok := testCeremonyBoundary(stateMismatchPageRenderer(), nil, nil).requireAuthState(rr, req, authContext,
			ceremony.AuthStateLevel1Password)

		assert.False(t, ok, "the caller must stop: the response is already written")
		assert.Equal(t, http.StatusBadRequest, rr.Code,
			"a stale tab is a client's mistake, not a server fault")
		body := rr.Body.String()
		assert.Contains(t, body, i18n.T(req.Context(), "auth_error.state_mismatch.title"))
		assert.Contains(t, body, i18n.T(req.Context(), "auth_error.state_mismatch.message"))
		// The page beside it, which says a different thing: the sign-in can no longer continue.
		assert.NotContains(t, body, i18n.T(req.Context(), "auth_error.ceremony_mismatch.message"))
		// Untouched: the state belongs to the step the user is actually on.
		assert.Equal(t, ceremony.AuthStateLevel1PasswordCompleted, authContext.AuthState)
	})

	t.Run("a refusal logs the accepted states and the actual one at warn, with no stack", func(t *testing.T) {
		logged := logtest.CaptureSlog(t)

		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/level1completed")

		ok := testCeremonyBoundary(stateMismatchPageRenderer(), nil, nil).requireAuthState(rr, req,
			&ceremony.AuthContext{AuthState: ceremony.AuthStateReadyToIssueCode},
			ceremony.AuthStateLevel1PasswordCompleted, ceremony.AuthStateLevel1ExistingSession)

		assert.False(t, ok)
		assert.Equal(t, http.StatusBadRequest, rr.Code,
			"/auth/level1completed answered 500 here until #436")

		records := logged.Records()
		require.Len(t, records, 1)
		assert.Equal(t, slog.LevelWarn, records[0].Level)
		assert.Equal(t, "auth state mismatch, refusing the request", records[0].Message)
		// Every accepted state and the actual one, because together they are the whole
		// diagnosis: neither alone says which step the browser asked for and which one the
		// ceremony is on. Plain strings, so the record reads the same whatever the handler.
		assert.Equal(t, []string{"level1_password_completed", "level1_existing_session"},
			records[0].Attrs["accepted_states"])
		assert.Equal(t, "ready_to_issue_code", records[0].Attrs["actual_state"])
		assert.NotContains(t, logged.Text(), "level=ERROR",
			"the Back button must not page whoever watches error-level lines")
	})

	t.Run("a refusal whose page cannot be rendered answers the 500 page", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/pwd")
		renderErr := errs.New("the template is broken")
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
			mock.Anything).Return(renderErr).Once()
		pageRenderer.On("InternalServerError", rr, req, renderErr).Return().Once()

		ok := testCeremonyBoundary(pageRenderer, nil, nil).requireAuthState(rr, req,
			&ceremony.AuthContext{AuthState: ceremony.AuthStateLevel1PasswordCompleted},
			ceremony.AuthStateLevel1Password)

		assert.False(t, ok, "the caller must stop: the 500 page is the answer")
		pageRenderer.AssertExpectations(t)
	})
}

// The loader's arms that involve no ceremony id: a missing context, a store fault and a context the
// request names. Each gated route used to carry its own copy of this prologue; the handler cases still
// drive the error arm through each route, and this owns what each arm answers (#436 seam 3). What the
// loader does with an id that is absent or does not match is TestLoadAuthContext_CeremonyId's.
func TestLoadAuthContext(t *testing.T) {
	t.Run("a missing context redirects to the account page with a warn line", func(t *testing.T) {
		logged := logtest.CaptureSlog(t)

		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/level1")

		ceremonyStore.On("GetAuthContext", req).Return(nil, ceremony.ErrNoAuthContext).Once()

		authContext, ok := testCeremonyBoundary(pageRenderer, ceremonyStore, auditLogger).loadAuthContext(rr, req)

		assert.False(t, ok)
		assert.Nil(t, authContext)
		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, testAdminConsoleBaseURL+"/account/profile", rr.Header().Get("Location"))

		records := logged.Records()
		require.Len(t, records, 1)
		assert.Equal(t, slog.LevelWarn, records[0].Level)
		assert.Equal(t, "auth context is missing, redirecting", records[0].Message)
		assert.Equal(t, testAdminConsoleBaseURL+"/account/profile", records[0].Attrs["redirect"])
	})

	t.Run("a wrapped missing context is still a missing context", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/level1")

		ceremonyStore.On("GetAuthContext", req).
			Return(nil, errs.Wrap(ceremony.ErrNoAuthContext, "reading the session")).Once()

		_, ok := testCeremonyBoundary(pageRenderer, ceremonyStore, auditLogger).loadAuthContext(rr, req)

		assert.False(t, ok)
		assert.Equal(t, http.StatusFound, rr.Code)
	})

	t.Run("any other failure is a 500 carrying that error", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/level1")

		ceremonyStore.On("GetAuthContext", req).Return(nil, assert.AnError).Once()
		pageRenderer.On("InternalServerError", rr, req, assert.AnError).Return().Once()

		authContext, ok := testCeremonyBoundary(pageRenderer, ceremonyStore, auditLogger).loadAuthContext(rr, req)

		assert.False(t, ok)
		assert.Nil(t, authContext)
		assert.Empty(t, rr.Header().Get("Location"), "a store fault is not a missing context")
	})

	t.Run("a present context the request names passes through, writing nothing", func(t *testing.T) {
		logged := logtest.CaptureSlog(t)

		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/level1?ceremony=" + testCeremonyId)

		stored := &ceremony.AuthContext{
			CeremonyId: testCeremonyId, ClientId: "test-client", AuthState: ceremony.AuthStateRequiresLevel1,
		}
		ceremonyStore.On("GetAuthContext", req).Return(stored, nil).Once()

		authContext, ok := testCeremonyBoundary(pageRenderer, ceremonyStore, auditLogger).loadAuthContext(rr, req)

		assert.True(t, ok)
		assert.Same(t, stored, authContext)
		assert.Empty(t, rr.Header())
		assert.Empty(t, rr.Body.String())
		assert.Empty(t, logged.Records())
	})
}

// The arm the store answers with a ceremony held but not named: the loader reads the ceremony the
// browser most recently wrote for the audit event, and answers the 400 page. A read of it that fails
// is a 500, and nothing is audited.
func TestLoadAuthContext_ACeremonyNotNamed(t *testing.T) {
	t.Run("audits the most recently written ceremony and answers 400", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/level2?ceremony=" + testCeremonyId)

		latest := &ceremony.AuthContext{
			CeremonyId: "another-ceremony", ClientId: "latest-client", AuthState: ceremony.AuthStateRequiresConsent, UserId: 7,
		}
		ceremonyStore.On("GetAuthContext", req).Return(nil, errs.WithStack(ceremony.ErrCeremonyNotHeld)).Once()
		ceremonyStore.On("LatestAuthContext", req).Return(latest, nil).Once()
		expectCeremonyMismatchOf(t, pageRenderer, auditLogger, rr, req, latest)

		authContext, ok := testCeremonyBoundary(pageRenderer, ceremonyStore, auditLogger).loadAuthContext(rr, req)

		assert.False(t, ok)
		assert.Nil(t, authContext)
		assert.Empty(t, rr.Header().Get("Location"), "a browser holding a ceremony is not sent to the account page")
	})

	t.Run("a failed read of the latest ceremony is a 500, audited nowhere", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/level2?ceremony=" + testCeremonyId)

		ceremonyStore.On("GetAuthContext", req).Return(nil, ceremony.ErrCeremonyNotHeld).Once()
		ceremonyStore.On("LatestAuthContext", req).Return(nil, assert.AnError).Once()
		pageRenderer.On("InternalServerError", rr, req, assert.AnError).Return().Once()

		authContext, ok := testCeremonyBoundary(pageRenderer, ceremonyStore, auditLogger).loadAuthContext(rr, req)

		assert.False(t, ok)
		assert.Nil(t, authContext)
	})
}

// stepRequestFor builds the request a browser sends to a step: a GET naming the ceremony in the URL
// when idInQuery is set, or a POST carrying it in the body when idInForm is set, and in the URL when
// idInQuery is. Anything a case leaves unset is absent from the request.
func stepRequestFor(method string, target string, idInQuery string, idInForm string) *http.Request {
	if idInQuery != "" {
		target += "?" + url.Values{ceremony.QueryParameter: {idInQuery}}.Encode()
	}
	var req *http.Request
	if method == http.MethodPost {
		form := url.Values{}
		if idInForm != "" {
			form.Set(ceremony.IdField, idInForm)
		}
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
}

// The comparison every gated route makes in the loader, once, for a page load and for a submission
// (#246 decision 22, #437 seam 4), over the real ceremony store, whose read of the ceremony a request
// names is the rule. Each case varies one thing from a passing case and names the gate that refuses
// it. A refusal is the 400 page and the audit event recording the ceremony the browser most recently
// wrote, and it never touches the stored context: the ceremony that is current is the one the user is
// working on in another tab.
func TestLoadAuthContext_CeremonyId(t *testing.T) {
	const otherId = "543210ZyXwVuTsRqPoNmLkJiHgFeDcBa"

	testCases := []struct {
		name    string
		method  string
		stored  string
		inQuery string
		inForm  string
		accept  bool
	}{
		{name: "a GET naming the stored ceremony in the URL", method: http.MethodGet,
			stored: testCeremonyId, inQuery: testCeremonyId, accept: true},
		{name: "a POST naming the stored ceremony in the body", method: http.MethodPost,
			stored: testCeremonyId, inForm: testCeremonyId, accept: true},
		{name: "a POST naming it in the body and in the URL", method: http.MethodPost,
			stored: testCeremonyId, inQuery: testCeremonyId, inForm: testCeremonyId, accept: true},
		// The upgrade of #436's neighbour: every GET step used to load without naming a ceremony.
		{name: "a GET naming no ceremony, the URL a bookmark or a hand-typed step has", method: http.MethodGet,
			stored: testCeremonyId},
		{name: "a GET naming another ceremony", method: http.MethodGet,
			stored: testCeremonyId, inQuery: otherId},
		{name: "a GET naming a prefix of the stored ceremony", method: http.MethodGet,
			stored: testCeremonyId, inQuery: testCeremonyId[:len(testCeremonyId)-1]},
		{name: "a GET naming the stored ceremony and more", method: http.MethodGet,
			stored: testCeremonyId, inQuery: testCeremonyId + "x"},
		{name: "a POST naming no ceremony", method: http.MethodPost,
			stored: testCeremonyId},
		{name: "a POST naming another ceremony in the body", method: http.MethodPost,
			stored: testCeremonyId, inForm: otherId},
		// The stored id belongs to a context a binary from before #79 wrote, and matching "" against
		// "" would accept every request that names nothing.
		{name: "a stored context with no id against a GET naming none", method: http.MethodGet, stored: ""},
		{name: "a stored context with no id against a POST naming none", method: http.MethodPost, stored: ""},
		// The query can never satisfy a POST: a page's own URL carries the id it was loaded with, and a
		// stale form posting to it must still be judged by the id its body holds.
		{name: "a POST naming the stored ceremony in the URL alone", method: http.MethodPost,
			stored: testCeremonyId, inQuery: testCeremonyId},
		{name: "a POST whose URL names the stored ceremony and whose body names another", method: http.MethodPost,
			stored: testCeremonyId, inQuery: testCeremonyId, inForm: otherId},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			rr := httptest.NewRecorder()

			stored := &ceremony.AuthContext{
				CeremonyId: tc.stored, ClientId: "test-client", AuthState: ceremony.AuthStateLevel1Password,
			}
			ceremonyStore, cookies := holdingCeremony(t, stored)
			req := withCookies(stepRequestFor(tc.method, "/auth/pwd", tc.inQuery, tc.inForm), cookies)
			if !tc.accept {
				expectCeremonyMismatchOf(t, pageRenderer, auditLogger, rr, req, stored)
			}

			authContext, ok := testCeremonyBoundary(pageRenderer, ceremonyStore, auditLogger).loadAuthContext(rr, req)

			assert.Equal(t, tc.accept, ok)
			if tc.accept {
				assert.Equal(t, stored, authContext)
			} else {
				assert.Nil(t, authContext)
				// The refusal is the page, so no redirect, and the stored context is not touched:
				// its state is what the other tab left it in.
				assert.Empty(t, rr.Header().Get("Location"))
				assert.Empty(t, rr.Result().Cookies(), "a refusal writes nothing to the browser session")
			}
			assertStillHeld(t, ceremonyStore, cookies, stored)
		})
	}

	// Answered before the missing-context redirect only when a context exists: with none stored the
	// load fails first, so a request naming any ceremony, or none, ends at the account page.
	t.Run("a missing context is still the account page, whatever the request names", func(t *testing.T) {
		// A POST is answered with a 303 and a GET with a 302 (#576, decision 6).
		for method, status := range map[string]int{http.MethodGet: http.StatusFound, http.MethodPost: http.StatusSeeOther} {
			t.Run(method, func(t *testing.T) {
				pageRenderer := handlersmocks.NewPageRenderer(t)
				ceremonyStore := handlersmocks.NewCeremonyStore(t)
				auditLogger := handlersmocks.NewAuditLogger(t)
				rr := httptest.NewRecorder()
				req := stepRequestFor(method, "/auth/pwd", testCeremonyId, testCeremonyId)

				ceremonyStore.On("GetAuthContext", req).Return(nil, ceremony.ErrNoAuthContext).Once()

				_, ok := testCeremonyBoundary(pageRenderer, ceremonyStore, auditLogger).loadAuthContext(rr, req)

				assert.False(t, ok)
				assert.Equal(t, status, rr.Code)
				assert.Equal(t, testAdminConsoleBaseURL+"/account/profile", rr.Header().Get("Location"))
			})
		}
	})
}

// Every redirect between two ceremony routes is built here, so this owns the shape once and the
// handler cases assert that each of their redirects names the ceremony they came from (#437 seam 4).
func TestCeremonyStepURL(t *testing.T) {
	t.Run("the route under the base URL naming the ceremony", func(t *testing.T) {
		got := ceremonyStepURL(testBaseURL, "/auth/pwd", &ceremony.AuthContext{CeremonyId: testCeremonyId})

		assert.Equal(t, testBaseURL+"/auth/pwd?ceremony="+testCeremonyId, got)
	})

	t.Run("the id is encoded and not trusted to need no escaping", func(t *testing.T) {
		got := ceremonyStepURL(testBaseURL, "/auth/issue", &ceremony.AuthContext{CeremonyId: "a b&c=d"})

		parsed, err := url.Parse(got)
		require.NoError(t, err)
		assert.Equal(t, "/auth/issue", parsed.Path)
		assert.Equal(t, []string{"a b&c=d"}, parsed.Query()[ceremony.QueryParameter],
			"the value survives a parse of the URL that was built, so no character changed what it meant")
		assert.Len(t, parsed.Query(), 1)
	})
}

// renderableRequest carries the settings the real render.Renderer reads out of the context on every
// render. Without it RenderTemplateToBuffer panics on a nil assertion, which is a property of the
// renderer rather than of anything under test here.
func renderableRequest(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
}

// TestRejectCeremonyMismatch_AuditsUnderTheRequestsContext is the third of #328's four call
// shapes: a helper that holds an *http.Request and no context of its own, so its audit call has to
// reach for r.Context(). Driven directly rather than through a handler, because the property is
// the helper's and the four bound handlers reach it identically.
//
// The matcher is what makes this fail for its stated reason: an id that is not the request's, the
// empty one a Background context yields included, matches nothing and the strict mock reports the
// unexpected call rather than the case passing.
func TestRejectCeremonyMismatch_AuditsUnderTheRequestsContext(t *testing.T) {
	const requestId = "goiabada/req-ceremony-1"

	pageRenderer := handlersmocks.NewPageRenderer(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	req, err := http.NewRequest("POST", "/auth/pwd", nil)
	require.NoError(t, err)
	req = req.WithContext(context.WithValue(req.Context(), chimiddleware.RequestIDKey, requestId))
	rr := httptest.NewRecorder()

	auditLogger.On("Log", mock.MatchedBy(func(ctx context.Context) bool {
		return chimiddleware.GetReqID(ctx) == requestId
	}), audit.EventAuthCeremonyMismatch, mock.MatchedBy(func(details map[string]interface{}) bool {
		// A plain string, not a ceremony.AuthState: the stored audit detail keeps its type
		// whatever the context's field is declared as (#436).
		authState, ok := details["auth_state"].(string)
		return details["client_identifier"] == "test-client" && ok && authState == "level1_password"
	})).Return().Once()
	pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
		mock.Anything).Return(nil).Once()

	testCeremonyBoundary(pageRenderer, nil, auditLogger).rejectCeremonyMismatch(rr, req, &ceremony.AuthContext{
		ClientId:  "test-client",
		AuthState: ceremony.AuthStateLevel1Password,
	})

	auditLogger.AssertExpectations(t)
	pageRenderer.AssertExpectations(t)
}
