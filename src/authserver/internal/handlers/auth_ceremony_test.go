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

// expectAuthStateMismatch sets the one call requireAuthState makes on a refusal, and asserts the
// page it renders is the 400 error page rather than a 500 with a stack, which is what ten of these
// eleven sites answered before #279 decision 21 and /auth/level1completed until #436.
//
// It asserts the state_mismatch pair specifically and not merely "some title": the ceremony
// mismatch page beside it says another sign-in was started in this browser, which is not what the
// Back button did, and a helper that accepted either would let the two pages be confused.
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

// The whole comparison table for the ceremony binding. The function is pure, so the table costs
// nothing and every caller then needs only one accept and one reject (#79 seam 3).
func TestCeremonyMatches(t *testing.T) {
	const stored = "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"

	testCases := []struct {
		name      string
		stored    string
		submitted string
		want      bool
	}{
		{
			name:      "Equal ids",
			stored:    stored,
			submitted: stored,
			want:      true,
		},
		{
			name:      "Different ids of the same length",
			stored:    stored,
			submitted: "543210ZyXwVuTsRqPoNmLkJiHgFeDcBa",
			want:      false,
		},
		{
			// The upgrade case. An auth context written before #79 carries no id, and matching
			// "" against "" would make it accept a form naming no ceremony at all.
			name:      "Empty stored id against an empty submission",
			stored:    "",
			submitted: "",
			want:      false,
		},
		{
			name:      "Empty stored id against a real submission",
			stored:    "",
			submitted: stored,
			want:      false,
		},
		{
			// What an absent form field looks like: r.PostFormValue answers "".
			name:      "Real stored id against an absent field",
			stored:    stored,
			submitted: "",
			want:      false,
		},
		{
			name:      "Near miss, one byte differs",
			stored:    stored,
			submitted: "aBcDeFgHiJkLmNoPqRsTuVwXyZ012346",
			want:      false,
		},
		{
			// A prefix must not match, which is the family of defect #79 is about: the
			// consent selection granted a scope because "consent1" was a prefix of
			// "consent10".
			name:      "Near miss, the submission is a prefix of the stored id",
			stored:    stored,
			submitted: stored[:len(stored)-1],
			want:      false,
		},
		{
			name:      "Near miss, the submission extends the stored id",
			stored:    stored,
			submitted: stored + "x",
			want:      false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ceremonyMatches(tc.stored, tc.submitted))
		})
	}
}

// stateMismatchPageRenderer is a real render.Renderer over the two templates the state-mismatch page
// renders through, so a case sees the status on the wire and the page's text rather than a bind
// map handed to a mock.
func stateMismatchPageRenderer() *render.Renderer {
	return render.New(fstest.MapFS{
		"layouts/no_menu_layout.html": {Data: []byte(`<html>{{template "content" .}}</html>`)},
		"auth_error.html":             {Data: []byte(`{{define "content"}}<h1>{{.title}}</h1><p>{{.error}}</p>{{end}}`)},
	})
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

		ok := requireAuthState(stateMismatchPageRenderer(), rr, req, authContext,
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

				ok := requireAuthState(stateMismatchPageRenderer(), rr, req,
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

		ok := requireAuthState(stateMismatchPageRenderer(), rr, req, authContext,
			ceremony.AuthStateLevel1Password)

		assert.False(t, ok, "the caller must stop: the response is already written")
		assert.Equal(t, http.StatusBadRequest, rr.Code,
			"a stale tab is a client's mistake, not a server fault")
		body := rr.Body.String()
		assert.Contains(t, body, i18n.T(req.Context(), "auth_error.state_mismatch.title"))
		assert.Contains(t, body, i18n.T(req.Context(), "auth_error.state_mismatch.message"))
		// The page beside it, which says a different thing: another sign-in was started here.
		assert.NotContains(t, body, i18n.T(req.Context(), "auth_error.ceremony_mismatch.message"))
		// Untouched: the state belongs to the step the user is actually on.
		assert.Equal(t, ceremony.AuthStateLevel1PasswordCompleted, authContext.AuthState)
	})

	t.Run("a refusal logs the accepted states and the actual one at warn, with no stack", func(t *testing.T) {
		logged := logtest.CaptureSlog(t)

		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/level1completed")

		ok := requireAuthState(stateMismatchPageRenderer(), rr, req,
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

		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, auditLogger, rr, req, testAdminConsoleBaseURL)

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

		_, ok := loadAuthContext(pageRenderer, ceremonyStore, auditLogger, rr, req, testAdminConsoleBaseURL)

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

		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, auditLogger, rr, req, testAdminConsoleBaseURL)

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

		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, auditLogger, rr, req, testAdminConsoleBaseURL)

		assert.True(t, ok)
		assert.Same(t, stored, authContext)
		assert.Empty(t, rr.Header())
		assert.Empty(t, rr.Body.String())
		assert.Empty(t, logged.Records())
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
			form.Set(ceremonyIdField, idInForm)
		}
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
}

// The comparison every gated route now makes in the loader, once, for a page load and for a
// submission (#246 decision 22, #437 seam 4). Each case varies one thing from a passing case and
// names the gate that refuses it. A refusal is the 400 page and the audit event, and it never
// touches the stored context: the ceremony that is current is the one the user is working on in
// another tab.
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
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			rr := httptest.NewRecorder()
			req := stepRequestFor(tc.method, "/auth/pwd", tc.inQuery, tc.inForm)

			stored := &ceremony.AuthContext{
				CeremonyId: tc.stored, ClientId: "test-client", AuthState: ceremony.AuthStateLevel1Password,
			}
			ceremonyStore.On("GetAuthContext", req).Return(stored, nil).Once()
			if !tc.accept {
				expectCeremonyMismatch(t, pageRenderer, auditLogger, rr, req)
			}

			authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, auditLogger, rr, req, testAdminConsoleBaseURL)

			assert.Equal(t, tc.accept, ok)
			if tc.accept {
				assert.Same(t, stored, authContext)
			} else {
				assert.Nil(t, authContext)
				// The refusal is the page, so no redirect, and the stored context is not touched:
				// nothing was saved or cleared, which the strict mock would report as an unexpected
				// call, and its state is what the other tab left it in.
				assert.Empty(t, rr.Header().Get("Location"))
				assert.Equal(t, ceremony.AuthStateLevel1Password, stored.AuthState)
			}
		})
	}

	// Answered before the missing-context redirect only when a context exists: with none stored the
	// load fails first, so a request naming any ceremony, or none, ends at the account page.
	t.Run("a missing context is still the account page, whatever the request names", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(method, func(t *testing.T) {
				pageRenderer := handlersmocks.NewPageRenderer(t)
				ceremonyStore := handlersmocks.NewCeremonyStore(t)
				auditLogger := handlersmocks.NewAuditLogger(t)
				rr := httptest.NewRecorder()
				req := stepRequestFor(method, "/auth/pwd", testCeremonyId, testCeremonyId)

				ceremonyStore.On("GetAuthContext", req).Return(nil, ceremony.ErrNoAuthContext).Once()

				_, ok := loadAuthContext(pageRenderer, ceremonyStore, auditLogger, rr, req, testAdminConsoleBaseURL)

				assert.False(t, ok)
				assert.Equal(t, http.StatusFound, rr.Code)
				assert.Equal(t, testAdminConsoleBaseURL+"/account/profile", rr.Header().Get("Location"))
			})
		}
	})
}

// submittedCeremonyId is a pure function of the request's method and its two sources, so its table
// pins which source counts for which method and nothing else (#437 seam 1).
func TestSubmittedCeremonyId(t *testing.T) {
	testCases := []struct {
		name    string
		method  string
		inQuery string
		inForm  string
		want    string
	}{
		{"a GET reads the URL's parameter", http.MethodGet, "from-the-url", "", "from-the-url"},
		{"a GET with no parameter names nothing", http.MethodGet, "", "", ""},
		{"a POST reads the body's field", http.MethodPost, "", "from-the-form", "from-the-form"},
		{"a POST ignores the URL's parameter", http.MethodPost, "from-the-url", "", ""},
		{"a POST prefers nothing from the URL over the body", http.MethodPost, "from-the-url", "from-the-form", "from-the-form"},
		// Any method that is not a POST reads the URL, so a HEAD asking for a step is judged as the GET is.
		{"a HEAD reads the URL's parameter", http.MethodHead, "from-the-url", "", "from-the-url"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := stepRequestFor(tc.method, "/auth/pwd", tc.inQuery, tc.inForm)
			assert.Equal(t, tc.want, submittedCeremonyId(req))
		})
	}

	t.Run("the form field's name in the URL is not the URL's parameter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/pwd?"+ceremonyIdField+"="+testCeremonyId, nil)
		assert.Empty(t, submittedCeremonyId(req),
			"the two names differ on purpose, so a URL can never be spelled as the field")
	})

	t.Run("a repeated parameter reads the first copy", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/pwd?ceremony=first&ceremony=second", nil)
		assert.Equal(t, "first", submittedCeremonyId(req))
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
		authState, ok := details["authState"].(string)
		return details["clientId"] == "test-client" && ok && authState == "level1_password"
	})).Return().Once()
	pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
		mock.Anything).Return(nil).Once()

	rejectCeremonyMismatch(pageRenderer, auditLogger, rr, req, &ceremony.AuthContext{
		ClientId:  "test-client",
		AuthState: ceremony.AuthStateLevel1Password,
	})

	auditLogger.AssertExpectations(t)
	pageRenderer.AssertExpectations(t)
}
