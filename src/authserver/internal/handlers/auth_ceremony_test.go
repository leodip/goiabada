package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/handlerhelpers"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// testCeremonyId is the id the bound handlers' cases share: the auth context holds it and the
// submitted form names it, which is what a browser posting a page that ceremony rendered sends. A
// case that means to be refused departs from it deliberately (#79).
//
// Here rather than in one handler's test file, because the consent, password and OTP cases all use
// it and none of the three owns the mechanism.
const testCeremonyId = "test-ceremony-id-0123456789abcd"

// expectCeremonyMismatch sets the two calls rejectCeremonyMismatch makes, and asserts the page it
// renders is the 400 error page rather than anything belonging to the flow that was submitted.
func expectCeremonyMismatch(t *testing.T, pageRenderer *mocks_handlers.PageRenderer,
	auditLogger *mocks_handlers.AuditLogger, rr *httptest.ResponseRecorder, req *http.Request) {
	t.Helper()

	auditLogger.On("Log", mock.Anything, audit.AuditAuthCeremonyMismatch, mock.Anything).Return().Once()
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
func expectAuthStateMismatch(t *testing.T, pageRenderer *mocks_handlers.PageRenderer,
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

// stateMismatchPageRenderer is a real HttpHelper over the two templates the state-mismatch page
// renders through, so a case sees the status on the wire and the page's text rather than a bind
// map handed to a mock.
func stateMismatchPageRenderer() *handlerhelpers.HttpHelper {
	return handlerhelpers.NewHttpHelper(fstest.MapFS{
		"layouts/no_menu_layout.html": {Data: []byte(`<html>{{template "content" .}}</html>`)},
		"auth_error.html":             {Data: []byte(`{{define "content"}}<h1>{{.title}}</h1><p>{{.error}}</p>{{end}}`)},
	})
}

// The gate's own table, which the eleven handler cases cannot own: they assert through a mocked
// writer, so nothing there sees the status on the wire or the log line. The predicate's table is
// ceremony's TestInState; this one owns what the gate does with its answer.
//
// The status is asserted on a real recorder through a real HttpHelper rather than on the bind map,
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

// The loader's three arms. Each gated route used to carry its own copy of this prologue; the
// handler cases still drive the error arm through each route, and this owns what each arm answers
// (#436 seam 3).
func TestLoadAuthContext(t *testing.T) {
	t.Run("a missing context redirects to the account page with a warn line", func(t *testing.T) {
		logged := logtest.CaptureSlog(t)

		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/level1")

		ceremonyStore.On("GetAuthContext", req).Return(nil, ceremony.ErrNoAuthContext).Once()

		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, rr, req, testAdminConsoleBaseURL)

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
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/level1")

		ceremonyStore.On("GetAuthContext", req).
			Return(nil, errs.Wrap(ceremony.ErrNoAuthContext, "reading the session")).Once()

		_, ok := loadAuthContext(pageRenderer, ceremonyStore, rr, req, testAdminConsoleBaseURL)

		assert.False(t, ok)
		assert.Equal(t, http.StatusFound, rr.Code)
	})

	t.Run("any other failure is a 500 carrying that error", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/level1")

		ceremonyStore.On("GetAuthContext", req).Return(nil, assert.AnError).Once()
		pageRenderer.On("InternalServerError", rr, req, assert.AnError).Return().Once()

		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, rr, req, testAdminConsoleBaseURL)

		assert.False(t, ok)
		assert.Nil(t, authContext)
		assert.Empty(t, rr.Header().Get("Location"), "a store fault is not a missing context")
	})

	t.Run("a present context passes through, writing nothing", func(t *testing.T) {
		logged := logtest.CaptureSlog(t)

		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/level1")

		stored := &ceremony.AuthContext{ClientId: "test-client", AuthState: ceremony.AuthStateRequiresLevel1}
		ceremonyStore.On("GetAuthContext", req).Return(stored, nil).Once()

		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, rr, req, testAdminConsoleBaseURL)

		assert.True(t, ok)
		assert.Same(t, stored, authContext)
		assert.Empty(t, rr.Header())
		assert.Empty(t, rr.Body.String())
		assert.Empty(t, logged.Records())
	})
}

// renderableRequest carries the settings the real HttpHelper reads out of the context on every
// render. Without it RenderTemplateToBuffer panics on a nil assertion, which is a property of the
// renderer rather than of anything under test here.
func renderableRequest(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	return req.WithContext(reqctx.WithSettings(req.Context(), &models.Settings{}))
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

	pageRenderer := mocks_handlers.NewPageRenderer(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	req, err := http.NewRequest("POST", "/auth/pwd", nil)
	require.NoError(t, err)
	req = req.WithContext(context.WithValue(req.Context(), chimiddleware.RequestIDKey, requestId))
	rr := httptest.NewRecorder()

	auditLogger.On("Log", mock.MatchedBy(func(ctx context.Context) bool {
		return chimiddleware.GetReqID(ctx) == requestId
	}), audit.AuditAuthCeremonyMismatch, mock.MatchedBy(func(details map[string]interface{}) bool {
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
