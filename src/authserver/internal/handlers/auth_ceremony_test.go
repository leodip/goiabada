package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/handlerhelpers"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
func expectCeremonyMismatch(t *testing.T, httpHelper *mocks_handlerhelpers.HttpHelper,
	auditLogger *mocks_audit.AuditLogger, rr *httptest.ResponseRecorder, req *http.Request) {
	t.Helper()

	auditLogger.On("Log", constants.AuditAuthCeremonyMismatch, mock.Anything).Return().Once()
	httpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["_httpStatus"] == http.StatusBadRequest &&
				data["title"] != "" && data["error"] != ""
		})).Return(nil).Once()
}

// expectAuthStateMismatch sets the one call rejectAuthStateMismatch makes, and asserts the page it
// renders is the 400 error page rather than a 500 with a stack, which is what these ten sites
// answered before (#279 decision 21).
//
// It asserts the state_mismatch pair specifically and not merely "some title": the ceremony
// mismatch page beside it says another sign-in was started in this browser, which is not what the
// Back button did, and a helper that accepted either would let the two pages be confused.
func expectAuthStateMismatch(t *testing.T, httpHelper *mocks_handlerhelpers.HttpHelper,
	rr *httptest.ResponseRecorder, req *http.Request) {
	t.Helper()

	httpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html",
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

// The helper's own table, which the ten handler cases cannot own: they assert through a mocked
// writer, so nothing there sees the status on the wire or the log line, and both are what
// decision 21 moved.
//
// The status is asserted on a real recorder through a real HttpHelper rather than on the bind map,
// because "_httpStatus" is only a request to RenderTemplate and a helper that passed 400 to a
// writer which ignored it would satisfy the map assertion (#279 decision 21, seam 10).
func TestRejectAuthStateMismatch(t *testing.T) {
	t.Run("answers 400 with the state mismatch page", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/pwd")

		httpHelper := handlerhelpers.NewHttpHelper(&mocks.TestFS{
			FileContents: map[string]string{
				"layouts/no_menu_layout.html": `<html>{{template "content" .}}</html>`,
				"auth_error.html":             `{{define "content"}}<h1>{{.title}}</h1><p>{{.error}}</p>{{end}}`,
			},
		})

		rejectAuthStateMismatch(httpHelper, rr, req,
			oauth.AuthStateLevel1Password, oauth.AuthStateLevel1PasswordCompleted)

		assert.Equal(t, http.StatusBadRequest, rr.Code,
			"a stale tab is a client's mistake, not a server fault")
		body := rr.Body.String()
		assert.Contains(t, body, i18n.T(req.Context(), "auth_error.state_mismatch.title"))
		assert.Contains(t, body, i18n.T(req.Context(), "auth_error.state_mismatch.message"))
		// The page beside it, which says a different thing: another sign-in was started here.
		assert.NotContains(t, body, i18n.T(req.Context(), "auth_error.ceremony_mismatch.message"))
	})

	t.Run("logs both states at warn, with no stack", func(t *testing.T) {
		logged := testutil.CaptureSlog(t)

		rr := httptest.NewRecorder()
		req := renderableRequest("/auth/pwd")

		httpHelper := handlerhelpers.NewHttpHelper(&mocks.TestFS{
			FileContents: map[string]string{
				"layouts/no_menu_layout.html": `<html>{{template "content" .}}</html>`,
				"auth_error.html":             `{{define "content"}}{{.title}}{{end}}`,
			},
		})

		rejectAuthStateMismatch(httpHelper, rr, req,
			oauth.AuthStateRequiresConsent, oauth.AuthStateInitial)

		output := logged.Text()
		// Both states, because the pair is the whole diagnosis: neither alone says which step
		// the browser asked for and which one the ceremony is on.
		assert.Contains(t, output, "level=WARN")
		assert.Contains(t, output, "required_state="+oauth.AuthStateRequiresConsent)
		assert.Contains(t, output, "actual_state="+oauth.AuthStateInitial)
		assert.NotContains(t, output, "level=ERROR",
			"the Back button must not page whoever watches error-level lines")
	})
}

// renderableRequest carries the settings the real HttpHelper reads out of the context on every
// render. Without it RenderTemplateToBuffer panics on a nil assertion, which is a property of the
// renderer rather than of anything under test here.
func renderableRequest(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	return req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{}))
}
