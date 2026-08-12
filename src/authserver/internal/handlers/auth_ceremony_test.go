package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/constants"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
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
