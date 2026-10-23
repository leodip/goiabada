package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/stretchr/testify/mock"
)

// Both password routes read their settings at the route boundary before anything else, so a request
// reaching either without them answers the 500 page carrying reqctx.ErrNoSettings and reads nothing,
// not even its ceremony: no load, no client, no lookup, no rotation, no save, no audit record (#580
// decision 5). The POST carries the right credentials, so a check that ran would be seen.
func TestMissingSettings_ThePasswordStepAnswersBeforeReadingItsCeremony(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			var req *http.Request
			var handler http.Handler
			if method == http.MethodPost {
				form := url.Values{}
				form.Add(ceremony.IdField, testCeremonyId)
				form.Add("email", "test@example.com")
				form.Add("password", "testpassword")
				req = httptest.NewRequest(http.MethodPost, "/auth/pwd", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				handler = buildAuthPwdPost(authPwdPostDeps{pageRenderer: pageRenderer, ceremonyStore: ceremonyStore,
					database: database, auditLogger: auditLogger})
			} else {
				req = httptest.NewRequest(http.MethodGet, "/auth/pwd?ceremony="+testCeremonyId, nil)
				handler = buildAuthPwdGet(authPwdGetDeps{pageRenderer: pageRenderer, ceremonyStore: ceremonyStore,
					database: database, auditLogger: auditLogger})
			}
			rr := httptest.NewRecorder()
			pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(isErrNoSettings)).Return().Once()

			handler.ServeHTTP(rr, req)

			pageRenderer.AssertExpectations(t)
			ceremonyStore.AssertNotCalled(t, "GetAuthContext", req)
			ceremonyStore.AssertNotCalled(t, "RegenerateSession", mock.Anything, mock.Anything, mock.Anything)
			ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
