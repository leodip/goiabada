package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/stretchr/testify/mock"
)

// Both consent routes read their settings at the route boundary before anything else, so a request
// reaching either without them answers the 500 page carrying reqctx.ErrNoSettings and reads nothing,
// not even its ceremony: no load, no save, no clear, no database read, no permission check, no audit
// record (#580 decision 5).
func TestMissingSettings_ConsentAnswersBeforeReadingItsCeremony(t *testing.T) {
	for _, step := range []struct {
		name   string
		method string
	}{
		{"consent GET", http.MethodGet},
		{"consent POST", http.MethodPost},
	} {
		t.Run(step.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			permissionChecker := handlersmocks.NewPermissionChecker(t)

			var req *http.Request
			var handler http.Handler
			if step.method == http.MethodPost {
				form := url.Values{}
				form.Add("btnSubmit", "submit")
				form.Add(ceremonyIdField, testCeremonyId)
				form.Add("consent0", "on")
				req = httptest.NewRequest(http.MethodPost, "/auth/consent", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				handler = buildConsentPost(consentPostDeps{
					pageRenderer:      pageRenderer,
					ceremonyStore:     ceremonyStore,
					database:          database,
					auditLogger:       auditLogger,
					permissionChecker: permissionChecker,
				})
			} else {
				req = httptest.NewRequest(http.MethodGet, "/auth/consent?ceremony="+testCeremonyId, nil)
				handler = buildConsentGet(consentGetDeps{
					pageRenderer:  pageRenderer,
					ceremonyStore: ceremonyStore,
					database:      database,
					auditLogger:   auditLogger,
				})
			}
			rr := httptest.NewRecorder()
			pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(isErrNoSettings)).Return().Once()

			handler.ServeHTTP(rr, req)

			pageRenderer.AssertExpectations(t)
			ceremonyStore.AssertNotCalled(t, "GetAuthContext", req)
			ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
			ceremonyStore.AssertNotCalled(t, "ClearAuthContext", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "GetUserById", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
			permissionChecker.AssertNotCalled(t, "FilterOutScopesWhereUserIsNotAuthorized",
				mock.Anything, mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
