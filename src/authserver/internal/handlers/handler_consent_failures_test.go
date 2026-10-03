package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/mock"
)

// One row per read or write of the consent screen's render failing: each is the 500 carrying that
// step's error, and nothing after it is reached, since only the steps before the fault are stubbed
// and the mocks refuse any other call.
func TestHandleConsentGet_Failures(t *testing.T) {
	boom := errors.New("boom")

	testCases := []struct {
		name    string
		stub    func(database *datamocks.Database, pageRenderer *handlersmocks.PageRenderer, ceremonyStore *handlersmocks.CeremonyStore)
		wantErr string
	}{
		{
			name: "the user read fails",
			stub: func(database *datamocks.Database, _ *handlersmocks.PageRenderer, _ *handlersmocks.CeremonyStore) {
				database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(nil, boom)
			},
			wantErr: "boom",
		},
		{
			name: "the client read fails",
			stub: func(database *datamocks.Database, _ *handlersmocks.PageRenderer, _ *handlersmocks.CeremonyStore) {
				database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(&record.User{Id: 1}, nil)
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(nil, boom)
			},
			wantErr: "boom",
		},
		{
			name: "the consent read fails",
			stub: func(database *datamocks.Database, _ *handlersmocks.PageRenderer, _ *handlersmocks.CeremonyStore) {
				database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(&record.User{Id: 1}, nil)
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
					Return(&record.Client{Id: 1, ClientIdentifier: "test-client"}, nil)
				database.On("GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, int64(1), int64(1)).Return(nil, boom)
			},
			wantErr: "boom",
		},
		{
			name: "the render fails",
			stub: func(database *datamocks.Database, pageRenderer *handlersmocks.PageRenderer, _ *handlersmocks.CeremonyStore) {
				database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(&record.User{Id: 1}, nil)
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
					Return(&record.Client{Id: 1, ClientIdentifier: "test-client"}, nil)
				database.On("GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, int64(1), int64(1)).Return(nil, nil)
				pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html", "/consent.html", mock.Anything).
					Return(boom)
			},
			wantErr: "boom",
		},
		{
			name: "the save before issuance fails",
			stub: func(database *datamocks.Database, _ *handlersmocks.PageRenderer, ceremonyStore *handlersmocks.CeremonyStore) {
				database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(&record.User{Id: 1}, nil)
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
					Return(&record.Client{Id: 1, ClientIdentifier: "test-client"}, nil)
				database.On("GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, int64(1), int64(1)).
					Return(&record.UserConsent{Id: 1, UserId: 1, ClientId: 1, Scope: "openid"}, nil)
				ceremonyStore.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(boom)
			},
			wantErr: "boom",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			database := datamocks.NewDatabase(t)

			auditLogger := handlersmocks.NewAuditLogger(t)
			handler := HandleConsentGet(pageRenderer, ceremonyStore, database, auditLogger, testBaseURL, testAdminConsoleBaseURL)

			req, _ := http.NewRequest("GET", "/auth/consent?ceremony="+testCeremonyId, nil)
			rr := httptest.NewRecorder()

			ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
				CeremonyId: testCeremonyId,
				AuthState:  ceremony.AuthStateRequiresConsent,
				UserId:     1,
				ClientId:   "test-client",
				Scope:      "openid",
			}, nil)
			tc.stub(database, pageRenderer, ceremonyStore)
			pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
				return err.Error() == tc.wantErr
			})).Return().Once()

			handler.ServeHTTP(rr, req)

			pageRenderer.AssertExpectations(t)
			ceremonyStore.AssertExpectations(t)
			database.AssertExpectations(t)
		})
	}
}

// One row per read or write of a granted consent failing, in the order the grant makes them: each
// is the 500 carrying that step's error, and nothing after it is reached -- no consent written, no
// audit event, no save -- since the mocks refuse any call not stubbed. The filter's own failure is
// "The filter failing closed records nothing" in handler_consent_test.go.
func TestHandleConsentPost_GrantFailures(t *testing.T) {
	boom := errors.New("boom")
	client := &record.Client{Id: 1, ClientIdentifier: "test-client"}
	user := &record.User{Id: 1}

	testCases := []struct {
		name    string
		stub    func(database *datamocks.Database, permissionChecker *handlersmocks.PermissionChecker, ceremonyStore *handlersmocks.CeremonyStore)
		wantErr string
	}{
		{
			name: "the client read fails",
			stub: func(database *datamocks.Database, _ *handlersmocks.PermissionChecker, _ *handlersmocks.CeremonyStore) {
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(nil, boom)
			},
			wantErr: "boom",
		},
		{
			name: "the client is gone",
			stub: func(database *datamocks.Database, _ *handlersmocks.PermissionChecker, _ *handlersmocks.CeremonyStore) {
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(nil, nil)
			},
			wantErr: "client not found",
		},
		{
			name: "the user read fails",
			stub: func(database *datamocks.Database, _ *handlersmocks.PermissionChecker, _ *handlersmocks.CeremonyStore) {
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)
				database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(nil, boom)
			},
			wantErr: "boom",
		},
		{
			name: "the user is gone",
			stub: func(database *datamocks.Database, _ *handlersmocks.PermissionChecker, _ *handlersmocks.CeremonyStore) {
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)
				database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(nil, nil)
			},
			wantErr: "user not found",
		},
		{
			name: "the consent read fails",
			stub: func(database *datamocks.Database, permissionChecker *handlersmocks.PermissionChecker, _ *handlersmocks.CeremonyStore) {
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)
				database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil)
				stubUserHoldsEveryScope(permissionChecker)
				datamocks.ExpectRunInTransaction(database, consentSaveTx)
				database.On("GetConsentByUserIdAndClientId", mock.Anything, consentSaveTx, int64(1), int64(1)).Return(nil, boom)
			},
			wantErr: "boom",
		},
		{
			name: "the consent write fails",
			stub: func(database *datamocks.Database, permissionChecker *handlersmocks.PermissionChecker, _ *handlersmocks.CeremonyStore) {
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)
				database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil)
				stubUserHoldsEveryScope(permissionChecker)
				datamocks.ExpectRunInTransaction(database, consentSaveTx)
				database.On("GetConsentByUserIdAndClientId", mock.Anything, consentSaveTx, int64(1), int64(1)).Return(nil, nil)
				database.On("CreateUserConsent", mock.Anything, consentSaveTx, mock.Anything).Return(boom)
			},
			wantErr: "boom",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			permissionChecker := handlersmocks.NewPermissionChecker(t)

			handler := HandleConsentPost(pageRenderer, ceremonyStore, database, nil, auditLogger, permissionChecker,
				testBaseURL, testAdminConsoleBaseURL)

			form := url.Values{}
			form.Add("btnSubmit", "submit")
			form.Add(ceremonyIdField, testCeremonyId)
			form.Add("consent0", "on")
			req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
				AuthState:  ceremony.AuthStateRequiresConsent,
				CeremonyId: testCeremonyId,
				UserId:     1,
				ClientId:   "test-client",
				Scope:      "openid profile",
			}, nil)
			tc.stub(database, permissionChecker, ceremonyStore)
			pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
				return err.Error() == tc.wantErr
			})).Return().Once()

			handler.ServeHTTP(rr, req)

			pageRenderer.AssertExpectations(t)
			ceremonyStore.AssertExpectations(t)
			database.AssertExpectations(t)
			auditLogger.AssertExpectations(t)
			permissionChecker.AssertExpectations(t)
		})
	}

	// The save after a recorded consent is the last write; its failure is the 500 after the audit
	// event, since the consent row is already committed.
	t.Run("the save before issuance fails", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		ceremonyStore := handlersmocks.NewCeremonyStore(t)
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		permissionChecker := handlersmocks.NewPermissionChecker(t)

		handler := HandleConsentPost(pageRenderer, ceremonyStore, database, nil, auditLogger, permissionChecker,
			testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("btnSubmit", "submit")
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("consent0", "on")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		ceremonyStore.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
			AuthState:  ceremony.AuthStateRequiresConsent,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
			Scope:      "openid profile",
		}, nil)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)
		database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil)
		stubUserHoldsEveryScope(permissionChecker)
		datamocks.ExpectRunInTransaction(database, consentSaveTx)
		database.On("GetConsentByUserIdAndClientId", mock.Anything, consentSaveTx, int64(1), int64(1)).Return(nil, nil)
		database.On("CreateUserConsent", mock.Anything, consentSaveTx, mock.Anything).Return(nil)
		auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return()
		ceremonyStore.On("SaveAuthContext", rr, req, mock.Anything).Return(boom)
		pageRenderer.On("InternalServerError", rr, req, boom).Return().Once()

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})
}
