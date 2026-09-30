package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
)

func TestHandleAuthLevel2Get(t *testing.T) {
	t.Run("Error when getting GetAuthContext", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		database := mocks_data.NewDatabase(t)

		auditLogger := mocks_handlers.NewAuditLogger(t)
		handler := HandleAuthLevel2Get(pageRenderer, ceremonyStore, database, auditLogger, testBaseURL, testAdminConsoleBaseURL)

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyId, nil)
		rr := httptest.NewRecorder()

		expectedError := &customerrors.ErrorDetail{}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(nil, expectedError)

		pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == expectedError
		})).Return()

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
	})

	t.Run("Unexpected AuthState", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		database := mocks_data.NewDatabase(t)

		auditLogger := mocks_handlers.NewAuditLogger(t)
		handler := HandleAuthLevel2Get(pageRenderer, ceremonyStore, database, auditLogger, testBaseURL, testAdminConsoleBaseURL)

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyId, nil)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			CeremonyId: testCeremonyId,
			AuthState:  ceremony.AuthStateReadyToIssueCode,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		expectAuthStateMismatch(t, pageRenderer, rr, req)

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
	})

	t.Run("Client not found", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		database := mocks_data.NewDatabase(t)

		auditLogger := mocks_handlers.NewAuditLogger(t)
		handler := HandleAuthLevel2Get(pageRenderer, ceremonyStore, database, auditLogger, testBaseURL, testAdminConsoleBaseURL)

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyId, nil)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			CeremonyId: testCeremonyId,
			AuthState:  ceremony.AuthStateRequiresLevel2,
			ClientId:   "test-client",
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(nil, nil)

		pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "client test-client not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("AcrLevel2Optional with OTP enabled", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		database := mocks_data.NewDatabase(t)

		auditLogger := mocks_handlers.NewAuditLogger(t)
		handler := HandleAuthLevel2Get(pageRenderer, ceremonyStore, database, auditLogger, testBaseURL, testAdminConsoleBaseURL)

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyId, nil)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			CeremonyId: testCeremonyId,
			AuthState:  ceremony.AuthStateRequiresLevel2,
			ClientId:   "test-client",
			UserId:     1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  models.AcrLevel2Optional,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

		user := &models.User{
			Id:                  1,
			OTPEnabled:          true,
			OtpConfigGeneration: 4,
		}
		database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil)

		ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
			return ac.AuthState == ceremony.AuthStateLevel2OTP &&
				ac.OtpConfigGeneration != nil && *ac.OtpConfigGeneration == 4
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, testBaseURL+"/auth/otp?ceremony="+testCeremonyId, rr.Header().Get("Location"))

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("AcrLevel2Optional with OTP disabled", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		database := mocks_data.NewDatabase(t)

		auditLogger := mocks_handlers.NewAuditLogger(t)
		handler := HandleAuthLevel2Get(pageRenderer, ceremonyStore, database, auditLogger, testBaseURL, testAdminConsoleBaseURL)

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyId, nil)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			CeremonyId: testCeremonyId,
			AuthState:  ceremony.AuthStateRequiresLevel2,
			ClientId:   "test-client",
			UserId:     1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  models.AcrLevel2Optional,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

		user := &models.User{
			Id:                  1,
			OTPEnabled:          false,
			OtpConfigGeneration: 4,
		}
		database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil)

		// **The skip arm captures too**, and that is the case worth pinning: a user who has
		// removed their authenticator answers the level 2 question by having nothing to
		// answer with, so this ceremony must discharge the obligation. Without the capture
		// here every session of such a user stays permanently behind and handlePromptNone
		// answers interaction_required for the rest of each session's life (#242 decision 3).
		ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
			return ac.AuthState == ceremony.AuthStateAuthenticationCompleted &&
				ac.OtpConfigGeneration != nil && *ac.OtpConfigGeneration == 4
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, testBaseURL+"/auth/completed?ceremony="+testCeremonyId, rr.Header().Get("Location"))

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("AcrLevel2Mandatory", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		database := mocks_data.NewDatabase(t)

		auditLogger := mocks_handlers.NewAuditLogger(t)
		handler := HandleAuthLevel2Get(pageRenderer, ceremonyStore, database, auditLogger, testBaseURL, testAdminConsoleBaseURL)

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyId, nil)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			CeremonyId: testCeremonyId,
			AuthState:  ceremony.AuthStateRequiresLevel2,
			ClientId:   "test-client",
			UserId:     1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  models.AcrLevel2Mandatory,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

		user := &models.User{
			Id:                  1,
			OtpConfigGeneration: 4,
		}
		database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil)

		ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
			return ac.AuthState == ceremony.AuthStateLevel2OTP &&
				ac.OtpConfigGeneration != nil && *ac.OtpConfigGeneration == 4
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, testBaseURL+"/auth/otp?ceremony="+testCeremonyId, rr.Header().Get("Location"))

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	// Part 4. GetUserById answers (nil, nil) for a row that is not there, so a user deleted
	// mid-ceremony used to reach `if user.OTPEnabled` and panic with a nil pointer
	// dereference, logged at status 0 (#203) because the panic escapes before the status is
	// written. Every sibling ceremony handler already checks this; this one did not, and
	// "every handler except one" is the kind of gap that regresses (#242 decision 5).
	t.Run("User not found", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		database := mocks_data.NewDatabase(t)

		auditLogger := mocks_handlers.NewAuditLogger(t)
		handler := HandleAuthLevel2Get(pageRenderer, ceremonyStore, database, auditLogger, testBaseURL, testAdminConsoleBaseURL)

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyId, nil)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			CeremonyId: testCeremonyId,
			AuthState:  ceremony.AuthStateRequiresLevel2,
			ClientId:   "test-client",
			UserId:     1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  models.AcrLevel2Mandatory,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

		database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(nil, nil)

		pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		// Nothing is saved and nothing is redirected: the ceremony stops here. NewCeremonyStore(t)
		// fails on an unregistered SaveAuthContext, and this says so in its own words.
		ceremonyStore.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
		assert.Empty(t, rr.Header().Get("Location"))

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Invalid AcrLevel", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		database := mocks_data.NewDatabase(t)

		auditLogger := mocks_handlers.NewAuditLogger(t)
		handler := HandleAuthLevel2Get(pageRenderer, ceremonyStore, database, auditLogger, testBaseURL, testAdminConsoleBaseURL)

		req, _ := http.NewRequest("GET", "/auth/level2?ceremony="+testCeremonyId, nil)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			CeremonyId: testCeremonyId,
			AuthState:  ceremony.AuthStateRequiresLevel2,
			ClientId:   "test-client",
			UserId:     1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  models.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

		user := &models.User{
			Id: 1,
		}
		database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(user, nil)

		pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "invalid targetAcrLevel: urn:goiabada:level1"
		})).Return()

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		database.AssertExpectations(t)
	})
}

// The whole table for /auth/level2's choice of arm. The handler cases above each drive one arm to
// its save and redirect; which arm a target and an enrolment get is decided here (#437 seam 1).
func TestDecideLevel2Arm(t *testing.T) {
	testCases := []struct {
		name       string
		target     models.AcrLevel
		userHasOTP bool
		wantState  ceremony.AuthState
		wantPath   string
		wantErr    string
	}{
		{"optional with OTP asks for it", models.AcrLevel2Optional, true, ceremony.AuthStateLevel2OTP, "/auth/otp", ""},
		{"optional without OTP skips it", models.AcrLevel2Optional, false, ceremony.AuthStateAuthenticationCompleted, "/auth/completed", ""},
		{"mandatory with OTP asks for it", models.AcrLevel2Mandatory, true, ceremony.AuthStateLevel2OTP, "/auth/otp", ""},
		{"mandatory without OTP enrols", models.AcrLevel2Mandatory, false, ceremony.AuthStateLevel2OTP, "/auth/otp", ""},
		{"level1 never reaches this hop", models.AcrLevel1, true, "", "", "invalid targetAcrLevel: urn:goiabada:level1"},
		{"an unknown level is refused", "urn:goiabada:level3", false, "", "", "invalid targetAcrLevel: urn:goiabada:level3"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			state, path, err := decideLevel2Arm(tc.target, tc.userHasOTP)

			if tc.wantErr != "" {
				assert.EqualError(t, err, tc.wantErr)
				assert.Empty(t, state)
				assert.Empty(t, path)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantState, state)
			assert.Equal(t, tc.wantPath, path)
		})
	}
}
