package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAuthLevel2Get(t *testing.T) {
	t.Run("Error when getting GetAuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel2Get(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/level2", nil)
		rr := httptest.NewRecorder()

		expectedError := &customerrors.ErrorDetail{}
		authHelper.On("GetAuthContext", mock.Anything).Return(nil, expectedError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == expectedError
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Unexpected AuthState", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel2Get(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/level2", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not requires_level_2"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Client not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel2Get(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/level2", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresLevel2,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "client test-client not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("AcrLevel2Optional with OTP enabled", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel2Get(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/level2", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresLevel2,
			ClientId:  "test-client",
			UserId:    1,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel2Optional,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		user := &models.User{
			Id:                  1,
			OTPEnabled:          true,
			OtpConfigGeneration: 4,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateLevel2OTP &&
				ac.OtpConfigGeneration != nil && *ac.OtpConfigGeneration == 4
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/otp", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("AcrLevel2Optional with OTP disabled", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel2Get(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/level2", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresLevel2,
			ClientId:  "test-client",
			UserId:    1,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel2Optional,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		user := &models.User{
			Id:                  1,
			OTPEnabled:          false,
			OtpConfigGeneration: 4,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		// **The skip arm captures too**, and that is the case worth pinning: a user who has
		// removed their authenticator answers the level 2 question by having nothing to
		// answer with, so this ceremony must discharge the obligation. Without the capture
		// here every session of such a user stays permanently behind and handlePromptNone
		// answers interaction_required for the rest of each session's life (#242 decision 3).
		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateAuthenticationCompleted &&
				ac.OtpConfigGeneration != nil && *ac.OtpConfigGeneration == 4
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/completed", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("AcrLevel2Mandatory", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel2Get(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/level2", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresLevel2,
			ClientId:  "test-client",
			UserId:    1,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel2Mandatory,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		user := &models.User{
			Id:                  1,
			OtpConfigGeneration: 4,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateLevel2OTP &&
				ac.OtpConfigGeneration != nil && *ac.OtpConfigGeneration == 4
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/otp", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	// Part 4. GetUserById answers (nil, nil) for a row that is not there, so a user deleted
	// mid-ceremony used to reach `if user.OTPEnabled` and panic with a nil pointer
	// dereference, logged at status 0 (#203) because the panic escapes before the status is
	// written. Every sibling ceremony handler already checks this; this one did not, and
	// "every handler except one" is the kind of gap that regresses (#242 decision 5).
	t.Run("User not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel2Get(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/level2", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresLevel2,
			ClientId:  "test-client",
			UserId:    1,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel2Mandatory,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		database.On("GetUserById", mock.Anything, int64(1)).Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		// Nothing is saved and nothing is redirected: the ceremony stops here. NewAuthHelper(t)
		// fails on an unregistered SaveAuthContext, and this says so in its own words.
		authHelper.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)
		assert.Empty(t, rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Invalid AcrLevel", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel2Get(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/level2", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresLevel2,
			ClientId:  "test-client",
			UserId:    1,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		user := &models.User{
			Id: 1,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "invalid targetAcrLevel: urn:goiabada:level1"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})
}
