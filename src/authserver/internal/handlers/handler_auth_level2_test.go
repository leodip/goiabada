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
			Id:         1,
			OTPEnabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateLevel2OTP
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/auth/otp", rr.Header().Get("Location"))

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
			Id:         1,
			OTPEnabled: false,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateAuthenticationCompleted
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/auth/completed", rr.Header().Get("Location"))

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
			Id: 1,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateLevel2OTP
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/auth/otp", rr.Header().Get("Location"))

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
