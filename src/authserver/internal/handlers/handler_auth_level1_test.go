package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	mocks_user "github.com/leodip/goiabada/core/user/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAuthLevel1Get(t *testing.T) {
	t.Run("Error when getting GetAuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)

		handler := HandleAuthLevel1Get(httpHelper, authHelper)

		req, err := http.NewRequest("GET", "/auth/level1", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		expectedError := &customerrors.ErrorDetail{} // You may want to customize this error
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

		handler := HandleAuthLevel1Get(httpHelper, authHelper)

		req, err := http.NewRequest("GET", "/auth/level1", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial, // This is an unexpected state
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not requires_level_1"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Successful flow", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)

		handler := HandleAuthLevel1Get(httpHelper, authHelper)

		req, err := http.NewRequest("GET", "/auth/level1", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresLevel1,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateLevel1Password
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/pwd", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})
}

func TestHandleAuthLevel1CompletedGet(t *testing.T) {
	t.Run("Error when getting GetAuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database)

		req, err := http.NewRequest("GET", "/auth/level1/completed", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authHelper.On("GetAuthContext", mock.Anything).Return(nil, assert.AnError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == assert.AnError
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Unexpected AuthState", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database)

		req, err := http.NewRequest("GET", "/auth/level1/completed", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState 'initial' does not match any required state"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Successful flow, redirect to level2", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database)

		req, err := http.NewRequest("GET", "/auth/level1/completed", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1PasswordCompleted,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel2Optional,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresLevel2
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level2", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Successful flow, redirect to completed", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database)

		req, err := http.NewRequest("GET", "/auth/level1/completed", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1PasswordCompleted,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateAuthenticationCompleted
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/completed", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("No session, auth completed", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database)

		req, _ := http.NewRequest("GET", "/auth/level1/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1PasswordCompleted,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(false)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateAuthenticationCompleted
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/completed", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Level2 auth config has changed", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database)

		req, _ := http.NewRequest("GET", "/auth/level1/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1PasswordCompleted,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		userSession := &models.UserSession{
			Id:                         1,
			UserId:                     1,
			AcrLevel:                   enums.AcrLevel2Optional.String(),
			Level2AuthConfigHasChanged: true,
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel2Optional,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

		database.On("UpdateUserSession", mock.Anything, userSession).Return(nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresLevel2
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level2", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("ACR level transitions", func(t *testing.T) {
		tests := []struct {
			name                    string
			sessionAcrLevel         enums.AcrLevel
			targetAcrLevel          enums.AcrLevel
			level2AuthConfigChanged bool
			expectedRedirect        string
		}{
			{
				name:             "AcrLevel1 to AcrLevel1",
				sessionAcrLevel:  enums.AcrLevel1,
				targetAcrLevel:   enums.AcrLevel1,
				expectedRedirect: "/auth/completed",
			},
			{
				name:             "AcrLevel1 to AcrLevel2Optional",
				sessionAcrLevel:  enums.AcrLevel1,
				targetAcrLevel:   enums.AcrLevel2Optional,
				expectedRedirect: "/auth/level2",
			},
			{
				name:             "AcrLevel1 to AcrLevel2Mandatory",
				sessionAcrLevel:  enums.AcrLevel1,
				targetAcrLevel:   enums.AcrLevel2Mandatory,
				expectedRedirect: "/auth/level2",
			},
			{
				name:             "AcrLevel2Optional to AcrLevel1",
				sessionAcrLevel:  enums.AcrLevel2Optional,
				targetAcrLevel:   enums.AcrLevel1,
				expectedRedirect: "/auth/completed",
			},
			{
				name:             "AcrLevel2Optional to AcrLevel2Optional (no change)",
				sessionAcrLevel:  enums.AcrLevel2Optional,
				targetAcrLevel:   enums.AcrLevel2Optional,
				expectedRedirect: "/auth/completed",
			},
			{
				name:                    "AcrLevel2Optional to AcrLevel2Optional (config changed)",
				sessionAcrLevel:         enums.AcrLevel2Optional,
				targetAcrLevel:          enums.AcrLevel2Optional,
				level2AuthConfigChanged: true,
				expectedRedirect:        "/auth/level2",
			},
			{
				name:             "AcrLevel2Optional to AcrLevel2Mandatory",
				sessionAcrLevel:  enums.AcrLevel2Optional,
				targetAcrLevel:   enums.AcrLevel2Mandatory,
				expectedRedirect: "/auth/level2",
			},
			{
				name:             "AcrLevel2Mandatory to AcrLevel1",
				sessionAcrLevel:  enums.AcrLevel2Mandatory,
				targetAcrLevel:   enums.AcrLevel1,
				expectedRedirect: "/auth/completed",
			},
			{
				name:             "AcrLevel2Mandatory to AcrLevel2Optional",
				sessionAcrLevel:  enums.AcrLevel2Mandatory,
				targetAcrLevel:   enums.AcrLevel2Optional,
				expectedRedirect: "/auth/completed",
			},
			{
				name:             "AcrLevel2Mandatory to AcrLevel2Mandatory",
				sessionAcrLevel:  enums.AcrLevel2Mandatory,
				targetAcrLevel:   enums.AcrLevel2Mandatory,
				expectedRedirect: "/auth/completed",
			},
			{
				name:                    "AcrLevel2Mandatory to AcrLevel2Mandatory (config changed)",
				sessionAcrLevel:         enums.AcrLevel2Mandatory,
				targetAcrLevel:          enums.AcrLevel2Mandatory,
				level2AuthConfigChanged: true,
				expectedRedirect:        "/auth/level2",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				authHelper := mocks_handlerhelpers.NewAuthHelper(t)
				userSessionManager := mocks_user.NewUserSessionManager(t)
				database := mocks_data.NewDatabase(t)

				handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database)

				req, _ := http.NewRequest("GET", "/auth/level1/completed", nil)
				rr := httptest.NewRecorder()

				authContext := &oauth.AuthContext{
					AuthState: oauth.AuthStateLevel1PasswordCompleted,
					ClientId:  "test-client",
				}
				authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

				sessionIdentifier := "test-session"
				ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
				req = req.WithContext(ctx)

				userSession := &models.UserSession{
					Id:                         1,
					UserId:                     1,
					AcrLevel:                   tt.sessionAcrLevel.String(),
					Level2AuthConfigHasChanged: tt.level2AuthConfigChanged,
				}
				database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
				database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

				client := &models.Client{
					Id:               1,
					ClientIdentifier: "test-client",
					DefaultAcrLevel:  tt.targetAcrLevel,
				}
				database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

				userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

				if tt.level2AuthConfigChanged {
					database.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(us *models.UserSession) bool {
						return !us.Level2AuthConfigHasChanged
					})).Return(nil)
				}

				expectedAuthState := oauth.AuthStateAuthenticationCompleted
				if tt.expectedRedirect == "/auth/level2" {
					expectedAuthState = oauth.AuthStateRequiresLevel2
				}

				authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
					return ac.AuthState == expectedAuthState
				})).Return(nil)

				handler.ServeHTTP(rr, req)

				assert.Equal(t, http.StatusFound, rr.Code)
				assert.Equal(t, config.GetAuthServer().BaseURL+tt.expectedRedirect, rr.Header().Get("Location"))

				httpHelper.AssertExpectations(t)
				authHelper.AssertExpectations(t)
				userSessionManager.AssertExpectations(t)
				database.AssertExpectations(t)
			})
		}
	})
}
