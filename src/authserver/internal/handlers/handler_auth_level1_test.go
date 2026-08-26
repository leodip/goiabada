package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/mocks"
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

		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database, nil)

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

		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database, nil)

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

		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database, nil)

		req, err := http.NewRequest("GET", "/auth/level1/completed", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1PasswordCompleted,
			ClientId:  "test-client",
			UserId:    1,
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

		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database, nil)

		req, err := http.NewRequest("GET", "/auth/level1/completed", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1PasswordCompleted,
			ClientId:  "test-client",
			UserId:    1,
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

		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database, nil)

		req, _ := http.NewRequest("GET", "/auth/level1/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1PasswordCompleted,
			ClientId:  "test-client",
			UserId:    1,
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

	// The user's authenticator changed since this session last answered the level 2 question,
	// so the session's snapshot is behind the user's counter and a step-up is owed. Nothing is
	// written: NewDatabase(t) fails on an unregistered call, and the explicit AssertNotCalled
	// below says so in its own words, because that deletion is the whole of part 1.1 (#242).
	t.Run("OTP config generation has moved since the session answered", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database, nil)

		req, _ := http.NewRequest("GET", "/auth/level1/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1PasswordCompleted,
			ClientId:  "test-client",
			UserId:    1,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		// UserSessionLoadUser is stubbed, so User is set here directly: the session answered
		// against generation 0 and the user has since moved to 1.
		userSession := &models.UserSession{
			Id:                  1,
			UserId:              1,
			AcrLevel:            enums.AcrLevel2Optional.String(),
			OtpConfigGeneration: 0,
			User:                models.User{Id: 1, OtpConfigGeneration: 1},
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

		// Part 1.1. The handler used to clear a boolean here and commit it, so a visitor who
		// closed the browser at the OTP form had already spent the re-prompt and the next
		// ceremony let them through on a password alone. Deciding to ask must write nothing:
		// the obligation is discharged at /auth/completed, once a ceremony has answered it.
		database.AssertNotCalled(t, "UpdateUserSession", mock.Anything, mock.Anything)
		assert.EqualValues(t, 0, userSession.OtpConfigGeneration,
			"the session's snapshot must not move in memory either")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("ACR level transitions", func(t *testing.T) {
		tests := []struct {
			name             string
			sessionAcrLevel  enums.AcrLevel
			targetAcrLevel   enums.AcrLevel
			otpConfigChanged bool
			expectedRedirect string
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
				name:             "AcrLevel2Optional to AcrLevel2Optional (otp config generation moved)",
				sessionAcrLevel:  enums.AcrLevel2Optional,
				targetAcrLevel:   enums.AcrLevel2Optional,
				otpConfigChanged: true,
				expectedRedirect: "/auth/level2",
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
				name:             "AcrLevel2Mandatory to AcrLevel2Mandatory (otp config generation moved)",
				sessionAcrLevel:  enums.AcrLevel2Mandatory,
				targetAcrLevel:   enums.AcrLevel2Mandatory,
				otpConfigChanged: true,
				expectedRedirect: "/auth/level2",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				authHelper := mocks_handlerhelpers.NewAuthHelper(t)
				userSessionManager := mocks_user.NewUserSessionManager(t)
				database := mocks_data.NewDatabase(t)

				handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database, nil)

				req, _ := http.NewRequest("GET", "/auth/level1/completed", nil)
				rr := httptest.NewRecorder()

				authContext := &oauth.AuthContext{
					AuthState: oauth.AuthStateLevel1PasswordCompleted,
					ClientId:  "test-client",
					UserId:    1,
				}
				authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

				sessionIdentifier := "test-session"
				ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
				req = req.WithContext(ctx)

				// UserSessionLoadUser is stubbed, so User is set here directly. A moved counter
				// is the session's snapshot sitting behind the user's, which is what the handler
				// compares (#242).
				userGeneration := int64(0)
				if tt.otpConfigChanged {
					userGeneration = 1
				}
				userSession := &models.UserSession{
					Id:                  1,
					UserId:              1,
					AcrLevel:            tt.sessionAcrLevel.String(),
					OtpConfigGeneration: 0,
					User:                models.User{Id: 1, OtpConfigGeneration: userGeneration},
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

				// Every row, not only the moved ones: this handler writes nothing at all now,
				// which is what stops an abandoned ceremony spending its re-prompt (#242).
				database.AssertNotCalled(t, "UpdateUserSession", mock.Anything, mock.Anything)

				httpHelper.AssertExpectations(t)
				authHelper.AssertExpectations(t)
				userSessionManager.AssertExpectations(t)
				database.AssertExpectations(t)
			})
		}
	})

	// The browser still holds user 1's session cookie while user 2 authenticates. The session is
	// valid throughout (HasValidUserSession is stubbed true in every row), so ownership is the only
	// thing separating these from the rows above: a session belonging to someone else contributes
	// no ACR, so the target alone decides step-up, and nothing writes to the other user's row (#133).
	t.Run("Foreign session does not decide step-up", func(t *testing.T) {
		tests := []struct {
			name             string
			sessionAcrLevel  enums.AcrLevel
			targetAcrLevel   enums.AcrLevel
			otpConfigChanged bool
			expectedRedirect string
			description      string
		}{
			{
				name:             "foreign session at the target still prompts for level2",
				sessionAcrLevel:  enums.AcrLevel2Optional,
				targetAcrLevel:   enums.AcrLevel2Optional,
				expectedRedirect: "/auth/level2",
				description:      "the second-factor bypass: user 1's ACR must not satisfy user 2's step-up",
			},
			{
				name:             "foreign mandatory session still prompts for level2",
				sessionAcrLevel:  enums.AcrLevel2Mandatory,
				targetAcrLevel:   enums.AcrLevel2Mandatory,
				expectedRedirect: "/auth/level2",
				description:      "the same bypass at the mandatory level, where the second factor is not optional",
			},
			{
				name:             "level1 target is not raised by a foreign session",
				sessionAcrLevel:  enums.AcrLevel2Mandatory,
				targetAcrLevel:   enums.AcrLevel1,
				expectedRedirect: "/auth/completed",
				description:      "the guard must not invent a second factor a level1 client never asked for",
			},
			{
				name:             "foreign session below the target",
				sessionAcrLevel:  enums.AcrLevel1,
				targetAcrLevel:   enums.AcrLevel2Optional,
				expectedRedirect: "/auth/level2",
				description:      "control: the target arm already handled this, so a failure here means it broke",
			},
			{
				name:             "the other user's snapshot is left alone",
				sessionAcrLevel:  enums.AcrLevel2Optional,
				targetAcrLevel:   enums.AcrLevel2Optional,
				otpConfigChanged: true,
				expectedRedirect: "/auth/level2",
				description:      "nothing may write to the other user's row, and nothing writes to any row now",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				authHelper := mocks_handlerhelpers.NewAuthHelper(t)
				userSessionManager := mocks_user.NewUserSessionManager(t)
				database := mocks_data.NewDatabase(t)

				handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database, nil)

				req, _ := http.NewRequest("GET", "/auth/level1/completed", nil)
				rr := httptest.NewRecorder()

				authContext := &oauth.AuthContext{
					AuthState: oauth.AuthStateLevel1PasswordCompleted,
					ClientId:  "test-client",
					UserId:    2,
				}
				authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

				sessionIdentifier := "test-session"
				ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
				req = req.WithContext(ctx)

				// UserSessionLoadUser is stubbed, so User is set here directly. A moved counter
				// is the session's snapshot sitting behind the user's, which is what the handler
				// compares (#242).
				userGeneration := int64(0)
				if tt.otpConfigChanged {
					userGeneration = 1
				}
				userSession := &models.UserSession{
					Id:                  1,
					UserId:              1,
					AcrLevel:            tt.sessionAcrLevel.String(),
					OtpConfigGeneration: 0,
					User:                models.User{Id: 1, OtpConfigGeneration: userGeneration},
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

				expectedAuthState := oauth.AuthStateAuthenticationCompleted
				if tt.expectedRedirect == "/auth/level2" {
					expectedAuthState = oauth.AuthStateRequiresLevel2
				}

				authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
					return ac.AuthState == expectedAuthState
				})).Return(nil)

				handler.ServeHTTP(rr, req)

				assert.Equal(t, http.StatusFound, rr.Code)
				assert.Equal(t, config.GetAuthServer().BaseURL+tt.expectedRedirect, rr.Header().Get("Location"), tt.description)
				assert.EqualValues(t, 0, userSession.OtpConfigGeneration,
					"the other user's session must not be modified in memory either")
				database.AssertNotCalled(t, "UpdateUserSession", mock.Anything, mock.Anything)

				httpHelper.AssertExpectations(t)
				authHelper.AssertExpectations(t)
				userSessionManager.AssertExpectations(t)
				database.AssertExpectations(t)
			})
		}
	})
}

// Seam 2, delivery. An authorization error that /auth/authorize refused to hand a logged-out
// browser is carried across the login ceremony on the auth context and delivered here, once level 1
// credentials have been verified. That is what makes the deferral in #213 an answer to RFC 9700
// 4.11.2 rather than a way of dropping errors on the floor: the client still receives the error
// response OIDC Core 3.1.2.2 with 3.1.2.6 says it MUST receive, just later.
func TestHandleAuthLevel1CompletedGet_DeliversADeferredError(t *testing.T) {

	newParkedContext := func(state string) *oauth.AuthContext {
		return &oauth.AuthContext{
			AuthState:                state,
			ClientId:                 "test-client",
			RedirectURI:              "https://legit.example/cb",
			ResponseType:             "code",
			State:                    "abc123",
			DeferredErrorCode:        "invalid_scope",
			DeferredErrorDescription: "Invalid scope format: 'bogus'.",
		}
	}

	// Both states the gate above admits. A parked error can only arrive on
	// AuthStateLevel1PasswordCompleted today, because the existing-session shortcut is reached
	// only with a valid session and that request was answered at /auth/authorize, but the delivery
	// does not turn on which one it is and a later change to the shortcut must not silently strand
	// a parked error.
	for _, state := range []string{
		oauth.AuthStateLevel1PasswordCompleted,
		oauth.AuthStateLevel1ExistingSession,
	} {
		t.Run("answers the client on "+state, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			authHelper := mocks_handlerhelpers.NewAuthHelper(t)
			userSessionManager := mocks_user.NewUserSessionManager(t)
			database := mocks_data.NewDatabase(t)

			handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database, nil)

			req := httptest.NewRequest("GET", "/auth/level1completed", nil)
			rr := httptest.NewRecorder()

			authHelper.On("GetAuthContext", mock.Anything).Return(newParkedContext(state), nil)

			// The clear goes first, and it has to reach the browser: ClearAuthContext persists the
			// deletion through a Set-Cookie on w, and the answer commits the response, so a clear
			// afterwards would leave the browser holding a context it could replay (#141).
			const clearedContextCookie = "cleared-auth-context"
			authHelper.On("ClearAuthContext", rr, req).Run(func(args mock.Arguments) {
				args.Get(0).(http.ResponseWriter).Header().Set("Set-Cookie", clearedContextCookie)
			}).Return(nil)

			database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(
				&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil)
			stubRegisteredRedirectURI(database, "https://legit.example/cb")

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusFound, rr.Code)
			location := rr.Header().Get("Location")
			assert.Contains(t, location, "https://legit.example/cb?")
			assert.Contains(t, location, "error=invalid_scope")
			assert.Contains(t, location, "state=abc123")
			assert.Equal(t, clearedContextCookie, rr.Result().Header.Get("Set-Cookie"),
				"the auth context must be cleared before the client response is committed")

			httpHelper.AssertExpectations(t)
			authHelper.AssertExpectations(t)
			database.AssertExpectations(t)
		})
	}

	t.Run("a failing clear still answers the client, with server_error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database, nil)

		req := httptest.NewRequest("GET", "/auth/level1completed", nil)
		rr := httptest.NewRecorder()

		authHelper.On("GetAuthContext", mock.Anything).Return(
			newParkedContext(oauth.AuthStateLevel1PasswordCompleted), nil)
		authHelper.On("ClearAuthContext", rr, req).Return(assert.AnError)
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(
			&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil)
		stubRegisteredRedirectURI(database, "https://legit.example/cb")

		handler.ServeHTTP(rr, req)

		// The client's redirect URI was validated upstream, so it is owed an error response even
		// when this server cannot tidy up after itself, and RFC 6749 4.1.2.1 mints server_error for
		// exactly this condition (#141). This delivery point gets that behaviour by going through
		// answerClientWithError rather than by re-implementing it from memory, which is the whole
		// reason that helper was extracted.
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "error=server_error")
		assert.NotContains(t, location, "invalid_scope")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("an unusable form_post template answers 500", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		// Deliberately malformed, an unclosed action, so template.ParseFS fails. form_post is the
		// only response mode whose arm can fail after the redirect URI has been validated, and it
		// is also what proves templateFS is genuinely wired through to this handler: with nil
		// passed here instead, this case would 500 for the wrong reason and the parameter could be
		// removed without a test noticing.
		templateFS := &mocks.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}
		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS)

		req := httptest.NewRequest("GET", "/auth/level1completed", nil)
		rr := httptest.NewRecorder()

		authContext := newParkedContext(oauth.AuthStateLevel1PasswordCompleted)
		authContext.ResponseMode = "form_post"
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)
		authHelper.On("ClearAuthContext", rr, req).Return(nil)
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(
			&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil)
		stubRegisteredRedirectURI(database, "https://legit.example/cb")
		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("a self-registered client gets the refusal page, not the redirect", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database, nil)

		req := httptest.NewRequest("GET", "/auth/level1completed", nil)
		rr := httptest.NewRecorder()

		authHelper.On("GetAuthContext", mock.Anything).Return(
			newParkedContext(oauth.AuthStateLevel1PasswordCompleted), nil)
		authHelper.On("ClearAuthContext", rr, req).Return(nil)
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(
			&models.Client{Id: 1, ClientIdentifier: "test-client", CreatedViaDCR: true}, nil)
		httpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html",
			"/auth_redirect_blocked.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		// Unreachable in practice, because /auth/authorize renders the interstitial for this client
		// without deferring anything (decision 8). It is asserted because the delivery point loads
		// the client's provenance for itself, so the guard has to hold here too or a future change
		// to that routing would turn this into an open redirect (#108).
		assert.Empty(t, rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
	})

	t.Run("no parked error leaves today's step-up decision alone", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, database, nil)

		req := httptest.NewRequest("GET", "/auth/level1completed", nil)
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, "sess-1"))
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1PasswordCompleted,
			ClientId:  "test-client",
			UserId:    1,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "sess-1").Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, mock.Anything).Return(nil)
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(
			&models.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: enums.AcrLevel1}, nil)
		userSessionManager.On("HasValidUserSession", mock.Anything, mock.Anything, mock.Anything).Return(false)
		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateAuthenticationCompleted
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		// The sentinel is DeferredErrorCode != "", so a context written by an older binary, where
		// the field is absent and unmarshals to "", reads as "no parked error" and this handler
		// behaves exactly as it did before #213.
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/completed", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})
}
