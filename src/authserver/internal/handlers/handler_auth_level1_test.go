package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestHandleAuthLevel1Get(t *testing.T) {
	t.Run("Error when getting GetAuthContext", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)

		handler := HandleAuthLevel1Get(pageRenderer, ceremonyStore, testBaseURL, testAdminConsoleBaseURL)

		req, err := http.NewRequest("GET", "/auth/level1", nil)
		assert.NoError(t, err)

		req = withSessionSettings(req)

		rr := httptest.NewRecorder()

		expectedError := &customerrors.ErrorDetail{} // You may want to customize this error
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

		handler := HandleAuthLevel1Get(pageRenderer, ceremonyStore, testBaseURL, testAdminConsoleBaseURL)

		req, err := http.NewRequest("GET", "/auth/level1", nil)
		assert.NoError(t, err)

		req = withSessionSettings(req)

		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			AuthState: ceremony.AuthStateInitial, // This is an unexpected state
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		expectAuthStateMismatch(t, pageRenderer, rr, req)

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
	})

	t.Run("Successful flow", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)

		handler := HandleAuthLevel1Get(pageRenderer, ceremonyStore, testBaseURL, testAdminConsoleBaseURL)

		req, err := http.NewRequest("GET", "/auth/level1", nil)
		assert.NoError(t, err)

		req = withSessionSettings(req)

		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			AuthState: ceremony.AuthStateRequiresLevel1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
			return ac.AuthState == ceremony.AuthStateLevel1Password
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, testBaseURL+"/auth/pwd", rr.Header().Get("Location"))

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
	})
}

func TestHandleAuthLevel1CompletedGet(t *testing.T) {
	t.Run("Error when getting GetAuthContext", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, nil, testBaseURL, testAdminConsoleBaseURL)

		req, err := http.NewRequest("GET", "/auth/level1/completed", nil)
		assert.NoError(t, err)

		req = withSessionSettings(req)

		rr := httptest.NewRecorder()

		ceremonyStore.On("GetAuthContext", mock.Anything).Return(nil, assert.AnError)

		pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == assert.AnError
		})).Return()

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
	})

	t.Run("Unexpected AuthState", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, nil, testBaseURL, testAdminConsoleBaseURL)

		req, err := http.NewRequest("GET", "/auth/level1/completed", nil)
		assert.NoError(t, err)

		req = withSessionSettings(req)

		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			AuthState: ceremony.AuthStateInitial,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState 'initial' does not match any required state"
		})).Return()

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
	})

	t.Run("Successful flow, redirect to level2", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, nil, testBaseURL, testAdminConsoleBaseURL)

		req, err := http.NewRequest("GET", "/auth/level1/completed", nil)
		assert.NoError(t, err)

		req = withSessionSettings(req)

		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			AuthState: ceremony.AuthStateLevel1PasswordCompleted,
			ClientId:  "test-client",
			UserId:    1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		sessionIdentifier := "test-session"
		ctx := reqctx.WithSessionIdentifier(req.Context(), sessionIdentifier)
		req = req.WithContext(ctx)

		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: models.AcrLevel1,
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  models.AcrLevel2Optional,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", userSession, testIdleTimeoutInSeconds, testMaxLifetimeInSeconds, mock.AnythingOfType("*int64")).Return(true)

		ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
			return ac.AuthState == ceremony.AuthStateRequiresLevel2
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, testBaseURL+"/auth/level2", rr.Header().Get("Location"))

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Successful flow, redirect to completed", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, nil, testBaseURL, testAdminConsoleBaseURL)

		req, err := http.NewRequest("GET", "/auth/level1/completed", nil)
		assert.NoError(t, err)

		req = withSessionSettings(req)

		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			AuthState: ceremony.AuthStateLevel1PasswordCompleted,
			ClientId:  "test-client",
			UserId:    1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		sessionIdentifier := "test-session"
		ctx := reqctx.WithSessionIdentifier(req.Context(), sessionIdentifier)
		req = req.WithContext(ctx)

		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: models.AcrLevel1,
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  models.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", userSession, testIdleTimeoutInSeconds, testMaxLifetimeInSeconds, mock.AnythingOfType("*int64")).Return(true)

		ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
			return ac.AuthState == ceremony.AuthStateAuthenticationCompleted
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, testBaseURL+"/auth/completed", rr.Header().Get("Location"))

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("No session, auth completed", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, nil, testBaseURL, testAdminConsoleBaseURL)

		req, _ := http.NewRequest("GET", "/auth/level1/completed", nil)
		req = withSessionSettings(req)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			AuthState: ceremony.AuthStateLevel1PasswordCompleted,
			ClientId:  "test-client",
			UserId:    1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		sessionIdentifier := "test-session"
		ctx := reqctx.WithSessionIdentifier(req.Context(), sessionIdentifier)
		req = req.WithContext(ctx)

		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: models.AcrLevel1,
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  models.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", userSession, testIdleTimeoutInSeconds, testMaxLifetimeInSeconds, mock.AnythingOfType("*int64")).Return(false)

		ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
			return ac.AuthState == ceremony.AuthStateAuthenticationCompleted
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, testBaseURL+"/auth/completed", rr.Header().Get("Location"))

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	// The user's authenticator changed since this session last answered the level 2 question,
	// so the session's snapshot is behind the user's counter and a step-up is owed. Nothing is
	// written: NewDatabase(t) fails on an unregistered call, and the explicit AssertNotCalled
	// below says so in its own words, because that deletion is the whole of part 1.1 (#242).
	t.Run("OTP config generation has moved since the session answered", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, nil, testBaseURL, testAdminConsoleBaseURL)

		req, _ := http.NewRequest("GET", "/auth/level1/completed", nil)
		req = withSessionSettings(req)
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			AuthState: ceremony.AuthStateLevel1PasswordCompleted,
			ClientId:  "test-client",
			UserId:    1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		sessionIdentifier := "test-session"
		ctx := reqctx.WithSessionIdentifier(req.Context(), sessionIdentifier)
		req = req.WithContext(ctx)

		// UserSessionLoadUser is stubbed, so User is set here directly: the session answered
		// against generation 0 and the user has since moved to 1.
		userSession := &models.UserSession{
			Id:                  1,
			UserId:              1,
			AcrLevel:            models.AcrLevel2Optional,
			OtpConfigGeneration: 0,
			User:                models.User{Id: 1, OtpConfigGeneration: 1},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  models.AcrLevel2Optional,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", userSession, testIdleTimeoutInSeconds, testMaxLifetimeInSeconds, mock.AnythingOfType("*int64")).Return(true)

		ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
			return ac.AuthState == ceremony.AuthStateRequiresLevel2
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, testBaseURL+"/auth/level2", rr.Header().Get("Location"))

		// Part 1.1. The handler used to clear a boolean here and commit it, so a visitor who
		// closed the browser at the OTP form had already spent the re-prompt and the next
		// ceremony let them through on a password alone. Deciding to ask must write nothing:
		// the obligation is discharged at /auth/completed, once a ceremony has answered it.
		database.AssertNotCalled(t, "UpdateUserSession", mock.Anything, mock.Anything, mock.Anything)
		assert.EqualValues(t, 0, userSession.OtpConfigGeneration,
			"the session's snapshot must not move in memory either")

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("ACR level transitions", func(t *testing.T) {
		tests := []struct {
			name             string
			sessionAcrLevel  models.AcrLevel
			targetAcrLevel   models.AcrLevel
			otpConfigChanged bool
			expectedRedirect string
		}{
			{
				name:             "AcrLevel1 to AcrLevel1",
				sessionAcrLevel:  models.AcrLevel1,
				targetAcrLevel:   models.AcrLevel1,
				expectedRedirect: "/auth/completed",
			},
			{
				name:             "AcrLevel1 to AcrLevel2Optional",
				sessionAcrLevel:  models.AcrLevel1,
				targetAcrLevel:   models.AcrLevel2Optional,
				expectedRedirect: "/auth/level2",
			},
			{
				name:             "AcrLevel1 to AcrLevel2Mandatory",
				sessionAcrLevel:  models.AcrLevel1,
				targetAcrLevel:   models.AcrLevel2Mandatory,
				expectedRedirect: "/auth/level2",
			},
			{
				name:             "AcrLevel2Optional to AcrLevel1",
				sessionAcrLevel:  models.AcrLevel2Optional,
				targetAcrLevel:   models.AcrLevel1,
				expectedRedirect: "/auth/completed",
			},
			{
				name:             "AcrLevel2Optional to AcrLevel2Optional (no change)",
				sessionAcrLevel:  models.AcrLevel2Optional,
				targetAcrLevel:   models.AcrLevel2Optional,
				expectedRedirect: "/auth/completed",
			},
			{
				name:             "AcrLevel2Optional to AcrLevel2Optional (otp config generation moved)",
				sessionAcrLevel:  models.AcrLevel2Optional,
				targetAcrLevel:   models.AcrLevel2Optional,
				otpConfigChanged: true,
				expectedRedirect: "/auth/level2",
			},
			{
				name:             "AcrLevel2Optional to AcrLevel2Mandatory",
				sessionAcrLevel:  models.AcrLevel2Optional,
				targetAcrLevel:   models.AcrLevel2Mandatory,
				expectedRedirect: "/auth/level2",
			},
			{
				name:             "AcrLevel2Mandatory to AcrLevel1",
				sessionAcrLevel:  models.AcrLevel2Mandatory,
				targetAcrLevel:   models.AcrLevel1,
				expectedRedirect: "/auth/completed",
			},
			{
				name:             "AcrLevel2Mandatory to AcrLevel2Optional",
				sessionAcrLevel:  models.AcrLevel2Mandatory,
				targetAcrLevel:   models.AcrLevel2Optional,
				expectedRedirect: "/auth/completed",
			},
			{
				name:             "AcrLevel2Mandatory to AcrLevel2Mandatory",
				sessionAcrLevel:  models.AcrLevel2Mandatory,
				targetAcrLevel:   models.AcrLevel2Mandatory,
				expectedRedirect: "/auth/completed",
			},
			{
				name:             "AcrLevel2Mandatory to AcrLevel2Mandatory (otp config generation moved)",
				sessionAcrLevel:  models.AcrLevel2Mandatory,
				targetAcrLevel:   models.AcrLevel2Mandatory,
				otpConfigChanged: true,
				expectedRedirect: "/auth/level2",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				pageRenderer := mocks_handlers.NewPageRenderer(t)
				ceremonyStore := mocks_handlers.NewCeremonyStore(t)
				userSessionManager := mocks_handlers.NewUserSessionManager(t)
				database := mocks_data.NewDatabase(t)

				handler := HandleAuthLevel1CompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, nil, testBaseURL, testAdminConsoleBaseURL)

				req, _ := http.NewRequest("GET", "/auth/level1/completed", nil)
				req = withSessionSettings(req)
				rr := httptest.NewRecorder()

				authContext := &ceremony.AuthContext{
					AuthState: ceremony.AuthStateLevel1PasswordCompleted,
					ClientId:  "test-client",
					UserId:    1,
				}
				ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

				sessionIdentifier := "test-session"
				ctx := reqctx.WithSessionIdentifier(req.Context(), sessionIdentifier)
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
					AcrLevel:            tt.sessionAcrLevel,
					OtpConfigGeneration: 0,
					User:                models.User{Id: 1, OtpConfigGeneration: userGeneration},
				}
				database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(userSession, nil)
				database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(nil)

				client := &models.Client{
					Id:               1,
					ClientIdentifier: "test-client",
					DefaultAcrLevel:  tt.targetAcrLevel,
				}
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

				userSessionManager.On("HasValidUserSession", userSession, testIdleTimeoutInSeconds, testMaxLifetimeInSeconds, mock.AnythingOfType("*int64")).Return(true)

				expectedAuthState := ceremony.AuthStateAuthenticationCompleted
				if tt.expectedRedirect == "/auth/level2" {
					expectedAuthState = ceremony.AuthStateRequiresLevel2
				}

				ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
					return ac.AuthState == expectedAuthState
				})).Return(nil)

				handler.ServeHTTP(rr, req)

				assert.Equal(t, http.StatusFound, rr.Code)
				assert.Equal(t, testBaseURL+tt.expectedRedirect, rr.Header().Get("Location"))

				// Every row, not only the moved ones: this handler writes nothing at all now,
				// which is what stops an abandoned ceremony spending its re-prompt (#242).
				database.AssertNotCalled(t, "UpdateUserSession", mock.Anything, mock.Anything, mock.Anything)

				pageRenderer.AssertExpectations(t)
				ceremonyStore.AssertExpectations(t)
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
			sessionAcrLevel  models.AcrLevel
			targetAcrLevel   models.AcrLevel
			otpConfigChanged bool
			expectedRedirect string
			description      string
		}{
			{
				name:             "foreign session at the target still prompts for level2",
				sessionAcrLevel:  models.AcrLevel2Optional,
				targetAcrLevel:   models.AcrLevel2Optional,
				expectedRedirect: "/auth/level2",
				description:      "the second-factor bypass: user 1's ACR must not satisfy user 2's step-up",
			},
			{
				name:             "foreign mandatory session still prompts for level2",
				sessionAcrLevel:  models.AcrLevel2Mandatory,
				targetAcrLevel:   models.AcrLevel2Mandatory,
				expectedRedirect: "/auth/level2",
				description:      "the same bypass at the mandatory level, where the second factor is not optional",
			},
			{
				name:             "level1 target is not raised by a foreign session",
				sessionAcrLevel:  models.AcrLevel2Mandatory,
				targetAcrLevel:   models.AcrLevel1,
				expectedRedirect: "/auth/completed",
				description:      "the guard must not invent a second factor a level1 client never asked for",
			},
			{
				name:             "foreign session below the target",
				sessionAcrLevel:  models.AcrLevel1,
				targetAcrLevel:   models.AcrLevel2Optional,
				expectedRedirect: "/auth/level2",
				description:      "control: the target arm already handled this, so a failure here means it broke",
			},
			{
				name:             "the other user's snapshot is left alone",
				sessionAcrLevel:  models.AcrLevel2Optional,
				targetAcrLevel:   models.AcrLevel2Optional,
				otpConfigChanged: true,
				expectedRedirect: "/auth/level2",
				description:      "nothing may write to the other user's row, and nothing writes to any row now",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				pageRenderer := mocks_handlers.NewPageRenderer(t)
				ceremonyStore := mocks_handlers.NewCeremonyStore(t)
				userSessionManager := mocks_handlers.NewUserSessionManager(t)
				database := mocks_data.NewDatabase(t)

				handler := HandleAuthLevel1CompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, nil, testBaseURL, testAdminConsoleBaseURL)

				req, _ := http.NewRequest("GET", "/auth/level1/completed", nil)
				req = withSessionSettings(req)
				rr := httptest.NewRecorder()

				authContext := &ceremony.AuthContext{
					AuthState: ceremony.AuthStateLevel1PasswordCompleted,
					ClientId:  "test-client",
					UserId:    2,
				}
				ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)

				sessionIdentifier := "test-session"
				ctx := reqctx.WithSessionIdentifier(req.Context(), sessionIdentifier)
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
					AcrLevel:            tt.sessionAcrLevel,
					OtpConfigGeneration: 0,
					User:                models.User{Id: 1, OtpConfigGeneration: userGeneration},
				}
				database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(userSession, nil)
				database.On("UserSessionLoadUser", mock.Anything, mock.Anything, userSession).Return(nil)

				client := &models.Client{
					Id:               1,
					ClientIdentifier: "test-client",
					DefaultAcrLevel:  tt.targetAcrLevel,
				}
				database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)

				userSessionManager.On("HasValidUserSession", userSession, testIdleTimeoutInSeconds, testMaxLifetimeInSeconds, mock.AnythingOfType("*int64")).Return(true)

				expectedAuthState := ceremony.AuthStateAuthenticationCompleted
				if tt.expectedRedirect == "/auth/level2" {
					expectedAuthState = ceremony.AuthStateRequiresLevel2
				}

				ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
					return ac.AuthState == expectedAuthState
				})).Return(nil)

				handler.ServeHTTP(rr, req)

				assert.Equal(t, http.StatusFound, rr.Code)
				assert.Equal(t, testBaseURL+tt.expectedRedirect, rr.Header().Get("Location"), tt.description)
				assert.EqualValues(t, 0, userSession.OtpConfigGeneration,
					"the other user's session must not be modified in memory either")
				database.AssertNotCalled(t, "UpdateUserSession", mock.Anything, mock.Anything, mock.Anything)

				pageRenderer.AssertExpectations(t)
				ceremonyStore.AssertExpectations(t)
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

	newParkedContext := func(state string) *ceremony.AuthContext {
		return &ceremony.AuthContext{
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
		ceremony.AuthStateLevel1PasswordCompleted,
		ceremony.AuthStateLevel1ExistingSession,
	} {
		t.Run("answers the client on "+state, func(t *testing.T) {
			pageRenderer := mocks_handlers.NewPageRenderer(t)
			ceremonyStore := mocks_handlers.NewCeremonyStore(t)
			userSessionManager := mocks_handlers.NewUserSessionManager(t)
			database := mocks_data.NewDatabase(t)

			handler := HandleAuthLevel1CompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, nil, testBaseURL, testAdminConsoleBaseURL)

			req := httptest.NewRequest("GET", "/auth/level1completed", nil)
			req = withSessionSettings(req)
			rr := httptest.NewRecorder()

			ceremonyStore.On("GetAuthContext", mock.Anything).Return(newParkedContext(state), nil)

			// The clear goes first, and it has to reach the browser: ClearAuthContext persists the
			// deletion through a Set-Cookie on w, and the answer commits the response, so a clear
			// afterwards would leave the browser holding a context it could replay (#141).
			const clearedContextCookie = "cleared-auth-context"
			ceremonyStore.On("ClearAuthContext", rr, req).Run(func(args mock.Arguments) {
				args.Get(0).(http.ResponseWriter).Header().Set("Set-Cookie", clearedContextCookie)
			}).Return(nil)

			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
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

			pageRenderer.AssertExpectations(t)
			ceremonyStore.AssertExpectations(t)
			database.AssertExpectations(t)
		})
	}

	// The one context that carries a malformed max_age: /auth/authorize parked its refusal for an
	// anonymous browser. It is delivered before anything reads max_age or the session, which is why
	// RequestedMaxAge reading such a value as 0 is never what answers this ceremony (#243).
	t.Run("a parked max_age refusal is delivered without asking about a session", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, nil, testBaseURL, testAdminConsoleBaseURL)

		req := withSessionSettings(httptest.NewRequest("GET", "/auth/level1completed", nil))
		rr := httptest.NewRecorder()

		parked := newParkedContext(ceremony.AuthStateLevel1PasswordCompleted)
		parked.MaxAge = "abc"
		parked.DeferredErrorCode = "invalid_request"
		parked.DeferredErrorDescription = "The max_age parameter must be a non-negative integer."
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(parked, nil)
		ceremonyStore.On("ClearAuthContext", rr, req).Return(nil)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
			&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil)
		stubRegisteredRedirectURI(database, "https://legit.example/cb")

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "legit.example", location.Host)
		assert.Equal(t, "invalid_request", location.Query().Get("error"))
		assert.Equal(t, parked.DeferredErrorDescription, location.Query().Get("error_description"))
		userSessionManager.AssertNotCalled(t, "HasValidUserSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		database.AssertNotCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a failing clear still answers the client, with server_error", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, nil, testBaseURL, testAdminConsoleBaseURL)

		req := httptest.NewRequest("GET", "/auth/level1completed", nil)
		req = withSessionSettings(req)
		rr := httptest.NewRecorder()

		ceremonyStore.On("GetAuthContext", mock.Anything).Return(
			newParkedContext(ceremony.AuthStateLevel1PasswordCompleted), nil)
		ceremonyStore.On("ClearAuthContext", rr, req).Return(assert.AnError)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
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

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
	})

	t.Run("an unusable form_post template answers 500", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		// Deliberately malformed, an unclosed action, so template.ParseFS fails. form_post is the
		// only response mode whose arm can fail after the redirect URI has been validated, and it
		// is also what proves templateFS is genuinely wired through to this handler: with nil
		// passed here instead, this case would 500 for the wrong reason and the parameter could be
		// removed without a test noticing.
		templateFS := fstest.MapFS{
			"form_post.html": {Data: []byte(`<form action="{{ .redirectURI`)},
		}
		handler := HandleAuthLevel1CompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, templateFS, testBaseURL, testAdminConsoleBaseURL)

		req := httptest.NewRequest("GET", "/auth/level1completed", nil)
		req = withSessionSettings(req)
		rr := httptest.NewRecorder()

		authContext := newParkedContext(ceremony.AuthStateLevel1PasswordCompleted)
		authContext.ResponseMode = "form_post"
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)
		ceremonyStore.On("ClearAuthContext", rr, req).Return(nil)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
			&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil)
		stubRegisteredRedirectURI(database, "https://legit.example/cb")
		pageRenderer.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Return()

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
	})

	t.Run("a self-registered client gets the refusal page, not the redirect", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, nil, testBaseURL, testAdminConsoleBaseURL)

		req := httptest.NewRequest("GET", "/auth/level1completed", nil)
		req = withSessionSettings(req)
		rr := httptest.NewRecorder()

		ceremonyStore.On("GetAuthContext", mock.Anything).Return(
			newParkedContext(ceremony.AuthStateLevel1PasswordCompleted), nil)
		ceremonyStore.On("ClearAuthContext", rr, req).Return(nil)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
			&models.Client{Id: 1, ClientIdentifier: "test-client", CreatedViaDCR: true}, nil)
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html",
			"/auth_redirect_blocked.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		// Unreachable in practice, because /auth/authorize renders the interstitial for this client
		// without deferring anything (decision 8). It is asserted because the delivery point loads
		// the client's provenance for itself, so the guard has to hold here too or a future change
		// to that routing would turn this into an open redirect (#108).
		assert.Empty(t, rr.Header().Get("Location"))

		pageRenderer.AssertExpectations(t)
	})

	t.Run("no parked error leaves today's step-up decision alone", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		ceremonyStore := mocks_handlers.NewCeremonyStore(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthLevel1CompletedGet(pageRenderer, ceremonyStore, userSessionManager, database, nil, testBaseURL, testAdminConsoleBaseURL)

		req := httptest.NewRequest("GET", "/auth/level1completed", nil)
		req = withSessionSettings(req)
		req = req.WithContext(reqctx.WithSessionIdentifier(req.Context(), "sess-1"))
		rr := httptest.NewRecorder()

		authContext := &ceremony.AuthContext{
			AuthState: ceremony.AuthStateLevel1PasswordCompleted,
			ClientId:  "test-client",
			UserId:    1,
		}
		ceremonyStore.On("GetAuthContext", mock.Anything).Return(authContext, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "sess-1").Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
			&models.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: models.AcrLevel1}, nil)
		userSessionManager.On("HasValidUserSession", mock.Anything, testIdleTimeoutInSeconds, testMaxLifetimeInSeconds, mock.Anything).Return(false)
		ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
			return ac.AuthState == ceremony.AuthStateAuthenticationCompleted
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		// The sentinel is DeferredErrorCode != "", so a context written by an older binary, where
		// the field is absent and unmarshals to "", reads as "no parked error" and this handler
		// behaves exactly as it did before #213.
		assert.Equal(t, testBaseURL+"/auth/completed", rr.Header().Get("Location"))

		pageRenderer.AssertExpectations(t)
		ceremonyStore.AssertExpectations(t)
	})
}
