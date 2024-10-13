package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_test "github.com/leodip/goiabada/core/mocks"
	mocks_user "github.com/leodip/goiabada/core/user/mocks"
)

func TestHandleAuthCompleted(t *testing.T) {
	t.Run("Successful flow, existing session, consent not required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompleted(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateAuthenticationCompleted,
			ClientId:  "test-client",
			UserId:    1,
			Scope:     "openid profile",
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1)).Return(userSession, nil)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("Successful flow, new session, consent not required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompleted(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:   oauth.AuthStateAuthenticationCompleted,
			ClientId:    "test-client",
			UserId:      1,
			Scope:       "openid profile",
			AuthMethods: "pwd",
		}

		sessionIdentifier := "new-test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		// Simulating no existing session
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		// Expect HasValidUserSession to return false for a new session
		userSessionManager.On("HasValidUserSession", mock.Anything, (*models.UserSession)(nil), mock.AnythingOfType("*int")).Return(false)

		// Expect StartNewUserSession to be called instead of BumpUserSession
		newUserSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
		}
		userSessionManager.On("StartNewUserSession", rr, req, int64(1), int64(1), "pwd", enums.AcrLevel1.String()).Return(newUserSession, nil)

		auditLogger.On("Log", constants.AuditStartedNewUserSesson, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("Error in GetAuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompleted(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		expectedError := errors.New("auth context error")
		authHelper.On("GetAuthContext", mock.Anything).Return(nil, expectedError)

		profileUrl := "http://example.com/account/profile"
		config.GetAdminConsole().BaseURL = profileUrl

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == expectedError.Error()
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Invalid AuthState", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompleted(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "authContext.AuthState is not authentication_completed")
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Client is nil", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompleted(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateAuthenticationCompleted,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "client test-client not found")
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("User is not enabled", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompleted(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateAuthenticationCompleted,
			ClientId:     "test-client",
			UserId:       1,
			Scope:        "openid profile",
			ResponseMode: "query",
			RedirectURI:  "https://example.com/callback",
			State:        "some-state",
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1)).Return(userSession, nil)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: false,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.Anything).Return()

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)

		// Check redirection URL
		location, _ := rr.Result().Location()
		assert.Equal(t, "https://example.com/callback", location.Scheme+"://"+location.Host+location.Path)

		// Check query parameters
		query := location.Query()
		assert.Equal(t, "access_denied", query.Get("error"))
		assert.Contains(t, query.Get("error_description"), "The user account is disabled")
		assert.Equal(t, "some-state", query.Get("state"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("authContext.Scope is filtered and becomes empty", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompleted(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateAuthenticationCompleted,
			ClientId:     "test-client",
			UserId:       1,
			Scope:        "openid profile",
			ResponseMode: "query",
			RedirectURI:  "https://example.com/callback",
			State:        "some-state",
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1)).Return(userSession, nil)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		// Simulate the scope being filtered to an empty string
		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("", nil)

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)

		// Check redirection URL
		location, _ := rr.Result().Location()
		assert.Equal(t, "https://example.com/callback", location.Scheme+"://"+location.Host+location.Path)

		// Check query parameters
		query := location.Query()
		assert.Equal(t, "access_denied", query.Get("error"))
		assert.Contains(t, query.Get("error_description"), "The user is not authorized to access any of the requested scopes")
		assert.Equal(t, "some-state", query.Get("state"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("Successful flow, new session, consent required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompleted(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:   oauth.AuthStateAuthenticationCompleted,
			ClientId:    "test-client",
			UserId:      1,
			Scope:       "openid profile",
			AuthMethods: "pwd",
		}

		sessionIdentifier := "new-test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          true,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, (*models.UserSession)(nil), mock.AnythingOfType("*int")).Return(false)

		newUserSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
		}
		userSessionManager.On("StartNewUserSession", rr, req, int64(1), int64(1), "pwd", enums.AcrLevel1.String()).Return(newUserSession, nil)

		auditLogger.On("Log", constants.AuditStartedNewUserSesson, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresConsent
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/auth/consent", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("Successful flow, new session, offline_access scope requires consent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompleted(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:   oauth.AuthStateAuthenticationCompleted,
			ClientId:    "test-client",
			UserId:      1,
			Scope:       "openid profile offline_access",
			AuthMethods: "pwd",
		}

		sessionIdentifier := "new-test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			ConsentRequired:          false, // Note: This is false, but consent should still be required due to offline_access
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, (*models.UserSession)(nil), mock.AnythingOfType("*int")).Return(false)

		newUserSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
		}
		userSessionManager.On("StartNewUserSession", rr, req, int64(1), int64(1), "pwd", enums.AcrLevel1.String()).Return(newUserSession, nil)

		auditLogger.On("Log", constants.AuditStartedNewUserSesson, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile offline_access", user).Return("openid profile offline_access", nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresConsent
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/auth/consent", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})
}
