package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_test "github.com/leodip/goiabada/core/mocks"
	mocks_user "github.com/leodip/goiabada/core/user/mocks"
)

func TestHandleAuthCompletedGet(t *testing.T) {
	t.Run("Successful flow, existing session (SSO reuse), consent not required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// SSO reuse: AuthenticatedAt is nil (not set by password handler)
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

		sessionAuthTime := time.Now().UTC().Add(-5 * time.Minute)
		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: sessionAuthTime,
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
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		// SSO reuse: no UpdateUserSession call (AuthTime is NOT refreshed)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode &&
				ac.AuthenticatedAt != nil && ac.AuthenticatedAt.Equal(sessionAuthTime)
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("Successful flow, existing session with re-auth, consent not required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// Re-auth case (e.g. prompt=login): AuthenticatedAt set by password handler
		pwdAuthTime := time.Now().UTC()
		authContext := &oauth.AuthContext{
			AuthState:       oauth.AuthStateAuthenticationCompleted,
			ClientId:        "test-client",
			UserId:          1,
			Scope:           "openid profile",
			AuthenticatedAt: &pwdAuthTime,
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		oldAuthTime := time.Now().UTC().Add(-1 * time.Hour)
		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: oldAuthTime,
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
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		// Re-auth: AuthTime is refreshed and session is updated
		database.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(s *models.UserSession) bool {
			return s.Id == userSession.Id && !s.AuthTime.IsZero() && s.AuthTime.After(oldAuthTime)
		})).Return(nil)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode &&
				ac.AuthenticatedAt != nil && !ac.AuthenticatedAt.IsZero() &&
				ac.AuthenticatedAt.After(oldAuthTime)
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	// The only row that distinguishes the two spellings of userReallyAuthenticated. The SSO
	// subtest above carries nil, which short-circuits before !IsZero() is reached, and the
	// re-auth subtest carries a nonzero timestamp, which passes either way; so with the
	// !IsZero() term deleted a zero AuthenticatedAt would count as authentication and the
	// session's AuthTime would be overwritten with now. That term is pre-existing and the
	// #129 gate does not read it, but nothing else in the file covers it (found by round 2
	// of the stage 5 review).
	t.Run("Successful flow, existing session, zero AuthenticatedAt does not refresh AuthTime", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// Non-nil but zero, which is what an AuthContext round-tripped through the cookie
		// yields for an absent RFC 3339 timestamp.
		var zeroAuthenticatedAt time.Time
		authContext := &oauth.AuthContext{
			AuthState:       oauth.AuthStateAuthenticationCompleted,
			ClientId:        "test-client",
			UserId:          1,
			Scope:           "openid profile",
			AuthenticatedAt: &zeroAuthenticatedAt,
		}

		sessionIdentifier := "test-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		sessionAuthTime := time.Now().UTC().Add(-5 * time.Minute)
		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: sessionAuthTime,
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
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		// No UpdateUserSession expectation: a zero timestamp is not authentication, so
		// AuthTime must not be refreshed. Reaching it fails the case on the strict mock.

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		// The session's existing AuthTime is carried forward rather than replaced.
		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode &&
				ac.AuthenticatedAt != nil && ac.AuthenticatedAt.Equal(sessionAuthTime)
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

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

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// This ceremony did level 1: handler_auth_pwd sets both of these. Without
		// Level1AuthCompleted the #129 gate restarts level 1 rather than starting a
		// session, so this subtest is also the positive control for that gate.
		pwdAuthTime := time.Now().UTC()
		authContext := &oauth.AuthContext{
			AuthState:   oauth.AuthStateAuthenticationCompleted,
			ClientId:    "test-client",
			UserId:      1,
			Scope:       "openid profile",
			AuthMethods: "pwd",
			// Nonzero so the StartNewUserSession expectation below pins that the handler
			// forwards THIS value. With 0 the assertion would also pass against a
			// hard-coded zero (#106 decision 11).
			AuthStateGeneration: 7,
			AuthenticatedAt:     &pwdAuthTime,
			Level1AuthCompleted: true,
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
		sessionAuthTime := time.Now().UTC()
		newUserSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: sessionAuthTime,
		}
		userSessionManager.On("StartNewUserSession", rr, req, int64(1), int64(1), "pwd", enums.AcrLevel1.String(), int64(7)).Return(newUserSession, nil)

		auditLogger.On("Log", constants.AuditStartedNewUserSesson, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode &&
				ac.AuthenticatedAt != nil && ac.AuthenticatedAt.Equal(sessionAuthTime)
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

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

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

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

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

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

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

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

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// SSO reuse: AuthenticatedAt is nil
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

		sessionAuthTime := time.Now().UTC().Add(-5 * time.Minute)
		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: sessionAuthTime,
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
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		// SSO reuse: no UpdateUserSession call (AuthTime is NOT refreshed)

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

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// SSO reuse: AuthenticatedAt is nil
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

		sessionAuthTime := time.Now().UTC().Add(-5 * time.Minute)
		userSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: sessionAuthTime,
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
		userSessionManager.On("BumpUserSession", req, sessionIdentifier, int64(1),
			"", enums.AcrLevel1.String()).Return(userSession, nil)

		// SSO reuse: no UpdateUserSession call (AuthTime is NOT refreshed)

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

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// Positive control for the #129 gate, as in the subtest above.
		pwdAuthTime := time.Now().UTC()
		authContext := &oauth.AuthContext{
			AuthState:   oauth.AuthStateAuthenticationCompleted,
			ClientId:    "test-client",
			UserId:      1,
			Scope:       "openid profile",
			AuthMethods: "pwd",
			// Nonzero so the StartNewUserSession expectation below pins that the handler
			// forwards THIS value. With 0 the assertion would also pass against a
			// hard-coded zero (#106 decision 11).
			AuthStateGeneration: 7,
			AuthenticatedAt:     &pwdAuthTime,
			Level1AuthCompleted: true,
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

		sessionAuthTime := time.Now().UTC()
		newUserSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: sessionAuthTime,
		}
		userSessionManager.On("StartNewUserSession", rr, req, int64(1), int64(1), "pwd", enums.AcrLevel1.String(), int64(7)).Return(newUserSession, nil)

		auditLogger.On("Log", constants.AuditStartedNewUserSesson, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile", user).Return("openid profile", nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresConsent &&
				ac.AuthenticatedAt != nil && ac.AuthenticatedAt.Equal(sessionAuthTime)
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/consent", rr.Header().Get("Location"))

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

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// Positive control for the #129 gate, as in the two subtests above.
		pwdAuthTime := time.Now().UTC()
		authContext := &oauth.AuthContext{
			AuthState:   oauth.AuthStateAuthenticationCompleted,
			ClientId:    "test-client",
			UserId:      1,
			Scope:       "openid profile offline_access",
			AuthMethods: "pwd",
			// Nonzero for the same reason as the other cases: it pins that the handler
			// forwards this value rather than a hard-coded zero (#106).
			AuthStateGeneration: 7,
			AuthenticatedAt:     &pwdAuthTime,
			Level1AuthCompleted: true,
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

		sessionAuthTime := time.Now().UTC()
		newUserSession := &models.UserSession{
			Id:       1,
			UserId:   1,
			AcrLevel: enums.AcrLevel1.String(),
			AuthTime: sessionAuthTime,
		}
		userSessionManager.On("StartNewUserSession", rr, req, int64(1), int64(1), "pwd", enums.AcrLevel1.String(), int64(7)).Return(newUserSession, nil)

		auditLogger.On("Log", constants.AuditStartedNewUserSesson, mock.Anything).Return()

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid profile offline_access", user).Return("openid profile offline_access", nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresConsent &&
				ac.AuthenticatedAt != nil && ac.AuthenticatedAt.Equal(sessionAuthTime)
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/consent", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	// #129 decisions 6 and 15. The two subtests below are the gate on the else branch; the
	// three "new session" subtests above are its positive control, since they now differ
	// from these only in carrying Level1AuthCompleted. That pairing is what pins the
	// predicate as "this ceremony did level 1" rather than "no valid session", which is the
	// shape TestSessionDeletedDuringAuthFlow_LoginSucceeds (#46) legitimately has.
	//
	// The second subtest is decision 15's: it carries a non-nil AuthenticatedAt written by
	// the OTP handler, so it is the row that fails against a gate reading
	// userReallyAuthenticated. That discriminator is still read on the valid-session branch,
	// and the zero-AuthenticatedAt subtest above is what covers its !IsZero() term.
	//
	// StartNewUserSession is deliberately not stubbed on the strict mock, so reaching it
	// fails the case on its own rather than through an assertion that could be deleted.
	t.Run("No valid session and this ceremony did not authenticate, restarts level 1", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// An SSO ceremony: handler_authorize copied the session's user, methods and
		// generation onto the context and never reached the password handler, so both
		// AuthenticatedAt and Level1AuthCompleted are unset. The session was then ended
		// mid-flight.
		authContext := &oauth.AuthContext{
			AuthState:           oauth.AuthStateAuthenticationCompleted,
			ClientId:            "test-client",
			UserId:              1,
			Scope:               "openid profile",
			AuthMethods:         "pwd",
			AuthStateGeneration: 7,
			Level1AuthCompleted: false,
		}

		sessionIdentifier := "terminated-session"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySessionIdentifier) == sessionIdentifier
		})).Return(authContext, nil)

		// The session is gone, which is what "ended mid-flight" looks like from here.
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

		userSessionManager.On("HasValidUserSession", mock.Anything, (*models.UserSession)(nil), mock.AnythingOfType("*int")).Return(false)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresLevel1
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("No valid session and only OTP authenticated this ceremony, restarts level 1", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		templateFS := &mocks_test.TestFS{}
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)

		handler := HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, database, templateFS, auditLogger, permissionChecker)

		req, _ := http.NewRequest("GET", "/auth/completed", nil)
		rr := httptest.NewRecorder()

		// Decision 15's ceremony. An SSO reuse stepped up to level 2, so AuthMethods came
		// off the reused session and handler_auth_otp set AuthenticatedAt on a successful
		// code, but no password was ever entered, so Level1AuthCompleted stays false. A gate
		// reading userReallyAuthenticated recreates the session here; this gate must not.
		otpAuthTime := time.Now().UTC()
		authContext := &oauth.AuthContext{
			AuthState:           oauth.AuthStateAuthenticationCompleted,
			ClientId:            "test-client",
			UserId:              1,
			Scope:               "openid profile",
			AuthMethods:         "pwd otp",
			AuthStateGeneration: 7,
			AuthenticatedAt:     &otpAuthTime,
			Level1AuthCompleted: false,
		}

		sessionIdentifier := "terminated-session"
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
			ConsentRequired:          false,
			DefaultAcrLevel:          enums.AcrLevel1,
			AuthorizationCodeEnabled: true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, (*models.UserSession)(nil), mock.AnythingOfType("*int")).Return(false)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresLevel1
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})
}
