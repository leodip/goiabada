package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oauth"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestBuildScopeInfoArray(t *testing.T) {
	t.Run("Empty scope", func(t *testing.T) {
		result := buildScopeInfoArray("", nil)
		assert.Empty(t, result)
	})

	t.Run("OIDC scopes", func(t *testing.T) {
		scope := "openid profile email offline_access"
		consent := &models.UserConsent{
			Scope: "openid profile",
		}
		result := buildScopeInfoArray(scope, consent)

		expected := []ScopeInfo{
			{Scope: "openid", Description: "Authenticate your user and allow access to the subject identifier (sub claim)", AlreadyConsented: true},
			{Scope: "profile", Description: "Access to claims: name, family_name, given_name, middle_name, nickname, preferred_username, profile, website, gender, birthdate, zoneinfo, locale, and updated_at", AlreadyConsented: true},
			{Scope: "email", Description: "Access to claims: email, email_verified", AlreadyConsented: false},
			{Scope: "offline_access", Description: "Access to an offline refresh token, allowing the client to obtain a new access token without requiring your immediate interaction", AlreadyConsented: false},
		}

		assert.Equal(t, expected, result)
	})

	t.Run("Custom scopes", func(t *testing.T) {
		scope := "resource1:read resource2:write"
		consent := &models.UserConsent{
			Scope: "resource1:read",
		}
		result := buildScopeInfoArray(scope, consent)

		expected := []ScopeInfo{
			{Scope: "resource1:read", Description: "Permission read on resource resource1", AlreadyConsented: true},
			{Scope: "resource2:write", Description: "Permission write on resource resource2", AlreadyConsented: false},
		}

		assert.Equal(t, expected, result)
	})

	t.Run("Mixed scopes", func(t *testing.T) {
		scope := "openid profile resource1:read"
		consent := &models.UserConsent{
			Scope: "openid resource1:read",
		}
		result := buildScopeInfoArray(scope, consent)

		expected := []ScopeInfo{
			{Scope: "openid", Description: "Authenticate your user and allow access to the subject identifier (sub claim)", AlreadyConsented: true},
			{Scope: "profile", Description: "Access to claims: name, family_name, given_name, middle_name, nickname, preferred_username, profile, website, gender, birthdate, zoneinfo, locale, and updated_at", AlreadyConsented: false},
			{Scope: "resource1:read", Description: "Permission read on resource resource1", AlreadyConsented: true},
		}

		assert.Equal(t, expected, result)
	})

	t.Run("No consent", func(t *testing.T) {
		scope := "openid profile resource1:read"
		result := buildScopeInfoArray(scope, nil)

		expected := []ScopeInfo{
			{Scope: "openid", Description: "Authenticate your user and allow access to the subject identifier (sub claim)", AlreadyConsented: false},
			{Scope: "profile", Description: "Access to claims: name, family_name, given_name, middle_name, nickname, preferred_username, profile, website, gender, birthdate, zoneinfo, locale, and updated_at", AlreadyConsented: false},
			{Scope: "resource1:read", Description: "Permission read on resource resource1", AlreadyConsented: false},
		}

		assert.Equal(t, expected, result)
	})

	t.Run("All OIDC scopes", func(t *testing.T) {
		scope := "openid profile email address phone groups attributes offline_access"
		result := buildScopeInfoArray(scope, nil)

		expected := []ScopeInfo{
			{Scope: "openid", Description: "Authenticate your user and allow access to the subject identifier (sub claim)", AlreadyConsented: false},
			{Scope: "profile", Description: "Access to claims: name, family_name, given_name, middle_name, nickname, preferred_username, profile, website, gender, birthdate, zoneinfo, locale, and updated_at", AlreadyConsented: false},
			{Scope: "email", Description: "Access to claims: email, email_verified", AlreadyConsented: false},
			{Scope: "address", Description: "Access to the address claim", AlreadyConsented: false},
			{Scope: "phone", Description: "Access to claims: phone_number and phone_number_verified", AlreadyConsented: false},
			{Scope: "groups", Description: "Access to the list of groups that you belong to", AlreadyConsented: false},
			{Scope: "attributes", Description: "Access to the attributes assigned to you by an admin, stored as key-value pairs", AlreadyConsented: false},
			{Scope: "offline_access", Description: "Access to an offline refresh token, allowing the client to obtain a new access token without requiring your immediate interaction", AlreadyConsented: false},
		}

		assert.Equal(t, expected, result)
	})
}

func TestFilterOutScopesWhereUserIsNotAuthorized(t *testing.T) {

	t.Run("All scopes authorized", func(t *testing.T) {
		mockPermissionChecker := mocks.NewPermissionChecker(t)
		user := &models.User{Id: 1}

		mockPermissionChecker.On("UserHasScopePermission", int64(1), "resource1:read").Return(true, nil)
		mockPermissionChecker.On("UserHasScopePermission", int64(1), "resource2:write").Return(true, nil)

		result, err := filterOutScopesWhereUserIsNotAuthorized("openid profile resource1:read resource2:write", user, mockPermissionChecker)

		assert.NoError(t, err)
		assert.Equal(t, "openid profile resource1:read resource2:write", result)
		mockPermissionChecker.AssertExpectations(t)
	})

	t.Run("Some scopes unauthorized", func(t *testing.T) {
		mockPermissionChecker := mocks.NewPermissionChecker(t)
		user := &models.User{Id: 1}

		mockPermissionChecker.On("UserHasScopePermission", int64(1), "resource1:read").Return(true, nil)
		mockPermissionChecker.On("UserHasScopePermission", int64(1), "resource2:write").Return(false, nil)

		result, err := filterOutScopesWhereUserIsNotAuthorized("openid profile resource1:read resource2:write", user, mockPermissionChecker)

		assert.NoError(t, err)
		assert.Equal(t, "openid profile resource1:read", result)
		mockPermissionChecker.AssertExpectations(t)
	})

	t.Run("Invalid scope format", func(t *testing.T) {
		mockPermissionChecker := mocks.NewPermissionChecker(t)
		user := &models.User{Id: 1}

		_, err := filterOutScopesWhereUserIsNotAuthorized("invalid_scope", user, mockPermissionChecker)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid scope format")
	})

	t.Run("Permission check error", func(t *testing.T) {
		mockPermissionChecker := mocks.NewPermissionChecker(t)
		user := &models.User{Id: 1}

		mockPermissionChecker.On("UserHasScopePermission", int64(1), "resource1:read").Return(false, errors.New("permission check failed"))

		_, err := filterOutScopesWhereUserIsNotAuthorized("resource1:read", user, mockPermissionChecker)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "permission check failed")
		mockPermissionChecker.AssertExpectations(t)
	})

	t.Run("Empty input scope", func(t *testing.T) {
		mockPermissionChecker := mocks.NewPermissionChecker(t)
		user := &models.User{Id: 1}

		result, err := filterOutScopesWhereUserIsNotAuthorized("", user, mockPermissionChecker)

		assert.NoError(t, err)
		assert.Equal(t, "", result)
	})

	t.Run("Only OIDC scopes", func(t *testing.T) {
		mockPermissionChecker := mocks.NewPermissionChecker(t)
		user := &models.User{Id: 1}

		result, err := filterOutScopesWhereUserIsNotAuthorized("openid profile email", user, mockPermissionChecker)

		assert.NoError(t, err)
		assert.Equal(t, "openid profile email", result)
	})

	t.Run("Mixed OIDC and custom scopes", func(t *testing.T) {
		mockPermissionChecker := mocks.NewPermissionChecker(t)
		user := &models.User{Id: 1}

		mockPermissionChecker.On("UserHasScopePermission", int64(1), "resource1:read").Return(true, nil)
		mockPermissionChecker.On("UserHasScopePermission", int64(1), "resource1:write").Return(false, nil)

		result, err := filterOutScopesWhereUserIsNotAuthorized("openid email resource1:read resource1:write offline_access", user, mockPermissionChecker)

		assert.NoError(t, err)
		assert.Equal(t, "openid email resource1:read offline_access", result)
		mockPermissionChecker.AssertExpectations(t)
	})

	t.Run("Nil user", func(t *testing.T) {
		mockPermissionChecker := mocks.NewPermissionChecker(t)

		_, err := filterOutScopesWhereUserIsNotAuthorized("openid profile", nil, mockPermissionChecker)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user is nil")
	})

	t.Run("Nil permission checker", func(t *testing.T) {
		user := &models.User{Id: 1}

		_, err := filterOutScopesWhereUserIsNotAuthorized("openid profile", user, nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "permissionChecker is nil")
	})
}

func TestHandleConsentGet(t *testing.T) {
	t.Run("GetAuthContext errors", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		templateFS := mocks.TestFS{}
		codeIssuer := mocks.NewCodeIssuer(t)
		permissionChecker := mocks.NewPermissionChecker(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleConsentGet(httpHelper, authHelper, database, &templateFS, codeIssuer, permissionChecker, auditLogger)

		req, _ := http.NewRequest("GET", "/consent", nil)
		rr := httptest.NewRecorder()

		expectedError := errors.New("auth context error")
		authHelper.On("GetAuthContext", req).Return(nil, expectedError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "auth context error"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("AuthContext auth is not completed", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		templateFS := mocks.TestFS{}
		codeIssuer := mocks.NewCodeIssuer(t)
		permissionChecker := mocks.NewPermissionChecker(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleConsentGet(httpHelper, authHelper, database, &templateFS, codeIssuer, permissionChecker, auditLogger)

		req, _ := http.NewRequest("GET", "/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{UserId: 1, AuthCompleted: false}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext is missing or has an unexpected state"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("AuthContext is missing", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		templateFS := mocks.TestFS{}
		codeIssuer := mocks.NewCodeIssuer(t)
		permissionChecker := mocks.NewPermissionChecker(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleConsentGet(httpHelper, authHelper, database, &templateFS, codeIssuer, permissionChecker, auditLogger)

		req, _ := http.NewRequest("GET", "/consent", nil)
		rr := httptest.NewRecorder()

		authHelper.On("GetAuthContext", req).Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext is missing or has an unexpected state"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		templateFS := mocks.TestFS{}
		codeIssuer := mocks.NewCodeIssuer(t)
		permissionChecker := mocks.NewPermissionChecker(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleConsentGet(httpHelper, authHelper, database, &templateFS, codeIssuer, permissionChecker, auditLogger)

		req, _ := http.NewRequest("GET", "/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{UserId: 1, AuthCompleted: true}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		database.On("GetUserById", mock.Anything, int64(1)).Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("User is disabled", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		templateFS := &mocks.TestFS{
			FileContents: map[string]string{
				"layouts/auth_layout.html": "{{template \"content\" .}}",
				"error.html":               "<div>{{.Error}}</div>",
			},
		}
		codeIssuer := mocks.NewCodeIssuer(t)
		permissionChecker := mocks.NewPermissionChecker(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleConsentGet(httpHelper, authHelper, database, templateFS, codeIssuer, permissionChecker, auditLogger)

		req, _ := http.NewRequest("GET", "/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId:        1,
			AuthCompleted: true,
			RedirectURI:   "http://example.com/callback",
			State:         "somestate",
			ResponseMode:  "query",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		user := &models.User{Id: 1, Enabled: false}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.Anything).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "http://example.com/callback?error=access_denied&error_description=The+user+is+not+enabled&state=somestate", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("User not authorized for any requested scopes", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		templateFS := &mocks.TestFS{
			FileContents: map[string]string{
				"layouts/auth_layout.html": "{{template \"content\" .}}",
				"error.html":               "<div>{{.Error}}</div>",
			},
		}
		codeIssuer := mocks.NewCodeIssuer(t)
		permissionChecker := mocks.NewPermissionChecker(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleConsentGet(httpHelper, authHelper, database, templateFS, codeIssuer, permissionChecker, auditLogger)

		req, _ := http.NewRequest("GET", "/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId:        1,
			AuthCompleted: true,
			Scope:         "resource1:read resource2:write",
			RedirectURI:   "http://example.com/callback",
			State:         "somestate",
			ResponseMode:  "query",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		user := &models.User{Id: 1, Enabled: true}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		permissionChecker.On("UserHasScopePermission", int64(1), "resource1:read").Return(false, nil)
		permissionChecker.On("UserHasScopePermission", int64(1), "resource2:write").Return(false, nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "http://example.com/callback?error=access_denied&error_description=The+user+is+not+authorized+to+access+any+of+the+requested+scopes&state=somestate", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("GetClientByClientIdentifier returns a nil client", func(t *testing.T) {
		httpHelper := &mocks.HttpHelper{}
		authHelper := &mocks.AuthHelper{}
		database := &mocks.Database{}
		templateFS := &mocks.TestFS{}
		codeIssuer := &mocks.CodeIssuer{}
		permissionChecker := &mocks.PermissionChecker{}
		auditLogger := &mocks.AuditLogger{}

		handler := HandleConsentGet(httpHelper, authHelper, database, templateFS, codeIssuer, permissionChecker, auditLogger)

		req, _ := http.NewRequest("GET", "/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId:        1,
			AuthCompleted: true,
			ClientId:      "test-client",
			Scope:         "openid profile",
		}

		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		user := &models.User{Id: 1, Email: "test@example.com", Enabled: true}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "client not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("client.ConsentRequired and scopes not fully consented", func(t *testing.T) {
		httpHelper := &mocks.HttpHelper{}
		authHelper := &mocks.AuthHelper{}
		database := &mocks.Database{}
		templateFS := &mocks.TestFS{}
		codeIssuer := &mocks.CodeIssuer{}
		permissionChecker := &mocks.PermissionChecker{}
		auditLogger := &mocks.AuditLogger{}

		handler := HandleConsentGet(httpHelper, authHelper, database, templateFS, codeIssuer, permissionChecker, auditLogger)

		req, _ := http.NewRequest("GET", "/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId:        1,
			AuthCompleted: true,
			ClientId:      "test-client",
			Scope:         "openid profile",
		}

		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		user := &models.User{Id: 1, Email: "test@example.com", Enabled: true}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		client := &models.Client{Id: 1, ClientIdentifier: "test-client", ConsentRequired: true, Description: "Test Client"}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		consent := &models.UserConsent{
			UserId:   1,
			ClientId: 1,
			Scope:    "openid",
		}
		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(consent, nil)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/consent.html", mock.MatchedBy(func(bind map[string]interface{}) bool {
			// Check if all expected keys are present
			expectedKeys := []string{"csrfField", "clientIdentifier", "clientDescription", "scopes"}
			for _, key := range expectedKeys {
				if _, ok := bind[key]; !ok {
					return false
				}
			}

			// Check specific values
			if bind["clientIdentifier"] != "test-client" {
				return false
			}
			if bind["clientDescription"] != "Test Client" {
				return false
			}

			// Check scopes
			scopes, ok := bind["scopes"].([]ScopeInfo)
			if !ok {
				return false
			}
			if len(scopes) != 2 {
				return false
			}

			// Check individual scopes
			expectedScopes := map[string]bool{
				"openid":  true,
				"profile": false,
			}
			for _, scope := range scopes {
				alreadyConsented, ok := expectedScopes[scope.Scope]
				if !ok || scope.AlreadyConsented != alreadyConsented {
					return false
				}
			}

			return true
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("authContext has scope offline_access", func(t *testing.T) {
		httpHelper := &mocks.HttpHelper{}
		authHelper := &mocks.AuthHelper{}
		database := &mocks.Database{}
		templateFS := &mocks.TestFS{}
		codeIssuer := &mocks.CodeIssuer{}
		permissionChecker := &mocks.PermissionChecker{}
		auditLogger := &mocks.AuditLogger{}

		handler := HandleConsentGet(httpHelper, authHelper, database, templateFS, codeIssuer, permissionChecker, auditLogger)

		req, _ := http.NewRequest("GET", "/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId:        1,
			AuthCompleted: true,
			ClientId:      "test-client",
			Scope:         "openid profile offline_access",
		}

		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		user := &models.User{Id: 1, Email: "test@example.com", Enabled: true}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		client := &models.Client{Id: 1, ClientIdentifier: "test-client", ConsentRequired: false, Description: "Test Client"}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		consent := &models.UserConsent{
			UserId:   1,
			ClientId: 1,
			Scope:    "openid",
		}
		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(consent, nil)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/consent.html", mock.MatchedBy(func(bind map[string]interface{}) bool {
			// Check if all expected keys are present
			expectedKeys := []string{"csrfField", "clientIdentifier", "clientDescription", "scopes"}
			for _, key := range expectedKeys {
				if _, ok := bind[key]; !ok {
					return false
				}
			}

			// Check specific values
			if bind["clientIdentifier"] != "test-client" {
				return false
			}
			if bind["clientDescription"] != "Test Client" {
				return false
			}

			// Check scopes
			scopes, ok := bind["scopes"].([]ScopeInfo)
			if !ok {
				return false
			}
			if len(scopes) != 3 {
				return false
			}

			// Check individual scopes
			expectedScopes := map[string]bool{
				"openid":         true,
				"profile":        false,
				"offline_access": false,
			}
			for _, scope := range scopes {
				alreadyConsented, ok := expectedScopes[scope.Scope]
				if !ok || scope.AlreadyConsented != alreadyConsented {
					return false
				}
			}

			return true
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
	})

	t.Run("Create and issue auth code when consent is not required", func(t *testing.T) {
		httpHelper := &mocks.HttpHelper{}
		authHelper := &mocks.AuthHelper{}
		database := &mocks.Database{}
		templateFS := &mocks.TestFS{}
		codeIssuer := &mocks.CodeIssuer{}
		permissionChecker := &mocks.PermissionChecker{}
		auditLogger := &mocks.AuditLogger{}

		handler := HandleConsentGet(httpHelper, authHelper, database, templateFS, codeIssuer, permissionChecker, auditLogger)

		req, _ := http.NewRequest("GET", "/consent", nil)
		rr := httptest.NewRecorder()

		sessionIdentifier := "test-session-id"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		authContext := &oauth.AuthContext{
			UserId:        1,
			AuthCompleted: true,
			ClientId:      "test-client",
			Scope:         "openid profile",
			ResponseMode:  "query",
			RedirectURI:   "https://example.com/callback",
			State:         "test-state",
		}

		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		user := &models.User{Id: 1, Email: "test@example.com", Enabled: true}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{Id: 1, ClientIdentifier: "test-client", ConsentRequired: false}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(nil)

		createdCode := &models.Code{
			Code:        "test-auth-code",
			RedirectURI: "https://example.com/callback",
			State:       "test-state",
		}
		codeIssuer.On("CreateAuthCode", mock.Anything, mock.MatchedBy(func(input *oauth.CreateCodeInput) bool {
			return input.AuthContext.UserId == authContext.UserId &&
				input.AuthContext.ClientId == authContext.ClientId &&
				input.AuthContext.Scope == authContext.Scope &&
				input.SessionIdentifier == sessionIdentifier
		})).Return(createdCode, nil)

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		auditLogger.On("Log", constants.AuditCreatedAuthCode, mock.Anything).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		assert.Equal(t, http.StatusFound, rr.Code, "Expected a redirect status code")

		location := rr.Header().Get("Location")
		assert.NotEmpty(t, location, "Location header should not be empty")

		redirectURL, err := url.Parse(location)
		assert.NoError(t, err, "Should be able to parse the redirect URL")

		assert.Equal(t, "https", redirectURL.Scheme, "Scheme should be https")
		assert.Equal(t, "example.com", redirectURL.Host, "Host should be example.com")
		assert.Equal(t, "/callback", redirectURL.Path, "Path should be /callback")

		query := redirectURL.Query()
		assert.Equal(t, "test-auth-code", query.Get("code"), "code parameter should match")
		assert.Equal(t, "test-state", query.Get("state"), "state parameter should match")
	})
}

func TestHandleConsentPost(t *testing.T) {
	t.Run("GetAuthContext gives error", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		templateFS := &mocks.TestFS{}
		codeIssuer := mocks.NewCodeIssuer(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, templateFS, codeIssuer, auditLogger)

		req, _ := http.NewRequest("POST", "/consent", nil)
		rr := httptest.NewRecorder()

		expectedError := errors.New("auth context error")
		authHelper.On("GetAuthContext", req).Return(nil, expectedError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "auth context error"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("authContext is null", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		templateFS := &mocks.TestFS{}
		codeIssuer := mocks.NewCodeIssuer(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, templateFS, codeIssuer, auditLogger)

		req, _ := http.NewRequest("POST", "/consent", nil)
		rr := httptest.NewRecorder()

		authHelper.On("GetAuthContext", req).Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext is missing or has an unexpected state"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("authContext auth is not completed", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		templateFS := &mocks.TestFS{}
		codeIssuer := mocks.NewCodeIssuer(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, templateFS, codeIssuer, auditLogger)

		req, _ := http.NewRequest("POST", "/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId:        1,
			AuthCompleted: false,
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext is missing or has an unexpected state"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("When consent is not given, it redirects to client with an error and clears the auth context", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		templateFS := &mocks.TestFS{}
		codeIssuer := mocks.NewCodeIssuer(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, templateFS, codeIssuer, auditLogger)

		req, _ := http.NewRequest("POST", "/consent", strings.NewReader("btnCancel=cancel"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId:        1,
			ClientId:      "test-client",
			AuthCompleted: true,
			RedirectURI:   "http://example.com/callback",
			State:         "test-state",
			ResponseMode:  "query",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "http://example.com/callback?error=access_denied&error_description=The+user+did+not+provide+consent&state=test-state", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("When form is submitted with no scopes selected, it redirects to client with an error and clears the auth context", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		templateFS := &mocks.TestFS{}
		codeIssuer := mocks.NewCodeIssuer(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, templateFS, codeIssuer, auditLogger)

		req, _ := http.NewRequest("POST", "/consent", strings.NewReader("btnSubmit=submit"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId:        1,
			ClientId:      "test-client",
			AuthCompleted: true,
			RedirectURI:   "http://example.com/callback",
			State:         "test-state",
			ResponseMode:  "query",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "http://example.com/callback?error=access_denied&error_description=The+user+did+not+provide+consent&state=test-state", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("When consent form is submitted but the client is not found", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		templateFS := &mocks.TestFS{}
		codeIssuer := mocks.NewCodeIssuer(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, templateFS, codeIssuer, auditLogger)

		req, _ := http.NewRequest("POST", "/consent", strings.NewReader("btnSubmit=submit&consent0=openid"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId:        1,
			ClientId:      "non-existent-client",
			AuthCompleted: true,
			RedirectURI:   "http://example.com/callback",
			State:         "test-state",
			ResponseMode:  "query",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		database.On("GetClientByClientIdentifier", mock.Anything, "non-existent-client").Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "client not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Consent form is submitted but the user is not found", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		templateFS := &mocks.TestFS{}
		codeIssuer := mocks.NewCodeIssuer(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, templateFS, codeIssuer, auditLogger)

		req, _ := http.NewRequest("POST", "/consent", strings.NewReader("btnSubmit=submit&consent0=openid"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId:        999, // Non-existent user ID
			ClientId:      "test-client",
			AuthCompleted: true,
			RedirectURI:   "http://example.com/callback",
			State:         "test-state",
			ResponseMode:  "query",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		client := &models.Client{Id: 1, ClientIdentifier: "test-client"}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		database.On("GetUserById", mock.Anything, int64(999)).Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Submit and update existing consent", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		templateFS := &mocks.TestFS{}
		codeIssuer := mocks.NewCodeIssuer(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, templateFS, codeIssuer, auditLogger)

		form := url.Values{}
		form.Add("btnSubmit", "submit")
		form.Add("consent0", "openid")
		form.Add("consent1", "profile")
		req, _ := http.NewRequest("POST", "/consent", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId:        1,
			ClientId:      "test-client",
			Scope:         "openid profile email",
			AuthCompleted: true,
			RedirectURI:   "http://example.com/callback",
			State:         "test-state",
			ResponseMode:  "query",
		}
		authHelper.On("GetAuthContext", mock.AnythingOfType("*http.Request")).Return(authContext, nil)

		client := &models.Client{Id: 1, ClientIdentifier: "test-client"}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		user := &models.User{Id: 1, Email: "test@example.com"}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		existingConsent := &models.UserConsent{
			Id:       1,
			UserId:   1,
			ClientId: 1,
			Scope:    "openid",
		}
		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(existingConsent, nil)

		database.On("UpdateUserConsent", mock.Anything, mock.MatchedBy(func(consent *models.UserConsent) bool {
			return consent.Id == 1 && consent.Scope == "openid profile"
		})).Return(nil)

		sessionIdentifier := "test-session-id"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		code := &models.Code{
			Code:        "test-code",
			State:       "test-state",
			RedirectURI: "http://example.com/callback",
		}
		codeIssuer.On("CreateAuthCode", mock.Anything, mock.MatchedBy(func(input *oauth.CreateCodeInput) bool {
			return input.AuthContext.UserId == 1 &&
				input.AuthContext.ClientId == "test-client" &&
				input.AuthContext.ConsentedScope == "openid profile" &&
				input.SessionIdentifier == sessionIdentifier
		})).Return(code, nil)

		auditLogger.On("Log", constants.AuditSavedConsent, mock.Anything).Return()
		auditLogger.On("Log", constants.AuditCreatedAuthCode, mock.Anything).Return()

		authHelper.On("ClearAuthContext", mock.Anything, mock.AnythingOfType("*http.Request")).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "http://example.com/callback?code=test-code&state=test-state", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Submit and create new user consent", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		templateFS := &mocks.TestFS{}
		codeIssuer := mocks.NewCodeIssuer(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, templateFS, codeIssuer, auditLogger)

		form := url.Values{}
		form.Add("btnSubmit", "submit")
		form.Add("consent0", "openid")
		form.Add("consent1", "profile")
		form.Add("consent2", "email")
		req, _ := http.NewRequest("POST", "/consent", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId:        1,
			ClientId:      "test-client",
			Scope:         "openid profile email",
			AuthCompleted: true,
			RedirectURI:   "http://example.com/callback",
			State:         "test-state",
			ResponseMode:  "query",
		}
		authHelper.On("GetAuthContext", mock.AnythingOfType("*http.Request")).Return(authContext, nil)

		client := &models.Client{Id: 1, ClientIdentifier: "test-client"}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		user := &models.User{Id: 1, Email: "test@example.com"}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(nil, nil)

		database.On("CreateUserConsent", mock.Anything, mock.MatchedBy(func(consent *models.UserConsent) bool {
			return consent.UserId == 1 &&
				consent.ClientId == 1 &&
				consent.Scope == "openid profile email" &&
				consent.GrantedAt.Valid
		})).Return(nil)

		sessionIdentifier := "test-session-id"
		ctx := context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		code := &models.Code{
			Code:        "test-code",
			State:       "test-state",
			RedirectURI: "http://example.com/callback",
		}
		codeIssuer.On("CreateAuthCode", mock.Anything, mock.MatchedBy(func(input *oauth.CreateCodeInput) bool {
			return input.AuthContext.UserId == 1 &&
				input.AuthContext.ClientId == "test-client" &&
				input.AuthContext.ConsentedScope == "openid profile email" &&
				input.SessionIdentifier == sessionIdentifier
		})).Return(code, nil)

		auditLogger.On("Log", constants.AuditSavedConsent, mock.Anything).Return()
		auditLogger.On("Log", constants.AuditCreatedAuthCode, mock.Anything).Return()

		authHelper.On("ClearAuthContext", mock.Anything, mock.AnythingOfType("*http.Request")).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "http://example.com/callback?code=test-code&state=test-state", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})
}

func TestIssueAuthCode(t *testing.T) {
	t.Run("Query response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/test", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "http://example.com/callback",
			State:       "test_state",
		}
		responseMode := "query"

		err := issueAuthCode(w, r, nil, code, responseMode)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "http://example.com/callback?code=test_code&state=test_state", w.Header().Get("Location"))
	})

	t.Run("Fragment response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/test", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "http://example.com/callback?existing=param1",
			State:       "test_state",
		}
		responseMode := "fragment"

		err := issueAuthCode(w, r, nil, code, responseMode)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "http://example.com/callback?existing=param1#code=test_code&state=test_state", w.Header().Get("Location"))
	})

	t.Run("Form post response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/test", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "http://example.com/callback?existing=param1",
			State:       "test_state",
		}
		responseMode := "form_post"

		templateFS := &mocks.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form method="post" action="{{.redirectURI}}">
					<input type="hidden" name="code" value="{{.code}}">
					<input type="hidden" name="state" value="{{.state}}">
				</form>`,
			},
		}

		err := issueAuthCode(w, r, templateFS, code, responseMode)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `<form method="post" action="http://example.com/callback?existing=param1">`)
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="code" value="test_code">`)
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="state" value="test_state">`)
	})

	t.Run("Default to query response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/test", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "http://example.com/callback?existing=param1",
			State:       "test_state",
		}
		responseMode := ""

		err := issueAuthCode(w, r, nil, code, responseMode)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "http://example.com/callback?code=test_code&existing=param1&state=test_state", w.Header().Get("Location"))
	})
}
