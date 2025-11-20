package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestBuildScopeInfoArray(t *testing.T) {
	t.Run("Empty scope", func(t *testing.T) {
		result := buildScopeInfoArray("", nil)
		assert.Empty(t, result)
	})

	t.Run("Single ID token scope", func(t *testing.T) {
		result := buildScopeInfoArray("openid", nil)
		assert.Len(t, result, 1)
		assert.Equal(t, ScopeInfo{
			Scope:            "openid",
			Description:      "Authenticate your user and identify you via a unique ID",
			AlreadyConsented: false,
		}, result[0])
	})

	t.Run("Multiple ID token scopes", func(t *testing.T) {
		result := buildScopeInfoArray("openid profile email", nil)
		assert.Len(t, result, 3)
		assert.Equal(t, ScopeInfo{
			Scope:            "openid",
			Description:      "Authenticate your user and identify you via a unique ID",
			AlreadyConsented: false,
		}, result[0])
		assert.Equal(t, ScopeInfo{
			Scope:            "profile",
			Description:      "Access to claims: name, family_name, given_name, middle_name, nickname, preferred_username, profile, website, gender, birthdate, zoneinfo, locale, and updated_at",
			AlreadyConsented: false,
		}, result[1])
		assert.Equal(t, ScopeInfo{
			Scope:            "email",
			Description:      "Access to claims: email, email_verified",
			AlreadyConsented: false,
		}, result[2])
	})

	t.Run("Offline access scope", func(t *testing.T) {
		result := buildScopeInfoArray("openid offline_access", nil)
		assert.Len(t, result, 2)
		assert.Equal(t, ScopeInfo{
			Scope:            "offline_access",
			Description:      "Access to an offline refresh token, allowing the client to obtain a new access token without requiring your immediate interaction",
			AlreadyConsented: false,
		}, result[1])
	})

	t.Run("Custom scope", func(t *testing.T) {
		result := buildScopeInfoArray("openid custom:read", nil)
		assert.Len(t, result, 2)
		assert.Equal(t, ScopeInfo{
			Scope:            "custom:read",
			Description:      "Permission read on resource custom",
			AlreadyConsented: false,
		}, result[1])
	})

	t.Run("With existing consent", func(t *testing.T) {
		consent := &models.UserConsent{
			Scope: "openid profile",
		}
		result := buildScopeInfoArray("openid profile email", consent)
		assert.Len(t, result, 3)
		assert.True(t, result[0].AlreadyConsented)
		assert.True(t, result[1].AlreadyConsented)
		assert.False(t, result[2].AlreadyConsented)
	})

	t.Run("Mixed scopes with consent", func(t *testing.T) {
		consent := &models.UserConsent{
			Scope: "openid custom:read",
		}
		result := buildScopeInfoArray("openid profile custom:read custom:write", consent)
		assert.Len(t, result, 4)
		assert.True(t, result[0].AlreadyConsented)
		assert.False(t, result[1].AlreadyConsented)
		assert.True(t, result[2].AlreadyConsented)
		assert.False(t, result[3].AlreadyConsented)
	})
}

func TestHandleConsentGet(t *testing.T) {
	t.Run("Error when getting AuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleConsentGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/consent", nil)
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

		handler := HandleConsentGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not requires_consent"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleConsentGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresConsent,
			UserId:    1,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		database.On("GetUserById", mock.Anything, int64(1)).Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Client not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleConsentGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresConsent,
			UserId:    1,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		user := &models.User{Id: 1}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "client not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Successful consent page rendering", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleConsentGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresConsent,
			UserId:    1,
			ClientId:  "test-client",
			Scope:     "openid profile email",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		user := &models.User{Id: 1}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			Description:      "Test Client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(nil, nil)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/consent.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			scopes, ok := data["scopes"].([]ScopeInfo)
			return ok && len(scopes) == 3 &&
				data["clientIdentifier"] == "test-client" &&
				data["clientDescription"] == "Test Client"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Fully consented scopes, redirect to issue", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleConsentGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresConsent,
			UserId:    1,
			ClientId:  "test-client",
			Scope:     "openid profile",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		user := &models.User{Id: 1}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			Description:      "Test Client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		consent := &models.UserConsent{
			UserId:   1,
			ClientId: 1,
			Scope:    "openid profile",
		}
		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(consent, nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Partial consent, render consent page", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleConsentGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresConsent,
			UserId:    1,
			ClientId:  "test-client",
			Scope:     "openid profile email",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		user := &models.User{Id: 1}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			Description:      "Test Client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		consent := &models.UserConsent{
			UserId:   1,
			ClientId: 1,
			Scope:    "openid profile",
		}
		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(consent, nil)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/consent.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			scopes, ok := data["scopes"].([]ScopeInfo)
			return ok && len(scopes) == 3 &&
				data["clientIdentifier"] == "test-client" &&
				data["clientDescription"] == "Test Client" &&
				scopes[0].AlreadyConsented && scopes[1].AlreadyConsented && !scopes[2].AlreadyConsented
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})
}

func TestHandleConsentPost(t *testing.T) {
	t.Run("Error when getting AuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/consent", nil)
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
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not requires_consent"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("User cancels consent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		form := url.Values{}
		form.Add("btnCancel", "cancel")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			ResponseMode: "query",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "https://example.com/callback?error=access_denied")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("User provides consent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		form := url.Values{}
		form.Add("btnSubmit", "submit")
		form.Add("consent0", "openid")
		form.Add("consent1", "profile")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresConsent,
			UserId:    1,
			ClientId:  "test-client",
			Scope:     "openid profile email",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		user := &models.User{Id: 1}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(nil, nil)

		database.On("CreateUserConsent", mock.Anything, mock.MatchedBy(func(consent *models.UserConsent) bool {
			return consent.UserId == 1 && consent.ClientId == 1 && consent.Scope == "openid profile"
		})).Return(nil)

		auditLogger.On("Log", constants.AuditSavedConsent, mock.Anything).Return()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode && ac.ConsentedScope == "openid profile"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Partial consent given", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		form := url.Values{}
		form.Add("btnSubmit", "submit")
		form.Add("consent0", "openid")
		form.Add("consent1", "profile")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresConsent,
			UserId:    1,
			ClientId:  "test-client",
			Scope:     "openid profile email",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		user := &models.User{Id: 1}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		existingConsent := &models.UserConsent{
			Id:       1,
			UserId:   1,
			ClientId: 1,
			Scope:    "openid",
		}
		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(existingConsent, nil)

		database.On("UpdateUserConsent", mock.Anything, mock.MatchedBy(func(consent *models.UserConsent) bool {
			return consent.UserId == 1 && consent.ClientId == 1 && consent.Scope == "openid profile"
		})).Return(nil)

		auditLogger.On("Log", constants.AuditSavedConsent, mock.Anything).Return()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode && ac.ConsentedScope == "openid profile"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("No consent given", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		form := url.Values{}
		form.Add("btnSubmit", "submit")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			ResponseMode: "query",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "https://example.com/callback?error=access_denied")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})
}
