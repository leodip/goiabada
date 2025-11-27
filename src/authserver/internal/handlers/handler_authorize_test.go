package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/validators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_user "github.com/leodip/goiabada/core/user/mocks"
	mocks_validators "github.com/leodip/goiabada/core/validators/mocks"
)

func TestHandleAuthorizeGet(t *testing.T) {
	t.Run("Valid request with existing session", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid", nil)
		assert.NoError(t, err)

		// Add settings to context
		settings := &models.Settings{PKCERequired: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial &&
				ac.ClientId == "test-client" &&
				ac.RedirectURI == "https://example.com" &&
				ac.ResponseType == "code" &&
				ac.Scope == "openid"
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)

		// Client is now fetched before ValidateRequest to determine PKCE requirement
		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)

		userSession := &models.UserSession{
			Id:     1,
			UserId: 123,
			User: models.User{
				Id:      123,
				Enabled: true,
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.AnythingOfType("string")).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateLevel1ExistingSession &&
				ac.UserId == 123 &&
				ac.AcrLevel == userSession.AcrLevel &&
				ac.AuthMethods == userSession.AuthMethods
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1completed", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Valid request without existing session", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid", nil)
		assert.NoError(t, err)

		// Add settings to context
		settings := &models.Settings{PKCERequired: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial &&
				ac.ClientId == "test-client" &&
				ac.RedirectURI == "https://example.com" &&
				ac.ResponseType == "code" &&
				ac.Scope == "openid"
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)

		// Client is now fetched before ValidateRequest to determine PKCE requirement
		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.AnythingOfType("string")).Return(nil, nil)

		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)

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
		authorizeValidator.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Invalid client and redirect URI", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req, err := http.NewRequest("GET", "/authorize?client_id=invalid-client&redirect_uri=https://example.com&response_type=code&scope=openid", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial &&
				ac.ClientId == "invalid-client" &&
				ac.RedirectURI == "https://example.com" &&
				ac.ResponseType == "code" &&
				ac.Scope == "openid"
		})).Return(nil)

		validationError := customerrors.NewErrorDetail("", "Invalid client or redirect URI")
		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(validationError)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["title"] == "Unable to authorize" && data["error"] == validationError.GetDescription()
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("Invalid request", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=invalid&scope=openid", nil)
		assert.NoError(t, err)

		// Add settings to context
		settings := &models.Settings{PKCERequired: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial &&
				ac.ClientId == "test-client" &&
				ac.RedirectURI == "https://example.com" &&
				ac.ResponseType == "invalid" &&
				ac.Scope == "openid"
		})).Return(nil)

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)

		// Client is now fetched before ValidateRequest to determine PKCE requirement
		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		validationError := customerrors.NewErrorDetail("", "Invalid response type")
		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(validationError)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "https://example.com?error=")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("Invalid scopes", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=invalid", nil)
		assert.NoError(t, err)

		// Add settings to context
		settings := &models.Settings{PKCERequired: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial &&
				ac.ClientId == "test-client" &&
				ac.RedirectURI == "https://example.com" &&
				ac.ResponseType == "code" &&
				ac.Scope == "invalid"
		})).Return(nil)

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)

		// Client is now fetched before ValidateRequest to determine PKCE requirement
		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		validationError := customerrors.NewErrorDetail("", "Invalid scope")
		authorizeValidator.On("ValidateScopes", "invalid").Return(validationError)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "https://example.com?error=")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("Disabled user account", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid", nil)
		assert.NoError(t, err)

		// Add settings to context
		settings := &models.Settings{PKCERequired: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial &&
				ac.ClientId == "test-client" &&
				ac.RedirectURI == "https://example.com" &&
				ac.ResponseType == "code" &&
				ac.Scope == "openid"
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)

		// Client is now fetched before ValidateRequest to determine PKCE requirement
		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)

		userSession := &models.UserSession{
			Id:     1,
			UserId: 123,
			User: models.User{
				Id:      123,
				Enabled: false,
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.AnythingOfType("string")).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123)
		})).Return()

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "https://example.com?error=access_denied")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Missing auth context", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(customerrors.ErrNoAuthContext)

		// Expect the InternalServerError call
		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == customerrors.ErrNoAuthContext
		})).Once()

		handler.ServeHTTP(rr, req)
		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Valid request with AcrLevel2Optional", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid", nil)
		assert.NoError(t, err)

		// Add settings to context
		settings := &models.Settings{PKCERequired: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial &&
				ac.ClientId == "test-client" &&
				ac.RedirectURI == "https://example.com" &&
				ac.ResponseType == "code" &&
				ac.Scope == "openid"
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)

		// Client is now fetched before ValidateRequest to determine PKCE requirement
		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel2Optional,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)

		userSession := &models.UserSession{
			Id:          1,
			UserId:      123,
			AcrLevel:    enums.AcrLevel1.String(), // Set this to the appropriate level
			AuthMethods: "pwd",                    // Set this to the appropriate method(s)
			User: models.User{
				Id:      123,
				Enabled: true,
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.AnythingOfType("string")).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateLevel1ExistingSession &&
				ac.UserId == 123 &&
				ac.ClientId == "test-client" &&
				ac.RedirectURI == "https://example.com" &&
				ac.ResponseType == "code" &&
				ac.Scope == "openid"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1completed", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})
}

func TestRedirToClientWithError_QueryResponseMode(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	err := redirToClientWithError(w, r, nil, "invalid_request", "Invalid request", "query", "https://example.com/callback", "abc123", "code")

	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://example.com/callback?error=invalid_request&error_description=Invalid+request&state=abc123", w.Header().Get("Location"))
}

func TestRedirToClientWithError_FragmentResponseMode(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	err := redirToClientWithError(w, r, nil, "unauthorized_client", "Unauthorized client", "fragment", "https://example.com/callback", "xyz789", "code")

	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://example.com/callback#error=unauthorized_client&error_description=Unauthorized+client&state=xyz789", w.Header().Get("Location"))
}

func TestRedirToClientWithError_FormPostResponseMode(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	templateFS := &mocks.TestFS{
		FileContents: map[string]string{
			"form_post.html": `<form method="post" action="{{.redirectURI}}">
				<input type="hidden" name="error" value="{{.error}}">
				<input type="hidden" name="error_description" value="{{.error_description}}">
				<input type="hidden" name="state" value="{{.state}}">
			</form>`,
		},
	}

	err := redirToClientWithError(w, r, templateFS, "access_denied", "Access denied", "form_post", "https://example.com/callback", "def456", "code")

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `<form method="post" action="https://example.com/callback">`)
	assert.Contains(t, w.Body.String(), `<input type="hidden" name="error" value="access_denied">`)
	assert.Contains(t, w.Body.String(), `<input type="hidden" name="error_description" value="Access denied">`)
	assert.Contains(t, w.Body.String(), `<input type="hidden" name="state" value="def456">`)
}

func TestRedirToClientWithError_DefaultToQueryResponseMode(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	err := redirToClientWithError(w, r, nil, "server_error", "Internal server error", "", "https://example.com/callback", "ghi789", "code")

	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://example.com/callback?error=server_error&error_description=Internal+server+error&state=ghi789", w.Header().Get("Location"))
}

// Implicit flow error response tests

func TestRedirToClientWithError_ImplicitFlow_DefaultsToFragment(t *testing.T) {
	tests := []struct {
		name         string
		responseType string
	}{
		{"token response type", "token"},
		{"id_token response type", "id_token"},
		{"id_token token response type", "id_token token"},
		{"token id_token response type (reversed)", "token id_token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/authorize", nil)

			// No response_mode specified, should default to fragment for implicit flow
			err := redirToClientWithError(w, r, nil, "access_denied", "Access denied", "", "https://example.com/callback", "state123", tt.responseType)

			require.NoError(t, err)
			assert.Equal(t, http.StatusFound, w.Code)
			location := w.Header().Get("Location")
			assert.Contains(t, location, "https://example.com/callback#")
			assert.Contains(t, location, "error=access_denied")
			assert.Contains(t, location, "error_description=Access+denied")
			assert.Contains(t, location, "state=state123")
		})
	}
}

func TestRedirToClientWithError_ImplicitFlow_ExplicitResponseModeRespected(t *testing.T) {
	// Even for implicit flow, explicit response_mode should be respected
	t.Run("fragment response mode explicit", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		err := redirToClientWithError(w, r, nil, "invalid_request", "Invalid request", "fragment", "https://example.com/callback", "state123", "token")

		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Contains(t, w.Header().Get("Location"), "https://example.com/callback#")
	})

	t.Run("form_post response mode for implicit flow", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		templateFS := &mocks.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form method="post" action="{{.redirectURI}}">
					<input type="hidden" name="error" value="{{.error}}">
					<input type="hidden" name="error_description" value="{{.error_description}}">
					<input type="hidden" name="state" value="{{.state}}">
				</form>`,
			},
		}

		err := redirToClientWithError(w, r, templateFS, "access_denied", "Access denied", "form_post", "https://example.com/callback", "state123", "id_token token")

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `<form method="post" action="https://example.com/callback">`)
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="error" value="access_denied">`)
	})
}

func TestRedirToClientWithError_HybridFlow_UsesQuery(t *testing.T) {
	// Hybrid flows (containing "code") should use query by default
	tests := []struct {
		name         string
		responseType string
	}{
		{"code token (hybrid)", "code token"},
		{"code id_token (hybrid)", "code id_token"},
		{"code id_token token (hybrid)", "code id_token token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/authorize", nil)

			// No response_mode specified, should default to query for hybrid flow (contains code)
			err := redirToClientWithError(w, r, nil, "access_denied", "Access denied", "", "https://example.com/callback", "state123", tt.responseType)

			require.NoError(t, err)
			assert.Equal(t, http.StatusFound, w.Code)
			location := w.Header().Get("Location")
			assert.Contains(t, location, "https://example.com/callback?")
			assert.Contains(t, location, "error=access_denied")
		})
	}
}

func TestRedirToClientWithError_NoState(t *testing.T) {
	t.Run("empty state not included", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		err := redirToClientWithError(w, r, nil, "access_denied", "Access denied", "query", "https://example.com/callback", "", "code")

		require.NoError(t, err)
		location := w.Header().Get("Location")
		assert.NotContains(t, location, "state=")
	})

	t.Run("whitespace-only state not included", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		err := redirToClientWithError(w, r, nil, "access_denied", "Access denied", "fragment", "https://example.com/callback", "   ", "token")

		require.NoError(t, err)
		location := w.Header().Get("Location")
		assert.NotContains(t, location, "state=")
	})
}

func TestHandleAuthorizeGet_ImplicitFlow(t *testing.T) {
	t.Run("Valid implicit flow request with token response type", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=token&scope=openid&nonce=test-nonce", nil)
		assert.NoError(t, err)

		// Add settings to context with implicit flow enabled
		settings := &models.Settings{
			PKCERequired:        true,
			ImplicitFlowEnabled: true,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial &&
				ac.ClientId == "test-client" &&
				ac.RedirectURI == "https://example.com" &&
				ac.ResponseType == "token" &&
				ac.Scope == "openid"
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.MatchedBy(func(input *validators.ValidateClientAndRedirectURIInput) bool {
			return input.ResponseType == "token"
		})).Return(nil)

		// Client with implicit flow enabled
		client := &models.Client{
			Id:                   1,
			ClientIdentifier:     "test-client",
			DefaultAcrLevel:      enums.AcrLevel1,
			ImplicitGrantEnabled: nil, // Uses global setting
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.MatchedBy(func(input *validators.ValidateRequestInput) bool {
			return input.ResponseType == "token" && input.ImplicitGrantEnabled == true
		})).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.AnythingOfType("string")).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, (*models.UserSession)(nil), mock.AnythingOfType("*int")).Return(false)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresLevel1
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("Valid implicit flow request with id_token token response type", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=id_token%20token&scope=openid&nonce=test-nonce", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			PKCERequired:        false,
			ImplicitFlowEnabled: true,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial &&
				ac.ResponseType == "id_token token"
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.MatchedBy(func(input *validators.ValidateClientAndRedirectURIInput) bool {
			return input.ResponseType == "id_token token"
		})).Return(nil)

		client := &models.Client{
			Id:                   1,
			ClientIdentifier:     "test-client",
			DefaultAcrLevel:      enums.AcrLevel1,
			ImplicitGrantEnabled: nil,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.MatchedBy(func(input *validators.ValidateRequestInput) bool {
			return input.ResponseType == "id_token token" && input.ImplicitGrantEnabled == true && input.Nonce == "test-nonce"
		})).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.AnythingOfType("string")).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, (*models.UserSession)(nil), mock.AnythingOfType("*int")).Return(false)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresLevel1
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("Implicit flow disabled - validation error redirects with fragment", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=token&scope=openid", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			PKCERequired:        false,
			ImplicitFlowEnabled: false, // Disabled globally
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial && ac.ResponseType == "token"
		})).Return(nil)

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)

		client := &models.Client{
			Id:                   1,
			ClientIdentifier:     "test-client",
			DefaultAcrLevel:      enums.AcrLevel1,
			ImplicitGrantEnabled: nil, // Uses global setting (disabled)
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		// Validator returns error because implicit flow is disabled
		validationError := customerrors.NewErrorDetail("unauthorized_client", "This client is not authorized for the implicit grant flow.")
		authorizeValidator.On("ValidateRequest", mock.MatchedBy(func(input *validators.ValidateRequestInput) bool {
			return input.ResponseType == "token" && input.ImplicitGrantEnabled == false
		})).Return(validationError)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		// For implicit flow response type, error should be in fragment
		assert.Contains(t, location, "https://example.com#")
		assert.Contains(t, location, "error=unauthorized_client")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("Client explicitly enables implicit flow overriding global", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=token&scope=openid&nonce=test-nonce", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			PKCERequired:        false,
			ImplicitFlowEnabled: false, // Disabled globally
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial && ac.ResponseType == "token"
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)

		// Client explicitly enables implicit flow
		implicitEnabled := true
		client := &models.Client{
			Id:                   1,
			ClientIdentifier:     "test-client",
			DefaultAcrLevel:      enums.AcrLevel1,
			ImplicitGrantEnabled: &implicitEnabled, // Client override
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.MatchedBy(func(input *validators.ValidateRequestInput) bool {
			// Client override should take effect
			return input.ResponseType == "token" && input.ImplicitGrantEnabled == true
		})).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.AnythingOfType("string")).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, (*models.UserSession)(nil), mock.AnythingOfType("*int")).Return(false)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresLevel1
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})
}
