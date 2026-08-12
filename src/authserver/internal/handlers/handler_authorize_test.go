package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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
	mocks_oauth "github.com/leodip/goiabada/core/oauth/mocks"
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

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

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
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		// Client is now fetched before ValidateRequest to determine PKCE requirement
		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

		userSession := &models.UserSession{
			Id:     1,
			UserId: 123,
			// Deliberately conflicting and nonzero: the SESSION is at 7 while the user it
			// belongs to is at 9. The AuthContext must inherit 7, because reading the
			// user's current value here would launder an old ceremony into the generation a
			// later credential change established (#106 decision 11(d)).
			AuthStateGeneration: 7,
			User: models.User{
				Id:                  123,
				Enabled:             true,
				AuthStateGeneration: 9,
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.AnythingOfType("string")).Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateLevel1ExistingSession &&
				ac.UserId == 123 &&
				ac.AcrLevel == userSession.AcrLevel &&
				ac.AuthMethods == userSession.AuthMethods &&
				// From the session, not the user. Thin on purpose: the tables live in
				// token_issuer_auth_state_generation_test.go.
				ac.AuthStateGeneration == 7
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

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

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
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		// Client is now fetched before ValidateRequest to determine PKCE requirement
		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

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

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

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

	// This is the only place an auth context is created, so it is the only place a ceremony id
	// can be minted. Every bound form renders it and every bound POST checks it, so a context
	// saved without one would render forms whose every submission is refused (#79).
	//
	// The request is deliberately made to fail validation straight afterwards: what is under test
	// is the id on the FIRST context saved, and stopping there keeps the setup to the two calls
	// that matter.
	t.Run("The saved auth context names a fresh ceremony", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		seen := map[string]bool{}
		for i := 0; i < 2; i++ {
			req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid", nil)
			assert.NoError(t, err)
			rr := httptest.NewRecorder()

			var saved *oauth.AuthContext
			authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
				saved = ac
				return true
			})).Return(nil).Once()

			validationError := customerrors.NewErrorDetail("", "Invalid client or redirect URI")
			authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(validationError).Once()
			httpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html", mock.Anything).Return(nil).Once()

			handler.ServeHTTP(rr, req)

			if assert.NotNil(t, saved) {
				assert.Len(t, saved.CeremonyId, ceremonyIdLength,
					"the ceremony id must be generated at the full length, not left empty")
				// A ceremony id shared between two authorization requests would bind neither:
				// the second request's form would satisfy the first's check.
				assert.False(t, seen[saved.CeremonyId], "each authorization request gets its own ceremony id")
				seen[saved.CeremonyId] = true
			}
		}

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

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

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
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

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

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

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

		// The clear has to reach the browser, so it must happen before the response is
		// committed. rr.Header() is the live map the handler and this stub share, so it shows
		// the sentinel under either ordering; rr.Result() reads the snapshot taken when the
		// status line was written, which is the only unit-tier view that tells them apart.
		const clearedContextCookie = "cleared-auth-context"
		authHelper.On("ClearAuthContext", rr, req).Run(func(args mock.Arguments) {
			args.Get(0).(http.ResponseWriter).Header().Set("Set-Cookie", clearedContextCookie)
		}).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

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
		assert.Equal(t, clearedContextCookie, rr.Result().Header.Get("Set-Cookie"),
			"the auth context must be cleared before the client response is committed")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("Invalid scopes with a failing clear - server_error to the client", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=invalid", nil)
		assert.NoError(t, err)

		settings := &models.Settings{PKCERequired: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(nil)

		// A failed clear writes no cookie, so the browser keeps the auth context whatever the
		// handler does next. The client is still owed its error response, and server_error is
		// the code RFC 6749 4.1.2.1 mints for a fault that cannot travel as a 500.
		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "invalid").Return(customerrors.NewErrorDetail("", "Invalid scope"))

		handler.ServeHTTP(rr, req)

		// httpHelper has no InternalServerError expectation, so the mock fails the test if the
		// handler answers with a bare 500 instead of redirecting the client.
		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Result().Header.Get("Location")
		assert.Contains(t, location, "https://example.com?error=server_error")
		assert.Contains(t, location, "error_description=Internal+server+error")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("Invalid scopes with a failing clear and an unusable form_post template - last-resort 500", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		// Deliberately malformed, an unclosed action, so template.ParseFS fails and
		// redirToClientWithError returns "unable to parse template" instead of committing.
		// form_post is the only response mode whose arm can fail after the redirect URI has
		// been validated, so it is how this branch is reached at all.
		templateFS := &mocks.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, templateFS, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&response_mode=form_post&scope=invalid", nil)
		assert.NoError(t, err)

		settings := &models.Settings{PKCERequired: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(nil)
		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		// The clear failed and the server_error response the client is owed cannot be built
		// either, so there is nowhere left to send it and the 500 is the last resort. Without
		// this expectation the handler would answer nothing at all.
		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "invalid").Return(customerrors.NewErrorDetail("", "Invalid scope"))

		handler.ServeHTTP(rr, req)

		// Nothing reached the client: the form_post arm fails before it writes, and the 500 is
		// the mock's, so no redirect is committed.
		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("Invalid scopes with an unusable form_post template - 500 when the refusal itself cannot be sent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		templateFS := &mocks.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, templateFS, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&response_mode=form_post&scope=invalid", nil)
		assert.NoError(t, err)

		settings := &models.Settings{PKCERequired: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(nil)

		// The other half of the same family: here the clear succeeds and it is the ordinary
		// refusal that cannot be committed. This is the closure's second and pre-existing 500,
		// pinned separately so a future edit cannot delete either copy unnoticed.
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "invalid").Return(customerrors.NewErrorDetail("", "Invalid scope"))

		handler.ServeHTTP(rr, req)

		assert.Empty(t, rr.Result().Header.Get("Location"))

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

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

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
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		// Client is now fetched before ValidateRequest to determine PKCE requirement
		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

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

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

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

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

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
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		// Client is now fetched before ValidateRequest to determine PKCE requirement
		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel2Optional,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

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

	t.Run("POST request with form body succeeds", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		form := url.Values{}
		form.Set("client_id", "test-client")
		form.Set("redirect_uri", "https://example.com")
		form.Set("response_type", "code")
		form.Set("scope", "openid")

		req, err := http.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

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

	t.Run("POST validation error redirects with form-body params", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		form := url.Values{}
		form.Set("client_id", "test-client")
		form.Set("redirect_uri", "https://example.com")
		form.Set("response_type", "invalid")
		form.Set("scope", "openid")
		form.Set("state", "abc123")

		req, err := http.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
				ac.State == "abc123" &&
				ac.Scope == "openid"
		})).Return(nil)

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		validationError := customerrors.NewErrorDetail("invalid_request", "Invalid response type")
		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(validationError)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		// Confirms redirect_uri and state were re-read from the POST body in the
		// error closure (not from an empty query string).
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com?error=invalid_request")
		assert.Contains(t, location, "state=abc123")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("Captures ui_locales from query string into AuthContext", func(t *testing.T) {
		// Canary for the regression this work is meant to prevent: an OIDC
		// ui_locales hint passed on the authorize request must land on the
		// AuthContext that's persisted to the session, so subsequent steps
		// of the multi-step auth flow (/auth/pwd, /auth/otp, /auth/consent)
		// see the same locale preference.
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		req, err := http.NewRequest("GET",
			"/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&ui_locales=pt-BR%20es",
			nil)
		assert.NoError(t, err)

		settings := &models.Settings{PKCERequired: true}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		hasUILocales := func(ac *oauth.AuthContext) bool {
			return len(ac.UILocales) == 2 && ac.UILocales[0] == "pt-BR" && ac.UILocales[1] == "es"
		}

		// First save: AuthContext just constructed; UILocales must be captured here.
		// The request pointer changes after RefineLocalizerWithUILocales, so we use
		// mock.Anything for the request slot.
		authHelper.On("SaveAuthContext", rr, mock.Anything, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial && hasUILocales(ac)
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.Anything).Return(nil)

		client := &models.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: enums.AcrLevel1}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.Anything).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

		// Second save: AuthState advances after id_token_hint validation —
		// UILocales must still be present (preserved across saves).
		authHelper.On("SaveAuthContext", rr, mock.Anything, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return hasUILocales(ac)
		})).Return(nil)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)
		userSessionManager.On("HasValidUserSession", mock.Anything, (*models.UserSession)(nil), mock.Anything).Return(false)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1", rr.Header().Get("Location"))

		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		database.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
	})

	t.Run("Captures ui_locales from form body (POST)", func(t *testing.T) {
		// Same as the query-string canary, but ui_locales arrives in the POST
		// body. r.FormValue covers both, so the same code path runs — but this
		// pins behaviour that's easy to break if anything in the request
		// pre-processing chain consumes the body.
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		form := url.Values{}
		form.Set("client_id", "test-client")
		form.Set("redirect_uri", "https://example.com")
		form.Set("response_type", "code")
		form.Set("scope", "openid")
		form.Set("ui_locales", "pt-BR es")

		req, err := http.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		settings := &models.Settings{PKCERequired: true}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		hasUILocales := func(ac *oauth.AuthContext) bool {
			return len(ac.UILocales) == 2 && ac.UILocales[0] == "pt-BR" && ac.UILocales[1] == "es"
		}

		authHelper.On("SaveAuthContext", rr, mock.Anything, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial && hasUILocales(ac)
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.Anything).Return(nil)

		client := &models.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: enums.AcrLevel1}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.Anything).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

		authHelper.On("SaveAuthContext", rr, mock.Anything, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return hasUILocales(ac)
		})).Return(nil)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, (*models.UserSession)(nil)).Return(nil)
		userSessionManager.On("HasValidUserSession", mock.Anything, (*models.UserSession)(nil), mock.Anything).Return(false)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)

		authHelper.AssertExpectations(t)
	})
}

// stubClientProvenanceLookup answers the client load that a handler performs before dispatching an
// error redirect, so that the redirect knows whose redirect URI it is about to use. It answers with
// an administrator-created client, the case in which weighing provenance changes nothing, so a
// refusal case still asserts the redirect it was written to assert (#108).
func stubClientProvenanceLookup(database *mocks_data.Database) {
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything).
		Return(&models.Client{ClientIdentifier: "test-client"}, nil)
}

// testRedirectError builds the input the cases below vary, naming an administrator-created client.
// Every one of them is about the shape of the response an error takes, and the error redirect now
// also carries the client it is answering so that its provenance can be weighed; an
// administrator-created client is the case in which that weighing changes nothing, which is what
// keeps these cases about the response (#108).
//
// It is also why every case below passes nil for httpHelper: the renderer is reached only when the
// redirect is withheld, so a nil there says this input never withholds one. Seam 6 owns the case
// that does, at the integration tier, where a rendered page can actually be read.
func testRedirectError(code string, description string, responseMode string, redirectURI string,
	state string, responseType string) redirectErrorInput {

	return redirectErrorInput{
		client:       &models.Client{ClientIdentifier: "test-client"},
		code:         code,
		description:  description,
		responseMode: responseMode,
		redirectURI:  redirectURI,
		state:        state,
		responseType: responseType,
	}
}

// redirectErrorFromAuthContext is what fourteen of the sixteen error redirects are built by, and
// the client it carries is the whole reason it exists: the redirect weighs where the redirect URI
// came from before using it. Nothing downstream reads that client yet, so a version of this
// function that quietly dropped it would pass every other test in this package. It is pure, so a
// table here is the cheapest place to say it must not (#108).
func TestRedirectErrorFromAuthContext(t *testing.T) {
	authContext := &oauth.AuthContext{
		ResponseMode: "form_post",
		RedirectURI:  "https://example.com/callback",
		State:        "test-state",
		ResponseType: "id_token token",
	}

	t.Run("carries the client it was handed", func(t *testing.T) {
		client := &models.Client{Id: 7, ClientIdentifier: "test-client"}

		input := redirectErrorFromAuthContext(authContext, client, "access_denied", "Access denied")

		assert.Same(t, client, input.client)
	})

	t.Run("carries nil when provenance could not be resolved", func(t *testing.T) {
		// The handlers that cannot resolve a client hand nil rather than skipping the redirect,
		// and nil has to survive the trip as nil: it means "unknown", which is the untrusted case.
		input := redirectErrorFromAuthContext(authContext, nil, "access_denied", "Access denied")

		assert.Nil(t, input.client)
	})

	t.Run("takes the response parameters from the ceremony and the error from its arguments", func(t *testing.T) {
		input := redirectErrorFromAuthContext(authContext, nil, "server_error", "Internal server error")

		assert.Equal(t, "server_error", input.code)
		assert.Equal(t, "Internal server error", input.description)
		assert.Equal(t, "form_post", input.responseMode)
		assert.Equal(t, "https://example.com/callback", input.redirectURI)
		assert.Equal(t, "test-state", input.state)
		assert.Equal(t, "id_token token", input.responseType)
	})
}

func TestRedirToClientWithError_QueryResponseMode(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	err := redirToClientWithError(w, r, nil, nil, testRedirectError("invalid_request", "Invalid request", "query", "https://example.com/callback", "abc123", "code"))

	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://example.com/callback?error=invalid_request&error_description=Invalid+request&state=abc123", w.Header().Get("Location"))
}

func TestRedirToClientWithError_FragmentResponseMode(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	err := redirToClientWithError(w, r, nil, nil, testRedirectError("unauthorized_client", "Unauthorized client", "fragment", "https://example.com/callback", "xyz789", "code"))

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

	err := redirToClientWithError(w, r, nil, templateFS, testRedirectError("access_denied", "Access denied", "form_post", "https://example.com/callback", "def456", "code"))

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `<form method="post" action="https://example.com/callback">`)
	assert.Contains(t, w.Body.String(), `<input type="hidden" name="error" value="access_denied">`)
	assert.Contains(t, w.Body.String(), `<input type="hidden" name="error_description" value="Access denied">`)
	assert.Contains(t, w.Body.String(), `<input type="hidden" name="state" value="def456">`)
}

// The form_post arm is the only one that can fail after the redirect URI has been validated, and it
// can fail in two different places. A template that will not parse fails before anything is written,
// which the per-site last-resort cases cover. A template that parses and then fails part way through
// execution is the other member, and it is reachable in production: server.New serves templates from
// os.DirFS(GOIABADA_AUTHSERVER_TEMPLATEDIR) when that variable is set, so the file is operator
// supplied. Rendering straight to the ResponseWriter would commit a partial 200 the instant the
// template emitted its first byte, and the caller's last-resort InternalServerError could then no
// longer change the status the client sees. The render therefore goes to a buffer and reaches w only
// once Execute has returned successfully (#141).
func TestRedirToClientWithError_FormPostExecutionFailureLeavesResponseUncommitted(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	// Parses cleanly. "missing" is absent from the map, so index yields an untyped nil, and
	// indexing that fails at execution time, after the <form> prefix has been emitted.
	templateFS := &mocks.TestFS{
		FileContents: map[string]string{
			"form_post.html": `<form>{{index . "missing" 0}}</form>`,
		},
	}

	err := redirToClientWithError(w, r, nil, templateFS, testRedirectError("server_error", "Internal server error",
		"form_post", "https://example.com/callback", "def456", "code"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to execute template")

	// Nothing may have reached the client yet, or the caller's last resort is not a last resort.
	assert.Empty(t, w.Body.String(), "a failed render must not put a partial body on the wire")

	w.WriteHeader(http.StatusInternalServerError)
	assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode,
		"the caller must still be able to answer 500 after the form_post render failed")
}

// The third and last way the form_post arm can fail: the render succeeds and the connection does
// not. Buffering cannot help here and is not meant to, since a client that cannot receive the page
// cannot receive a 500 either. What it must still do is report the failure rather than swallow it,
// so the caller logs something instead of treating a dead connection as a delivered refusal (#141).
func TestRedirToClientWithError_FormPostWriteFailureIsReported(t *testing.T) {
	w := &failingResponseWriter{}
	r := httptest.NewRequest("GET", "/authorize", nil)

	templateFS := &mocks.TestFS{
		FileContents: map[string]string{
			"form_post.html": `<form method="post" action="{{.redirectURI}}"></form>`,
		},
	}

	err := redirToClientWithError(w, r, nil, templateFS, testRedirectError("server_error", "Internal server error",
		"form_post", "https://example.com/callback", "def456", "code"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to write the form_post response")
}

func TestRedirToClientWithError_DefaultToQueryResponseMode(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	err := redirToClientWithError(w, r, nil, nil, testRedirectError("server_error", "Internal server error", "", "https://example.com/callback", "ghi789", "code"))

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
			err := redirToClientWithError(w, r, nil, nil, testRedirectError("access_denied", "Access denied", "", "https://example.com/callback", "state123", tt.responseType))

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

		err := redirToClientWithError(w, r, nil, nil, testRedirectError("invalid_request", "Invalid request", "fragment", "https://example.com/callback", "state123", "token"))

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

		err := redirToClientWithError(w, r, nil, templateFS, testRedirectError("access_denied", "Access denied", "form_post", "https://example.com/callback", "state123", "id_token token"))

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
			err := redirToClientWithError(w, r, nil, nil, testRedirectError("access_denied", "Access denied", "", "https://example.com/callback", "state123", tt.responseType))

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

		err := redirToClientWithError(w, r, nil, nil, testRedirectError("access_denied", "Access denied", "query", "https://example.com/callback", "", "code"))

		require.NoError(t, err)
		location := w.Header().Get("Location")
		assert.NotContains(t, location, "state=")
	})

	t.Run("whitespace-only state not included", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		err := redirToClientWithError(w, r, nil, nil, testRedirectError("access_denied", "Access denied", "fragment", "https://example.com/callback", "   ", "token"))

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

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

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
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

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
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

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

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

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
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

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
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

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

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

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
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

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

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

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
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

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
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

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

func TestHandleAuthorizeGet_IdTokenHint(t *testing.T) {
	t.Run("Invalid id_token_hint bad signature - invalid_request", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&id_token_hint=bad-jwt-token", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			PKCERequired: true,
			Issuer:       "https://test-issuer.com",
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial && ac.ClientId == "test-client"
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

		tokenParser.On("DecodeAndValidateTokenString", "bad-jwt-token", mock.Anything, false).Return(nil, errors.New("signature verification failed"))

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com?error=invalid_request")
		assert.Contains(t, location, "error_description=")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
	})

	t.Run("id_token_hint with wrong issuer - invalid_request", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&id_token_hint=valid-jwt-wrong-issuer", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			PKCERequired: true,
			Issuer:       "https://correct-issuer.com",
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial && ac.ClientId == "test-client"
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

		wrongIssuerToken := &oauth.JwtToken{
			TokenBase64: "valid-jwt-wrong-issuer",
			Claims: jwt.MapClaims{
				"iss": "https://wrong-issuer.com",
				"sub": "user-123",
			},
		}
		tokenParser.On("DecodeAndValidateTokenString", "valid-jwt-wrong-issuer", mock.Anything, false).Return(wrongIssuerToken, nil)

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com?error=invalid_request")
		assert.Contains(t, location, "error_description=")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
	})

	t.Run("id_token_hint missing sub claim - invalid_request", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&id_token_hint=valid-jwt-no-sub", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			PKCERequired: true,
			Issuer:       "https://test-issuer.com",
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial && ac.ClientId == "test-client"
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

		noSubToken := &oauth.JwtToken{
			TokenBase64: "valid-jwt-no-sub",
			Claims: jwt.MapClaims{
				"iss": "https://test-issuer.com",
			},
		}
		tokenParser.On("DecodeAndValidateTokenString", "valid-jwt-no-sub", mock.Anything, false).Return(noSubToken, nil)

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com?error=invalid_request")
		assert.Contains(t, location, "error_description=")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
	})

	t.Run("Expired id_token_hint matching user - succeeds", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		userSubject := uuid.New()
		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&id_token_hint=expired-jwt-token", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			PKCERequired: true,
			Issuer:       "https://test-issuer.com",
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "session-123")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial && ac.ClientId == "test-client"
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

		expiredToken := &oauth.JwtToken{
			TokenBase64: "expired-jwt-token",
			Claims: jwt.MapClaims{
				"iss": "https://test-issuer.com",
				"sub": userSubject.String(),
			},
		}
		tokenParser.On("DecodeAndValidateTokenString", "expired-jwt-token", mock.Anything, false).Return(expiredToken, nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.IdTokenHintSub == userSubject.String()
		})).Return(nil)

		userSession := &models.UserSession{
			Id:          1,
			UserId:      123,
			AcrLevel:    enums.AcrLevel1.String(),
			AuthMethods: "pwd",
			User: models.User{
				Id:      123,
				Enabled: true,
				Subject: userSubject,
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "session-123").Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateLevel1ExistingSession && ac.UserId == 123
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1completed", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
	})

	t.Run("SSO with id_token_hint matching session user - proceeds normally", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		userSubject := uuid.New()
		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&id_token_hint=valid-jwt-token", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			PKCERequired: true,
			Issuer:       "https://test-issuer.com",
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "session-123")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial && ac.ClientId == "test-client"
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

		validToken := &oauth.JwtToken{
			TokenBase64: "valid-jwt-token",
			Claims: jwt.MapClaims{
				"iss": "https://test-issuer.com",
				"sub": userSubject.String(),
			},
		}
		tokenParser.On("DecodeAndValidateTokenString", "valid-jwt-token", mock.Anything, false).Return(validToken, nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.IdTokenHintSub == userSubject.String()
		})).Return(nil)

		userSession := &models.UserSession{
			Id:          1,
			UserId:      123,
			AcrLevel:    enums.AcrLevel1.String(),
			AuthMethods: "pwd",
			User: models.User{
				Id:      123,
				Enabled: true,
				Subject: userSubject,
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "session-123").Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateLevel1ExistingSession && ac.UserId == 123
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1completed", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
	})

	t.Run("SSO with id_token_hint different user - forces re-auth", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		hintSubject := uuid.New()
		sessionSubject := uuid.New()

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&id_token_hint=different-user-jwt", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			PKCERequired: true,
			Issuer:       "https://test-issuer.com",
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "session-456")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial && ac.ClientId == "test-client"
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "").Return("", nil)

		differentUserToken := &oauth.JwtToken{
			TokenBase64: "different-user-jwt",
			Claims: jwt.MapClaims{
				"iss": "https://test-issuer.com",
				"sub": hintSubject.String(),
			},
		}
		tokenParser.On("DecodeAndValidateTokenString", "different-user-jwt", mock.Anything, false).Return(differentUserToken, nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.IdTokenHintSub == hintSubject.String()
		})).Return(nil)

		userSession := &models.UserSession{
			Id:          1,
			UserId:      456,
			AcrLevel:    enums.AcrLevel1.String(),
			AuthMethods: "pwd",
			User: models.User{
				Id:      456,
				Enabled: true,
				Subject: sessionSubject,
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "session-456").Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

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
		tokenParser.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
	})

	t.Run("prompt=none with valid id_token_hint matching session user - succeeds", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		userSubject := uuid.New()
		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&prompt=none&id_token_hint=valid-jwt-token", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			PKCERequired: true,
			Issuer:       "https://test-issuer.com",
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "session-789")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial && ac.ClientId == "test-client"
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "none").Return("none", nil)

		validToken := &oauth.JwtToken{
			TokenBase64: "valid-jwt-token",
			Claims: jwt.MapClaims{
				"iss": "https://test-issuer.com",
				"sub": userSubject.String(),
			},
		}
		tokenParser.On("DecodeAndValidateTokenString", "valid-jwt-token", mock.Anything, false).Return(validToken, nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.IdTokenHintSub == userSubject.String() && ac.Prompt == "none"
		})).Return(nil)
		// The silent-issue path sets the AuthContext again just before code issuance; this
		// is the assertion that it inherits the session's generation and not the user's.
		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.UserId == 789 && ac.AuthStateGeneration == 7
		})).Return(nil)

		userSession := &models.UserSession{
			Id:          1,
			UserId:      789,
			AcrLevel:    enums.AcrLevel1.String(),
			AuthMethods: "pwd",
			// Session at 7, user at 9. The prompt=none path is a SEPARATE session-reuse
			// site from the interactive one, and it must inherit from the session too, or a
			// silent re-issue would launder an old ceremony forward (#106 decision 11(d)).
			AuthStateGeneration: 7,
			User: models.User{
				Id:                  789,
				Enabled:             true,
				Subject:             userSubject,
				AuthStateGeneration: 9,
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "session-789").Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

		permissionChecker.On("FilterOutScopesWhereUserIsNotAuthorized", "openid", mock.MatchedBy(func(u *models.User) bool {
			return u.Id == 789
		})).Return("openid", nil)

		userSessionManager.On("BumpUserSession", req, "session-789", int64(1), "pwd", enums.AcrLevel1.String()).Return(userSession, nil)

		auditLogger.On("Log", constants.AuditBumpedUserSession, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(789) && details["clientId"] == int64(1)
		})).Return()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), config.GetAuthServer().BaseURL+"/auth/issue")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		permissionChecker.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("prompt=none with valid id_token_hint different user - login_required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		hintSubject := uuid.New()
		sessionSubject := uuid.New()

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&prompt=none&id_token_hint=different-user-jwt", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			PKCERequired: true,
			Issuer:       "https://test-issuer.com",
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "session-999")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateInitial && ac.ClientId == "test-client"
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "none").Return("none", nil)

		differentUserToken := &oauth.JwtToken{
			TokenBase64: "different-user-jwt",
			Claims: jwt.MapClaims{
				"iss": "https://test-issuer.com",
				"sub": hintSubject.String(),
			},
		}
		tokenParser.On("DecodeAndValidateTokenString", "different-user-jwt", mock.Anything, false).Return(differentUserToken, nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.IdTokenHintSub == hintSubject.String() && ac.Prompt == "none"
		})).Return(nil)

		userSession := &models.UserSession{
			Id:          1,
			UserId:      999,
			AcrLevel:    enums.AcrLevel1.String(),
			AuthMethods: "pwd",
			User: models.User{
				Id:      999,
				Enabled: true,
				Subject: sessionSubject,
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "session-999").Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

		// Same sentinel as the "Invalid scopes" case, for handlePromptNone's own refusal
		// closure: rr.Result() reads the header snapshot taken at commit time, so the sentinel
		// only appears there if the clear ran before the client response was committed.
		const clearedContextCookie = "cleared-auth-context"
		authHelper.On("ClearAuthContext", rr, req).Run(func(args mock.Arguments) {
			args.Get(0).(http.ResponseWriter).Header().Set("Set-Cookie", clearedContextCookie)
		}).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com?error=login_required")
		assert.Contains(t, location, "error_description=")
		assert.Equal(t, clearedContextCookie, rr.Result().Header.Get("Set-Cookie"),
			"the auth context must be cleared before the client response is committed")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
	})

	t.Run("prompt=none with a failing clear - server_error to the client", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		hintSubject := uuid.New()
		sessionSubject := uuid.New()

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&prompt=none&id_token_hint=different-user-jwt", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			PKCERequired: true,
			Issuer:       "https://test-issuer.com",
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "session-999")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "none").Return("none", nil)

		differentUserToken := &oauth.JwtToken{
			TokenBase64: "different-user-jwt",
			Claims: jwt.MapClaims{
				"iss": "https://test-issuer.com",
				"sub": hintSubject.String(),
			},
		}
		tokenParser.On("DecodeAndValidateTokenString", "different-user-jwt", mock.Anything, false).Return(differentUserToken, nil)

		userSession := &models.UserSession{
			Id:          1,
			UserId:      999,
			AcrLevel:    enums.AcrLevel1.String(),
			AuthMethods: "pwd",
			User: models.User{
				Id:      999,
				Enabled: true,
				Subject: sessionSubject,
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "session-999").Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

		// The refusal this path would otherwise send is login_required. With the clear failing,
		// the client gets server_error instead: a silent-renewal iframe reads that as "retry
		// later" rather than "start an interactive login", which is the accurate instruction
		// when the server has a fault the client will never learn about.
		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		handler.ServeHTTP(rr, req)

		// httpHelper has no InternalServerError expectation, so the mock fails the test if the
		// handler answers with a bare 500 instead of redirecting the client.
		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Result().Header.Get("Location")
		assert.Contains(t, location, "https://example.com?error=server_error")
		assert.Contains(t, location, "error_description=Internal+server+error")
		assert.NotContains(t, location, "login_required")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
	})

	t.Run("prompt=none with a failing clear and an unusable form_post template - last-resort 500", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		// handlePromptNone's closure carries its own copy of the last-resort 500, so removing
		// site 1's copy leaves this one and vice versa. Each is pinned at its own site.
		templateFS := &mocks.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, templateFS, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		hintSubject := uuid.New()
		sessionSubject := uuid.New()

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&response_mode=form_post&scope=openid&prompt=none&id_token_hint=different-user-jwt", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			PKCERequired: true,
			Issuer:       "https://test-issuer.com",
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "session-999")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "none").Return("none", nil)

		differentUserToken := &oauth.JwtToken{
			TokenBase64: "different-user-jwt",
			Claims: jwt.MapClaims{
				"iss": "https://test-issuer.com",
				"sub": hintSubject.String(),
			},
		}
		tokenParser.On("DecodeAndValidateTokenString", "different-user-jwt", mock.Anything, false).Return(differentUserToken, nil)

		userSession := &models.UserSession{
			Id:          1,
			UserId:      999,
			AcrLevel:    enums.AcrLevel1.String(),
			AuthMethods: "pwd",
			User: models.User{
				Id:      999,
				Enabled: true,
				Subject: sessionSubject,
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "session-999").Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		handler.ServeHTTP(rr, req)

		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
	})

	t.Run("prompt=none with an unusable form_post template - 500 when the refusal itself cannot be sent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		templateFS := &mocks.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, templateFS, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		hintSubject := uuid.New()
		sessionSubject := uuid.New()

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&response_mode=form_post&scope=openid&prompt=none&id_token_hint=different-user-jwt", nil)
		assert.NoError(t, err)

		settings := &models.Settings{
			PKCERequired: true,
			Issuer:       "https://test-issuer.com",
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "session-999")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
		authorizeValidator.On("ValidateScopes", "openid").Return(nil)
		authorizeValidator.On("ValidatePrompt", "none").Return("none", nil)

		differentUserToken := &oauth.JwtToken{
			TokenBase64: "different-user-jwt",
			Claims: jwt.MapClaims{
				"iss": "https://test-issuer.com",
				"sub": hintSubject.String(),
			},
		}
		tokenParser.On("DecodeAndValidateTokenString", "different-user-jwt", mock.Anything, false).Return(differentUserToken, nil)

		userSession := &models.UserSession{
			Id:          1,
			UserId:      999,
			AcrLevel:    enums.AcrLevel1.String(),
			AuthMethods: "pwd",
			User: models.User{
				Id:      999,
				Enabled: true,
				Subject: sessionSubject,
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "session-999").Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, userSession).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, userSession, mock.AnythingOfType("*int")).Return(true)

		// The clear succeeds here, so it is the login_required refusal itself that cannot be
		// committed. Site 2's second and pre-existing 500, pinned separately from the nested one
		// above.
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		handler.ServeHTTP(rr, req)

		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
	})

	t.Run("Rejects request parameter with request_not_supported", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&state=abc123&request=foo", nil)
		assert.NoError(t, err)

		settings := &models.Settings{PKCERequired: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(nil)
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)

		// The client load moved above the error-redirect closure, so it now runs before this
		// validator's error is dispatched (#108).
		stubClientProvenanceLookup(database)

		validationError := customerrors.NewErrorDetailWithHttpStatusCode("request_not_supported", "The request parameter is not supported.", http.StatusBadRequest)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.MatchedBy(func(input *validators.ValidateUnsupportedRequestParametersInput) bool {
			return input.HasRequest == true && input.HasRequestURI == false
		})).Return(validationError)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com?")
		assert.Contains(t, location, "error=request_not_supported")
		assert.Contains(t, location, "state=abc123")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("Rejects request_uri parameter with request_uri_not_supported", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&state=xyz&request_uri=https://example.com/x", nil)
		assert.NoError(t, err)

		settings := &models.Settings{PKCERequired: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(nil)
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)

		// The client load moved above the error-redirect closure, so it now runs before this
		// validator's error is dispatched (#108).
		stubClientProvenanceLookup(database)

		validationError := customerrors.NewErrorDetailWithHttpStatusCode("request_uri_not_supported", "The request_uri parameter is not supported.", http.StatusBadRequest)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.MatchedBy(func(input *validators.ValidateUnsupportedRequestParametersInput) bool {
			return input.HasRequest == false && input.HasRequestURI == true
		})).Return(validationError)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "error=request_uri_not_supported")
		assert.Contains(t, location, "state=xyz")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("Rejects empty request parameter (key present, value empty)", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&request=", nil)
		assert.NoError(t, err)

		settings := &models.Settings{PKCERequired: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(nil)
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)

		// The client load moved above the error-redirect closure, so it now runs before this
		// validator's error is dispatched (#108).
		stubClientProvenanceLookup(database)

		validationError := customerrors.NewErrorDetailWithHttpStatusCode("request_not_supported", "The request parameter is not supported.", http.StatusBadRequest)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.MatchedBy(func(input *validators.ValidateUnsupportedRequestParametersInput) bool {
			return input.HasRequest == true
		})).Return(validationError)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "error=request_not_supported")

		authorizeValidator.AssertExpectations(t)
	})
}
