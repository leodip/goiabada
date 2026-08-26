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
	"github.com/leodip/goiabada/core/i18n"
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

// stubAuthenticatedBrowser gives HandleAuthorizeGet a browser that has already authenticated.
//
// Since #213 the authorization endpoint parks a validation error and sends a logged-out visitor to
// /auth/level1 instead of redirecting them to the client, because RFC 9700 4.11.2 requires that the
// server authenticate the user before it redirects them. Every subtest that asserts the SHAPE of an
// error redirect (its code, description, response mode, state echo, and the clear-then-answer
// ordering around it) is asserting what a client receives, which is orthogonal to who is at the
// browser. Each of those keeps its assertions exactly as written and is handed a session here,
// rather than being retargeted at the login page and losing the coverage it exists for
// (#213 decision 6).
// stubRegisteredRedirectURI gives a ceremony's client the registrations the error emitter now reads
// before it will emit anything.
//
// Since #241 decision 11, redirectWillBeEmitted weighs the destination against what the client has
// registered right now, not only against where the URI came from and whether it names a host. Every
// test below that asserts the SHAPE of an error redirect is asserting what a client receives, which
// is orthogonal to whether an administrator has since deleted the callback, so each is handed its
// own registration here and keeps its assertions exactly as written. It is the same move
// stubAuthenticatedBrowser made for #213's session requirement, and for the same reason.
//
// The gate's own answers are TestRedirectWillBeEmitted's table, which owns every one of them.
// Nothing here asserts the gate; this is the fixture that lets the cases about something else stay
// about that something else.
func stubRegisteredRedirectURI(database *mocks_data.Database, registered ...string) {
	uris := make([]models.RedirectURI, 0, len(registered))
	for _, uri := range registered {
		uris = append(uris, models.RedirectURI{URI: uri})
	}
	database.On("GetRedirectURIsByClientId", mock.Anything, mock.Anything).Return(uris, nil)
}

func stubAuthenticatedBrowser(database *mocks_data.Database, userSessionManager *mocks_user.UserSessionManager) {
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything).
		Return(&models.UserSession{Id: 1, UserId: 1}, nil)
	userSessionManager.On("HasValidUserSession", mock.Anything, mock.Anything, mock.Anything).
		Return(true)
}

func TestHandleAuthorizeGet(t *testing.T) {
	t.Run("Valid request with existing session", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubRegisteredRedirectURI(database, "https://example.com")
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

		// A LocalizedError, which is what this validator returns for all seven of its
		// conditions since #213: the refusal page is rendered rather than redirected, so it
		// is the one authorize surface that answers in the visitor's locale. Both bind
		// entries are computed the same way the handler computes them rather than written
		// as literals, so a catalog reword moves the page and the test together while a
		// handler that stopped localizing still fails.
		validationError := i18n.NewLocalizedError(i18n.ErrCodeAuthorizeClientNotFound, nil)
		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(validationError)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["title"] == i18n.T(req.Context(), "auth_error.unable_to_authorize.title") &&
				data["error"] == validationError.Localize(req.Context())
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	// OIDC Core 3.1.2.6: "If the Response Mode value is not supported, the Authorization Server
	// returns an HTTP response code of 400 (Bad Request) without Error Response parameters." So
	// this one failure is answered on a page rather than becoming a redirect, immediate or deferred
	// (#213 decision 11).
	//
	// The mocks carry most of the assertion. All of them are strict, and none of the calls the rest
	// of the handler makes has an expectation here: the client load, the session lookup and all five
	// redirecting validations would each fail this test if the branch let the request through to
	// them. That is what pins the branch's position rather than merely its existence.
	t.Run("Unsupported response_mode is answered 400 on a page, above everything that redirects", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)

		// jwt is JARM, which this server does not implement, and it is what a client asking for an
		// unsupported mode most plausibly asks for.
		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=code&scope=openid&response_mode=jwt", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(nil)
		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)

		// _httpStatus is what RenderTemplate turns into the response code, so it is asserted here
		// rather than on the recorder: the helper is a mock and writes nothing. The integration
		// case asserts the 400 that actually reaches the wire.
		httpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["title"] == i18n.T(req.Context(), "auth_error.unable_to_authorize.title") &&
				data["error"] == i18n.T(req.Context(), "auth_error.unsupported_response_mode.message") &&
				data["_httpStatus"] == http.StatusBadRequest
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		// Neither the client nor the login page: an error that cannot be encoded in the requested
		// mode must not be deferred either, which is the half of this that #213 introduced.
		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	// A mode this server does implement is not answered by the branch above: query is encodable, so
	// an implicit request asking for it falls through to the ordinary validation and its refusal
	// reaches the client as a redirect.
	//
	// This pins inherited behaviour rather than endorsed behaviour, and the distinction is worth
	// stating because the refusal goes out in the query component. RFC 6749 section 4.2.2.1, the
	// implicit grant's own error response, says the authorization server "informs the client by
	// adding the following parameters to the fragment component of the redirection URI using the
	// 'application/x-www-form-urlencoded' format", and OAuth 2.0 Multiple Response Type Encoding
	// Practices section 3 says of id_token that "the default Response Mode for this Response Type
	// is the fragment encoding and the query encoding MUST NOT be used". So emitting this refusal
	// in query is a deviation.
	//
	// It predates #213 and #213 does not widen it: redirToClientWithError already defaults an
	// implicit error carrying no response_mode to fragment, so only an explicitly supplied query
	// reaches this branch. Correcting it changes what an implicit client receives and where it has
	// to look for it, which belongs to its own change rather than to this gate.
	t.Run("A supported response_mode the request may not use still reaches the client", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		stubRegisteredRedirectURI(database, "https://example.com")
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)
		stubAuthenticatedBrowser(database, userSessionManager)

		req, err := http.NewRequest("GET", "/authorize?client_id=test-client&redirect_uri=https://example.com&response_type=token&scope=openid&response_mode=query", nil)
		assert.NoError(t, err)

		settings := &models.Settings{PKCERequired: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(nil)
		authHelper.On("ClearAuthContext", rr, req).Return(nil)
		authorizeValidator.On("ValidateClientAndRedirectURI", mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
		authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*validators.ValidateRequestInput")).Return(
			customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"Implicit flow requires response_mode=fragment or no response_mode (fragment is the default for implicit flow).",
				http.StatusBadRequest))

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Result().Header.Get("Location")
		assert.Contains(t, location, "https://example.com?error=invalid_request")
		assert.Contains(t, location, "Implicit+flow+requires+response_mode%3Dfragment")

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

			validationError := i18n.NewLocalizedError(i18n.ErrCodeAuthorizeClientNotFound, nil)
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
		stubRegisteredRedirectURI(database, "https://example.com")
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)
		stubAuthenticatedBrowser(database, userSessionManager)

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
		stubRegisteredRedirectURI(database, "https://example.com")
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)
		stubAuthenticatedBrowser(database, userSessionManager)

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
		stubRegisteredRedirectURI(database, "https://example.com")
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)
		stubAuthenticatedBrowser(database, userSessionManager)

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
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubAuthenticatedBrowser(database, userSessionManager)

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
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubAuthenticatedBrowser(database, userSessionManager)

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
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubRegisteredRedirectURI(database, "https://example.com")
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)
		stubAuthenticatedBrowser(database, userSessionManager)

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
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubRegisteredRedirectURI(database, "https://example.com")
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

// testRegisteredDatabase gives the emitter's registration gate a client whose current
// registrations are the URIs named, which is what every case below that asserts a Location: needs
// since #241 decision 11: the gate reads them and withholds the redirect when the destination is
// not among them.
//
// It is deliberately the ONLY expectation on the mock. A case that reaches the emitter and does not
// reach this read is a case where one of the two older gates refused first, and those are handed a
// bare mocks_data.NewDatabase(t) instead, so a gate reordered above the read fails loudly rather
// than passing on a stub that answers everything.
func testRegisteredDatabase(t *testing.T, registered ...string) *mocks_data.Database {
	database := mocks_data.NewDatabase(t)

	uris := make([]models.RedirectURI, 0, len(registered))
	for _, uri := range registered {
		uris = append(uris, models.RedirectURI{URI: uri})
	}
	database.On("GetRedirectURIsByClientId", mock.Anything, mock.Anything).Return(uris, nil)

	return database
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

	err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, nil, testRedirectError("invalid_request", "Invalid request", "query", "https://example.com/callback", "abc123", "code"))

	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://example.com/callback?error=invalid_request&error_description=Invalid+request&state=abc123", w.Header().Get("Location"))
}

func TestRedirToClientWithError_FragmentResponseMode(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, nil, testRedirectError("unauthorized_client", "Unauthorized client", "fragment", "https://example.com/callback", "xyz789", "code"))

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

	err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, templateFS, testRedirectError("access_denied", "Access denied", "form_post", "https://example.com/callback", "def456", "code"))

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

	err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, templateFS, testRedirectError("server_error", "Internal server error",
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

	err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, templateFS, testRedirectError("server_error", "Internal server error",
		"form_post", "https://example.com/callback", "def456", "code"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to write the form_post response")
}

func TestRedirToClientWithError_DefaultToQueryResponseMode(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, nil, testRedirectError("server_error", "Internal server error", "", "https://example.com/callback", "ghi789", "code"))

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
			err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, nil, testRedirectError("access_denied", "Access denied", "", "https://example.com/callback", "state123", tt.responseType))

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

		err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, nil, testRedirectError("invalid_request", "Invalid request", "fragment", "https://example.com/callback", "state123", "token"))

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

		err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, templateFS, testRedirectError("access_denied", "Access denied", "form_post", "https://example.com/callback", "state123", "id_token token"))

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
			err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, nil, testRedirectError("access_denied", "Access denied", "", "https://example.com/callback", "state123", tt.responseType))

			require.NoError(t, err)
			assert.Equal(t, http.StatusFound, w.Code)
			location := w.Header().Get("Location")
			assert.Contains(t, location, "https://example.com/callback?")
			assert.Contains(t, location, "error=access_denied")
		})
	}
}

// Emptiness is the whole of the rule, and it is the whole of it in both directions. RFC 6749
// section 3.1 makes "?state=" and "?state" requests that carried no state, so nothing is echoed;
// Appendix A.5's "state = 1*VSCHAR" says the same of the response. But space is %x20, so it is
// VSCHAR, and a whitespace-only state is a value the client chose and this server must return
// unaltered per 4.1.2.1's "the exact value received from the client".
//
// The second subtest asserted the opposite until #146: the emitter guarded on
// len(strings.TrimSpace(state)) > 0, so "   " was dropped entirely and an RP that sent it got a
// response with no state to check at all.
func TestRedirToClientWithError_NoState(t *testing.T) {
	t.Run("empty state not included", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, nil, testRedirectError("access_denied", "Access denied", "query", "https://example.com/callback", "", "code"))

		require.NoError(t, err)
		location := w.Header().Get("Location")
		assert.NotContains(t, location, "state=")
	})

	t.Run("whitespace-only state echoed exactly", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, nil, testRedirectError("access_denied", "Access denied", "fragment", "https://example.com/callback", "   ", "token"))

		require.NoError(t, err)
		assert.Equal(t, "https://example.com/callback#error=access_denied&error_description=Access+denied&state=+++",
			w.Header().Get("Location"))
	})
}

// The defect the issue is named for, at the emitter that reports it. A client may register a
// redirect URI carrying a query (RFC 6749 3.1.2, and site/src/content/docs/concepts/clients.mdx
// documents it as permitted), and the error branch used to seed url.Values from that query and Add
// on top of it, so a registered "?state=fixed" came back alongside the state the client actually
// sent. url.Values.Get returns the first of two, which is the registered value, so an RP following
// RFC 9700 2.1 compared its CSRF token against a string it never generated.
//
// The registered-query shapes themselves are seam 1's exhaustive table, in
// authorization_response_test.go. What these cases add is that the emitter reaches it: a version of
// redirToClientWithError that went back to Query() and Encode() would pass every case in that table
// and fail every one of these.
func TestRedirToClientWithError_RegisteredQuery(t *testing.T) {
	t.Run("query mode replaces a registered state and keeps the rest", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback?state=fixed&lang=en"), nil, nil, testRedirectError("access_denied", "Access denied",
			"query", "https://example.com/callback?state=fixed&lang=en", "client-csrf-token", "code"))

		require.NoError(t, err)
		// Whole-string, not url.Values: parsing is the step that hid the duplicate, since Get
		// answers with the first of the two and reports nothing wrong.
		assert.Equal(t, "https://example.com/callback?lang=en&error=access_denied&error_description=Access+denied&state=client-csrf-token",
			w.Header().Get("Location"))
	})

	t.Run("query mode preserves a registered query that does not round-trip", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		// The retention half of the fix, which has nothing to do with state. url.Query discards
		// ParseQuery's error, so this field used to be deleted outright and the client was sent to
		// a URI it had not registered.
		err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback?lang=en;mode=dark"), nil, nil, testRedirectError("access_denied", "Access denied",
			"query", "https://example.com/callback?lang=en;mode=dark", "abc123", "code"))

		require.NoError(t, err)
		assert.Equal(t, "https://example.com/callback?lang=en;mode=dark&error=access_denied&error_description=Access+denied&state=abc123",
			w.Header().Get("Location"))
	})

	t.Run("fragment mode leaves the registered query alone", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		// The two branches construct differently and that difference is observable here: a
		// registered "state=fixed" in the query is NOT replaced, because the response parameters
		// are going into the fragment and the query is not the field list being written.
		err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback?state=fixed&lang=en"), nil, nil, testRedirectError("access_denied", "Access denied",
			"fragment", "https://example.com/callback?state=fixed&lang=en", "client-csrf-token", "token"))

		require.NoError(t, err)
		assert.Equal(t, "https://example.com/callback?state=fixed&lang=en#error=access_denied&error_description=Access+denied&state=client-csrf-token",
			w.Header().Get("Location"))
	})

	// The reserved set reaches this emitter. Both cases turn on a name the error response does
	// not itself emit, so filtering only what is being written leaves the registered field in
	// place and both assertions fail (#146, decision 13).
	t.Run("query mode drops a registered state the request did not supply", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback?state=fixed&lang=en"), nil, nil, testRedirectError("access_denied", "Access denied",
			"query", "https://example.com/callback?state=fixed&lang=en", "", "code"))

		require.NoError(t, err)
		// No state is emitted, because the request carried none, and the registered one does not
		// stand in for it: a state on this redirect is the client's own or it is absent.
		assert.Equal(t, "https://example.com/callback?lang=en&error=access_denied&error_description=Access+denied",
			w.Header().Get("Location"))
	})

	t.Run("query mode drops a registered code from an error response", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback?code=stale&lang=en"), nil, nil, testRedirectError("access_denied", "Access denied",
			"query", "https://example.com/callback?code=stale&lang=en", "client-csrf-token", "code"))

		require.NoError(t, err)
		// Otherwise a refusal arrives carrying an authorization code, and an RP that reads "code"
		// before "error" tries to redeem a value this server never issued on this request.
		assert.Equal(t, "https://example.com/callback?lang=en&error=access_denied&error_description=Access+denied&state=client-csrf-token",
			w.Header().Get("Location"))
	})
}

// RFC 6749 4.1.2.1 and 4.2.2.1 both require "the exact value received from the client", so every
// byte a client can legally put in a state has to survive the trip. The characters below are the
// ones a construction built out of string concatenation gets wrong: "+" decodes back as a space,
// "/" and "=" are what base64 state values are full of, "#" truncates a query, and "&" splits one
// field into two (#109 for the logout endpoint, #146 here).
func TestRedirToClientWithError_ByteExactState(t *testing.T) {
	const state = "a b+c/d=e#f&g=h"

	t.Run("query mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, nil, testRedirectError("access_denied", "Access denied",
			"query", "https://example.com/callback", state, "code"))

		require.NoError(t, err)
		assert.Equal(t, "https://example.com/callback?error=access_denied&error_description=Access+denied&state=a+b%2Bc%2Fd%3De%23f%26g%3Dh",
			w.Header().Get("Location"))
	})

	t.Run("fragment mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, nil, testRedirectError("access_denied", "Access denied",
			"fragment", "https://example.com/callback", state, "token"))

		require.NoError(t, err)
		assert.Equal(t, "https://example.com/callback#error=access_denied&error_description=Access+denied&state=a+b%2Bc%2Fd%3De%23f%26g%3Dh",
			w.Header().Get("Location"))
	})

	t.Run("form_post mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		// form_post carries the value in a form field rather than a URI, so what has to survive is
		// the raw string reaching the template, HTML-escaped by html/template and nothing else.
		templateFS := &mocks.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<input name="state" value="{{.state}}">`,
			},
		}

		err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, templateFS, testRedirectError("access_denied", "Access denied",
			"form_post", "https://example.com/callback", state, "code"))

		require.NoError(t, err)
		// html/template escapes "+" as &#43; and "&" as &amp; in an attribute; both decode back to
		// the byte the client sent, which is what "exact value" asks for in this transport.
		assert.Equal(t, `<input name="state" value="a b&#43;c/d=e#f&amp;g=h">`, w.Body.String())
	})
}

// The form_post response mode's own requirement, which neither branch met. OAuth 2.0 Form Post
// Response Mode section 2: "Because the Authorization Response is intended to be used only once,
// the Authorization Server MUST instruct the User Agent (and any intermediaries) not to store or
// reuse the content of the response." The page carries the client's state, and its twin on the
// success path carries an authorization code, and both were returned as a plain cacheable 200 with
// no cache header anywhere on the /auth routes to supply one (#146).
func TestRedirToClientWithError_FormPostIsNotCacheable(t *testing.T) {
	t.Run("both headers are set on a rendered page", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		templateFS := &mocks.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form method="post" action="{{.redirectURI}}"></form>`,
			},
		}

		err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, templateFS, testRedirectError("access_denied", "Access denied",
			"form_post", "https://example.com/callback", "abc123", "code"))

		require.NoError(t, err)
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
	})

	t.Run("neither header is set when the render failed", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		// The companion to the uncommitted-response case above. A failed render must leave the
		// response completely untouched, headers included, so the caller's last-resort 500 is
		// answering with its own headers rather than with those of a form_post page that was never
		// sent. Setting these two above the Execute would break that (#141).
		templateFS := &mocks.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form>{{index . "missing" 0}}</form>`,
			},
		}

		err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, templateFS, testRedirectError("server_error", "Internal server error",
			"form_post", "https://example.com/callback", "abc123", "code"))

		require.Error(t, err)
		assert.Empty(t, w.Header().Get("Cache-Control"))
		assert.Empty(t, w.Header().Get("Pragma"))
	})
}

// The form_post branch's "state" bind key is pinned in handler_auth_issue_test.go, by
// TestFormPostBindMapOmitsAnAbsentState, together with its twin on the success path: the property
// belongs to both emitters and to the shared template, so the cases live together rather than half
// here.
//
// It is there rather than here because it was first written off as impossible. The reasoning was
// that to a template a map key that is absent and a key holding "" are the same thing, which holds
// for {{.state}} and {{if .state}} and is false in general: a template that ranges over the map
// yields the key only when it is present. The mutation that makes the guard unconditional survives
// every assertion against a rendered page and is caught by the key-set assertion (#146).

// Gate 4's third site (#122). An error redirect is the open-redirect vector on this endpoint: the
// request has already been refused, and forwarding the browser anyway is this server sending a user
// somewhere on the strength of a stored string. #108's guard above covers only clients that
// registered themselves, so a client an administrator created, holding a row stored before these
// rules existed, walks straight past it.
//
// Every case below therefore carries the administrator-created client testRedirectError supplies. A
// case built on a nil or self-registered client would render the same page for #108's reason and go
// on passing with this guard deleted.
//
// These are also the only cases in this file that reach the renderer, which is why they are the only
// ones with a real httpHelper: its ten siblings pass nil precisely to say they never withhold a
// redirect.
func TestRedirToClientWithError_NonAbsoluteRedirectURIRendersTheBlockedPage(t *testing.T) {
	for _, tc := range []struct {
		name        string
		redirectURI string
		destination string
		why         string
	}{
		{
			name:        "scheme-relative",
			redirectURI: "//evil.example/cb",
			destination: "evil.example",
			why:         "url.Parse reads the authority, so the page names the host the browser would have gone to",
		},
		{
			name:        "https with no authority",
			redirectURI: "https:///evil.example/cb",
			destination: "https:///evil.example/cb",
			why: "decision 8's family. redirectDestinationLabel falls back to the whole URI when url.Parse " +
				"finds no host, which is what happens here, so the page shows the registered string rather " +
				"than evil.example. That is the documented fallback rather than a defect, and it still " +
				"puts the host in front of the user",
		},
		{
			name:        "carrying a fragment",
			redirectURI: "https://legit.example/cb#frag",
			destination: "legit.example",
			why:         "a legitimate host whose callback the fragment breaks, so the redirect is withheld and the host named",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/authorize", nil)

			httpHelper.On("RenderTemplate", w, r, "/layouts/no_menu_layout.html", "/auth_redirect_blocked.html",
				mock.MatchedBy(func(data map[string]interface{}) bool {
					return data["destination"] == tc.destination
				})).Return(nil)

			err := redirToClientWithError(w, r, mocks_data.NewDatabase(t), httpHelper, nil, testRedirectError("access_denied", "Access denied", "query", tc.redirectURI, "abc123", "code"))

			require.NoError(t, err)
			assert.Empty(t, w.Header().Get("Location"), "a withheld redirect must never become a Location: %s", tc.why)
			httpHelper.AssertExpectations(t)
		})
	}
}

// redirectWillBeEmitted is the one definition of "would an error response to this client actually
// leave the server", and it now has two readers: the emitter, which withholds the redirect and
// renders the interstitial, and the handler, which asks the same question earlier to decide whether
// anything has to be authenticated first. Two call sites that must agree is exactly the shape a
// later edit gets out of step, so the provenance, emittability and registration table lives here,
// once, and the handler-level tests stay thin on purpose. It is also why #241 decision 11 put its
// registration check in this predicate rather than at the seven sites that answer a client from a
// ceremony in progress: seven copies of a security gate is seven chances for one of them to be
// forgotten.
//
// Every negative varies exactly one thing from the accepted row, so none of them can pass with all
// the gates removed (#108, #122, #213, #241).
//
// The database is the row's own, and its ABSENCE is an assertion. A row whose gate refuses before
// the registration read is handed a mocks_data.NewDatabase(t) carrying no expectation at all, so a
// read that happens anyway fails the case instead of being absorbed by a permissive stub. That is
// the ordering claim, and it is a claim about this function rather than about the database: the two
// older gates cost nothing and the third costs a query, so the cheap refusals must stay above it.
func TestRedirectWillBeEmitted(t *testing.T) {
	// registeredDatabase answers the registration read with the URIs given. Declared here rather
	// than reused from testRegisteredDatabase because these rows need the empty list too, and an
	// empty variadic call reads as "no registrations" in one place and "no expectation" in the
	// other; saying which is meant is the point of the whole table.
	registeredDatabase := func(t *testing.T, registered ...string) *mocks_data.Database {
		database := mocks_data.NewDatabase(t)

		uris := make([]models.RedirectURI, 0, len(registered))
		for _, uri := range registered {
			uris = append(uris, models.RedirectURI{URI: uri})
		}
		database.On("GetRedirectURIsByClientId", mock.Anything, mock.Anything).Return(uris, nil)

		return database
	}

	// The rows whose gate refuses above the read use this: a mock with no expectation, so a call
	// that reaches it fails the case.
	noReadExpected := func(t *testing.T) *mocks_data.Database {
		return mocks_data.NewDatabase(t)
	}

	failingDatabase := func(t *testing.T) *mocks_data.Database {
		database := mocks_data.NewDatabase(t)
		database.On("GetRedirectURIsByClientId", mock.Anything, mock.Anything).
			Return(nil, errors.New("the database is unavailable"))
		return database
	}

	for _, tc := range []struct {
		name         string
		database     func(t *testing.T) *mocks_data.Database
		client       *models.Client
		redirectURI  string
		responseType string
		want         bool
		why          string
	}{
		{
			name: "administrator-registered client with an absolute, registered redirect URI",
			database: func(t *testing.T) *mocks_data.Database {
				return registeredDatabase(t, "https://legit.example/cb")
			},
			client:       &models.Client{ClientIdentifier: "test-client", CreatedViaDCR: false},
			redirectURI:  "https://legit.example/cb",
			responseType: "code",
			want:         true,
			why:          "a human vetted this redirect URI at registration and the client still holds it, so all three gates are answered",
		},
		{
			name: "self-registered client",
			// No expectation: the provenance gate refuses above the read.
			database:     noReadExpected,
			client:       &models.Client{ClientIdentifier: "dcr-client", CreatedViaDCR: true},
			redirectURI:  "https://legit.example/cb",
			responseType: "code",
			want:         false,
			why:          "the provenance gate: the client chose its own redirect URI, which is the source RFC 9700 4.11.2 names (#108)",
		},
		{
			name:         "unresolved client",
			database:     noReadExpected,
			client:       nil,
			redirectURI:  "https://legit.example/cb",
			responseType: "code",
			want:         false,
			why: "the provenance gate again. nil means the handler could not find out where the redirect URI " +
				"came from, and that is the untrusted case rather than an exempt one (#108). There is also no " +
				"client id to read registrations for, so the read could not happen even if the order changed",
		},
		{
			name: "administrator-registered client with an unemittable redirect URI",
			// No expectation: the emittability gate refuses above the read.
			database:     noReadExpected,
			client:       &models.Client{ClientIdentifier: "test-client", CreatedViaDCR: false},
			redirectURI:  "//evil.example/cb",
			responseType: "code",
			want:         false,
			why: "the emittability gate: provenance passes and the string still cannot name the host it " +
				"appears to, which is the row an old client can hold and the gate above cannot cover (#122)",
		},
		{
			name: "registered redirect URI deleted from the client",
			database: func(t *testing.T) *mocks_data.Database {
				return registeredDatabase(t, "https://other.example/cb")
			},
			client:       &models.Client{ClientIdentifier: "test-client", CreatedViaDCR: false},
			redirectURI:  "https://legit.example/cb",
			responseType: "code",
			want:         false,
			why: "the registration gate. Provenance and emittability both pass, exactly as they did when the " +
				"ceremony began, and the only thing that changed is that an administrator deleted this " +
				"callback while it ran (#241 decision 11)",
		},
		{
			name: "client with no registrations at all",
			database: func(t *testing.T) *mocks_data.Database {
				return registeredDatabase(t)
			},
			client:       &models.Client{ClientIdentifier: "test-client", CreatedViaDCR: false},
			redirectURI:  "https://legit.example/cb",
			responseType: "code",
			want:         false,
			why: "an empty list covers nothing, and this is the shape a client whose last callback was " +
				"removed actually has. RedirectURIIsRegistered answers false on it rather than treating " +
				"\"nothing registered\" as \"no restriction\"",
		},
		{
			name:         "registration read fails",
			database:     failingDatabase,
			client:       &models.Client{ClientIdentifier: "test-client", CreatedViaDCR: false},
			redirectURI:  "https://legit.example/cb",
			responseType: "code",
			want:         false,
			why: "an unresolved registration is the untrusted case, matching clientProvenance: the caller is " +
				"already answering an error, so a failed lookup withholds the redirect rather than turning a " +
				"working refusal into a 500",
		},
		{
			name: "loopback port flexibility IS granted on a code request",
			database: func(t *testing.T) *mocks_data.Database {
				return registeredDatabase(t, "http://127.0.0.1/cb")
			},
			client:       &models.Client{ClientIdentifier: "native-client", CreatedViaDCR: false},
			redirectURI:  "http://127.0.0.1:49152/cb",
			responseType: "code",
			want:         true,
			why: "RFC 8252 section 7.3: \"The authorization server MUST allow any port to be specified at the " +
				"time of the request for loopback IP redirect URIs\". So the ephemeral port IS registered, and " +
				"RFC 6749 4.1.2.1 then requires the error to be delivered there rather than withheld. Refusing " +
				"it made a native app's errors vanish with nothing on the wire (#41, #241)",
		},
		{
			name: "loopback port flexibility is NOT granted on an implicit request",
			database: func(t *testing.T) *mocks_data.Database {
				return registeredDatabase(t, "http://127.0.0.1/cb")
			},
			client:       &models.Client{ClientIdentifier: "native-client", CreatedViaDCR: false},
			redirectURI:  "http://127.0.0.1:49152/cb",
			responseType: "token",
			want:         false,
			why: "the same token-sequence test /auth/authorize and /auth/issue apply: flexibility is scoped to " +
				"the authorization code flow, because an implicit response carries tokens in the fragment where " +
				"PKCE cannot mitigate interception. /auth/authorize refused this URI at the front door on the " +
				"same rule, so the ceremony cannot legitimately be here (#41)",
		},
		{
			name: "a multi-token response type buys no loopback port",
			database: func(t *testing.T) *mocks_data.Database {
				return registeredDatabase(t, "http://127.0.0.1/cb")
			},
			client:       &models.Client{ClientIdentifier: "native-client", CreatedViaDCR: false},
			redirectURI:  "http://127.0.0.1:49152/cb",
			responseType: "code code",
			want:         false,
			why: "read off the token sequence rather than off ParseResponseType, which collapses duplicates and " +
				"ignores unrecognised values, so \"code code\" and \"code foo\" are HasCode && !HasToken && " +
				"!HasIdToken and must not buy an arbitrary port. The same reasoning as the validator's own gate",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := redirectWillBeEmitted(tc.database(t), tc.client, tc.redirectURI, tc.responseType,
				"TestRedirectWillBeEmitted")

			assert.Equal(t, tc.want, got, tc.why)
		})
	}
}

// The predicate reads the database, so the two answers one authorization request gets from it need
// not agree, and only one direction of disagreement is safe. This is the unsafe one: the pre-routing
// reader was refused, which is what made answering the client at once safe under RFC 9700 4.11.2,
// and the emitter must not then discard that refusal because its own read succeeded or saw the
// callback re-added.
//
// Asserted at the emitter rather than end to end because that is where the floor is enforced and
// where a later edit would drop it. The end-to-end shape is the sequential-read case in
// TestHandleAuthorizeGet_RegistrationReadFailsThenSucceeds (#241).
func TestRedirToClientWithError_HonoursAnEarlierRefusal(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	httpHelper.On("RenderTemplate", w, r, "/layouts/no_menu_layout.html", "/auth_redirect_blocked.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			// The host, not the URI: redirectDestinationLabel reduces it, as its own table pins.
			return data["destination"] == "legit.example"
		})).Return(nil)

	input := testRedirectError("invalid_scope", "Invalid scope", "query", "https://legit.example/cb",
		"abc123", "code")
	input.redirectAlreadyWithheld = true

	// No expectation on the database at all: the floor must short-circuit above the live gates, so
	// a registration read reaching this mock fails the case. That is the ordering claim, and it is
	// what stops a "helpful" edit from re-asking and taking the newer answer.
	err := redirToClientWithError(w, r, mocks_data.NewDatabase(t), httpHelper, nil, input)

	require.NoError(t, err)
	assert.Empty(t, w.Header().Get("Location"),
		"a refusal already given must never be overturned by a second read: that is attack 1 of RFC 9700 4.11.2")
	httpHelper.AssertExpectations(t)
}

func TestHandleAuthorizeGet_ImplicitFlow(t *testing.T) {
	t.Run("Valid implicit flow request with token response type", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_user.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubRegisteredRedirectURI(database, "https://example.com")
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)
		stubAuthenticatedBrowser(database, userSessionManager)

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
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubRegisteredRedirectURI(database, "https://example.com")
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)
		stubAuthenticatedBrowser(database, userSessionManager)

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
		stubRegisteredRedirectURI(database, "https://example.com")
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)
		stubAuthenticatedBrowser(database, userSessionManager)

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
		stubRegisteredRedirectURI(database, "https://example.com")
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)
		stubAuthenticatedBrowser(database, userSessionManager)

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
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubRegisteredRedirectURI(database, "https://example.com")
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
		stubRegisteredRedirectURI(database, "https://example.com")
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)
		stubAuthenticatedBrowser(database, userSessionManager)

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
		stubRegisteredRedirectURI(database, "https://example.com")
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)
		stubAuthenticatedBrowser(database, userSessionManager)

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
		stubRegisteredRedirectURI(database, "https://example.com")
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		permissionChecker := mocks_user.NewPermissionChecker(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger, permissionChecker, tokenParser)
		stubAuthenticatedBrowser(database, userSessionManager)

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

// Seam 1, the routing table. For a request that fails one of the five validations that run before
// this handler knows who is at the browser, does it answer the client, send the visitor to log in
// first, or refuse with the interstitial?
//
// This is the whole of #213: RFC 9700 4.11.2 says "The authorization server MUST always
// authenticate the user first and, with the exception of the silent authentication use case,
// prompt the user for credentials when needed, before redirecting the user", and before this change
// a cookieless browser carrying one bad scope was answered with a 302 to a host the client chose.
//
// Every row is driven end to end through HandleAuthorizeGet and asserted on the recorder, so
// answerClientNow is never read directly: the three outcomes are all externally visible, and a test
// that reached inside would pass with the routing wired to nothing.
//
// The rows are probe/routing_table.out, and its clause-coverage section is why some of them are
// here. Silence is pinned by a logged-out request against an administrator client, and prompt=login
// by a request that HAS a valid session: "none" with a session passes with the silence clause
// deleted (the session clause carries it), and "login" without one passes with the login clause
// deleted (the no-session default carries it). Those four rows are kept anyway, because they are
// the negative twins of the case-sensitivity rows and dropping them would leave "NONE" and "Login"
// asserting nothing in particular.
//
// One row of the probe's nineteen is absent, deliberately: an unresolved client cannot reach the
// predicate through this handler, because the load directly above it answers 500 on a nil client.
// The nil-client case is the untrusted case and it is pinned at seam 4, in TestRedirectWillBeEmitted.
func TestHandleAuthorizeGet_AuthenticateBeforeRedirect_RoutingTable(t *testing.T) {

	const (
		answerClient = "answer the client with the error now"
		deferToLogin = "park the error and go to /auth/level1"
		blockedPage  = "render the refusal interstitial, no login"
	)

	const emittableURI = "https://legit.example/cb"
	const unemittableURI = "//evil.example/cb"

	for _, tc := range []struct {
		name        string
		rawPrompt   string
		hasSession  bool
		createdVia  bool // CreatedViaDCR
		redirectURI string
		want        string
		why         string
	}{
		{
			name: "no prompt, no session", rawPrompt: "", hasSession: false,
			redirectURI: emittableURI, want: deferToLogin,
			why: "the issue itself: a cookieless visitor is no longer redirected to a host the client chose",
		},
		{
			name: "no prompt, valid session", rawPrompt: "", hasSession: true,
			redirectURI: emittableURI, want: answerClient,
			why: "somebody is authenticated already, so RFC 9700's precondition is met and nothing changes",
		},
		{
			name: "prompt=none, no session", rawPrompt: "none", hasSession: false,
			redirectURI: emittableURI, want: answerClient,
			why: "the silence clause, pinned: OIDC Core 3.1.2.3 forbids interacting with the End-User, " +
				"and this is the row that fails if it is deleted",
		},
		{
			name: "prompt=none, valid session", rawPrompt: "none", hasSession: true,
			redirectURI: emittableURI, want: answerClient,
			why: "silence does not depend on the session. Carried by the session clause, so it does NOT " +
				"pin silence: it is here as the twin of the row above",
		},
		{
			name: "prompt=none login, no session", rawPrompt: "none login", hasSession: false,
			redirectURI: emittableURI, want: answerClient,
			why: "an invalid prompt that still CONTAINS none stays silent. This is why the clause reads the " +
				"raw parameter: ValidatePrompt rejects this value, so authContext.Prompt is never assigned",
		},
		{
			name: "prompt=none consent, no session", rawPrompt: "none consent", hasSession: false,
			redirectURI: emittableURI, want: answerClient,
			why: "the second conflicting combination, same reason",
		},
		{
			name: "prompt=NONE, no session", rawPrompt: "NONE", hasSession: false,
			redirectURI: emittableURI, want: deferToLogin,
			why: "OIDC prompt values are case-sensitive, so NONE carries no recognised token and is interactive",
		},
		{
			name: "prompt=login, valid session", rawPrompt: "login", hasSession: true,
			redirectURI: emittableURI, want: deferToLogin,
			why: "the login clause, pinned: the client asked not to be answered on the strength of an " +
				"existing session, and this is the row that fails if it is deleted (decision 4)",
		},
		{
			name: "prompt=login, no session", rawPrompt: "login", hasSession: false,
			redirectURI: emittableURI, want: deferToLogin,
			why: "same outcome by the other clause. Carried by the no-session default, so it does NOT pin login",
		},
		{
			name: "prompt=login consent, valid session", rawPrompt: "login consent", hasSession: true,
			redirectURI: emittableURI, want: deferToLogin,
			why: "login among several valid values still defers",
		},
		{
			name: "prompt=login foo, valid session", rawPrompt: "login foo", hasSession: true,
			redirectURI: emittableURI, want: deferToLogin,
			why: "an invalid prompt that asked for a login still gets one, for the same raw-parameter reason " +
				"as the none rows above",
		},
		{
			name: "prompt=Login, valid session", rawPrompt: "Login", hasSession: true,
			redirectURI: emittableURI, want: answerClient,
			why: "case sensitivity again, the negative twin of prompt=login with a session",
		},
		{
			name: "prompt=consent, no session", rawPrompt: "consent", hasSession: false,
			redirectURI: emittableURI, want: deferToLogin,
			why: "consent is neither silence nor a forced login, so the ordinary rule applies",
		},
		{
			name: "prompt=select_account, valid session", rawPrompt: "select_account", hasSession: true,
			redirectURI: emittableURI, want: answerClient,
			why: "an unimplemented value, and a session holder is answered now",
		},
		{
			name: "no prompt, no session, self-registered client", rawPrompt: "", hasSession: false,
			createdVia: true, redirectURI: emittableURI, want: blockedPage,
			why: "#108's provenance guard fires without a login: no redirect leaves the server, so there is " +
				"nothing to authenticate before (decision 8)",
		},
		{
			name: "no prompt, valid session, self-registered client", rawPrompt: "", hasSession: true,
			createdVia: true, redirectURI: emittableURI, want: blockedPage,
			why: "unchanged from before this change",
		},
		{
			name: "prompt=none, no session, self-registered client", rawPrompt: "none", hasSession: false,
			createdVia: true, redirectURI: emittableURI, want: blockedPage,
			why: "37bbff5d: a silent request is not exempt from the trust guard, and it still is not",
		},
		{
			name: "no prompt, no session, unemittable redirect URI", rawPrompt: "", hasSession: false,
			redirectURI: unemittableURI, want: blockedPage,
			why: "#122's guard, on an administrator-registered client. Same reasoning as the DCR rows: the " +
				"visitor reaches the identical terminal page with or without entering a password",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			authHelper := mocks_handlerhelpers.NewAuthHelper(t)
			userSessionManager := mocks_user.NewUserSessionManager(t)
			database := mocks_data.NewDatabase(t)
			authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
			auditLogger := mocks_audit.NewAuditLogger(t)
			permissionChecker := mocks_user.NewPermissionChecker(t)
			tokenParser := mocks_oauth.NewTokenParser(t)

			handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil,
				authorizeValidator, auditLogger, permissionChecker, tokenParser)

			target := "/authorize?client_id=test-client&redirect_uri=" + url.QueryEscape(tc.redirectURI) +
				"&response_type=code&scope=" + url.QueryEscape("openid bogus")
			if tc.rawPrompt != "" {
				target += "&prompt=" + url.QueryEscape(tc.rawPrompt)
			}

			req := httptest.NewRequest("GET", target, nil)
			req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings,
				&models.Settings{}))
			rr := httptest.NewRecorder()

			authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(nil)

			authorizeValidator.On("ValidateClientAndRedirectURI",
				mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
			database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(
				&models.Client{Id: 1, ClientIdentifier: "test-client", CreatedViaDCR: tc.createdVia}, nil)
			authorizeValidator.On("ValidateUnsupportedRequestParameters",
				mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)
			authorizeValidator.On("ValidateRequest",
				mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
			authorizeValidator.On("ValidateScopes", "openid bogus").Return(
				customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
					"Invalid scope format: 'bogus'.", http.StatusBadRequest))

			// Maybe, for the reason the session lookup below is Maybe: the registration read is
			// the third gate inside redirectWillBeEmitted, so the DCR rows and the unemittable-URI
			// row are refused above it and never query. The rows that do reach it hold their own
			// destination registered, which is what keeps them about the routing they are named
			// for rather than about a deleted callback (#241 decision 11).
			database.On("GetRedirectURIsByClientId", mock.Anything, mock.Anything).
				Return([]models.RedirectURI{{URI: tc.redirectURI}}, nil).Maybe()

			// Maybe, because whether the session is looked up at all is the point of half these
			// rows: the clauses that read nothing are evaluated first, so a request that is
			// silent, or whose redirect would be withheld anyway, never queries.
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything).
				Return(&models.UserSession{Id: 1, UserId: 1}, nil).Maybe()
			userSessionManager.On("HasValidUserSession", mock.Anything, mock.Anything, mock.Anything).
				Return(tc.hasSession).Maybe()

			if tc.want != deferToLogin {
				authHelper.On("ClearAuthContext", rr, req).Return(nil)
			}
			if tc.want == blockedPage {
				httpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html",
					"/auth_redirect_blocked.html", mock.Anything).Return(nil)
			}

			handler.ServeHTTP(rr, req)

			location := rr.Header().Get("Location")

			switch tc.want {
			case answerClient:
				assert.Equal(t, http.StatusFound, rr.Code, tc.why)
				assert.True(t, strings.HasPrefix(location, tc.redirectURI),
					"the client must be answered at its own redirect URI, got %q: %s", location, tc.why)
				assert.Contains(t, location, "error=invalid_scope", tc.why)
			case deferToLogin:
				assert.Equal(t, http.StatusFound, rr.Code, tc.why)
				assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1", location, tc.why)
			case blockedPage:
				assert.Empty(t, location, "a withheld redirect must never become a Location: %s", tc.why)
			}

			httpHelper.AssertExpectations(t)
			authHelper.AssertExpectations(t)
			authorizeValidator.AssertExpectations(t)
		})
	}
}

// The session row is loaded lazily, so a fault reading it cannot preempt an outcome that never
// needed it, and it fails closed for the one outcome that does.
//
// §4 wrote hasValidUserSession as a plain local assigned above the predicate. That would query the
// session on every request reaching it, including a prompt=none request that queries again inside
// handlePromptNone and a prompt=login request that never looked at one before this change, and it
// would let a database fault answer 500 where the server used to answer correctly without a session
// at all. The three rows below are the difference, and each fails if the assignment is made eager.
func TestHandleAuthorizeGet_SessionLookupIsLazyAndFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rawPrompt string
		want      string // "client", "level1" or "500"
		why       string
	}{
		{
			name: "prompt=none", rawPrompt: "none", want: "client",
			why: "the silence clause decides on its own, so the broken lookup is never reached and the " +
				"client is answered exactly as it is today",
		},
		{
			name: "prompt=login", rawPrompt: "login", want: "level1",
			why: "the login clause decides on its own. The visitor goes to log in, which is where a " +
				"prompt=login request was going anyway, rather than to a 500",
		},
		{
			name: "no prompt", rawPrompt: "", want: "500",
			why: "the one outcome that genuinely needs the session. An unreadable session is not an absent " +
				"one: reading it as absent would send a signed-in user back through the login page on a " +
				"transient database fault, so it fails closed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			authHelper := mocks_handlerhelpers.NewAuthHelper(t)
			userSessionManager := mocks_user.NewUserSessionManager(t)
			database := mocks_data.NewDatabase(t)
			stubRegisteredRedirectURI(database, "https://legit.example/cb")
			authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
			auditLogger := mocks_audit.NewAuditLogger(t)
			permissionChecker := mocks_user.NewPermissionChecker(t)
			tokenParser := mocks_oauth.NewTokenParser(t)

			handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil,
				authorizeValidator, auditLogger, permissionChecker, tokenParser)

			target := "/authorize?client_id=test-client&redirect_uri=https%3A%2F%2Flegit.example%2Fcb" +
				"&response_type=code&scope=" + url.QueryEscape("openid bogus")
			if tc.rawPrompt != "" {
				target += "&prompt=" + tc.rawPrompt
			}

			req := httptest.NewRequest("GET", target, nil)
			req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings,
				&models.Settings{}))
			rr := httptest.NewRecorder()

			authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(nil)
			authorizeValidator.On("ValidateClientAndRedirectURI",
				mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
			database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(
				&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil)
			// Maybe on all three, because the predicate is computed above the validations: the
			// row that answers 500 does so before any of them runs, which is the correct order
			// (there is no answer to give a client until the server knows who is at the browser)
			// and is why they are not asserted as reached.
			authorizeValidator.On("ValidateUnsupportedRequestParameters",
				mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil).Maybe()
			authorizeValidator.On("ValidateRequest",
				mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil).Maybe()
			authorizeValidator.On("ValidateScopes", "openid bogus").Return(
				customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
					"Invalid scope format: 'bogus'.", http.StatusBadRequest)).Maybe()

			lookupErr := errors.New("the session store is unreachable")
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything).
				Return(nil, lookupErr).Maybe()

			switch tc.want {
			case "client":
				authHelper.On("ClearAuthContext", rr, req).Return(nil)
			case "500":
				httpHelper.On("InternalServerError", rr, req, lookupErr).Return()
			}

			handler.ServeHTTP(rr, req)

			switch tc.want {
			case "client":
				assert.Equal(t, http.StatusFound, rr.Code, tc.why)
				assert.Contains(t, rr.Header().Get("Location"), "error=invalid_scope", tc.why)
			case "level1":
				assert.Equal(t, http.StatusFound, rr.Code, tc.why)
				assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1",
					rr.Header().Get("Location"), tc.why)
			case "500":
				assert.Empty(t, rr.Header().Get("Location"),
					"a failed session lookup must not answer anybody: %s", tc.why)
			}

			httpHelper.AssertExpectations(t)
			authHelper.AssertExpectations(t)
		})
	}
}

// Decision 10's third boundary, which this stage adds. The description is conformed to RFC 6749
// Appendix A.8's character set on the way INTO the auth context, not only on the way out of the
// emitter, because a bound applied at emission does nothing for a string already written to a
// cookie: descriptions interpolate request text and ChunkedCookieStore caps a session at 50 chunks,
// so an unbounded parked description answers 500 instead of deferring.
//
// The filter is idempotent, which is what lets it run at both places and still leave the deferred
// and immediate paths byte-identical. That end-to-end equality belongs to seam 3; what is pinned
// here is only that the parked value went through the filter at all.
func TestHandleAuthorizeGet_ParkedDescriptionIsConformed(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	authHelper := mocks_handlerhelpers.NewAuthHelper(t)
	userSessionManager := mocks_user.NewUserSessionManager(t)
	database := mocks_data.NewDatabase(t)
	stubRegisteredRedirectURI(database, "https://legit.example/cb")
	authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	permissionChecker := mocks_user.NewPermissionChecker(t)
	tokenParser := mocks_oauth.NewTokenParser(t)

	handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil,
		authorizeValidator, auditLogger, permissionChecker, tokenParser)

	req := httptest.NewRequest("GET",
		"/authorize?client_id=test-client&redirect_uri=https%3A%2F%2Flegit.example%2Fcb"+
			"&response_type=code&scope="+url.QueryEscape("openid 💣"), nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings,
		&models.Settings{}))
	rr := httptest.NewRecorder()

	// The first save carries no parked error; the second is the deferral.
	authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
		return ac.DeferredErrorCode == ""
	})).Return(nil).Once()

	var parked string
	authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
		return ac.DeferredErrorCode == "invalid_scope"
	})).Run(func(args mock.Arguments) {
		parked = args.Get(2).(*oauth.AuthContext).DeferredErrorDescription
	}).Return(nil).Once()

	authorizeValidator.On("ValidateClientAndRedirectURI",
		mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
	database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(
		&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil)
	authorizeValidator.On("ValidateUnsupportedRequestParameters",
		mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)
	authorizeValidator.On("ValidateRequest",
		mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
	authorizeValidator.On("ValidateScopes", "openid 💣").Return(
		customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
			"Invalid scope format: '💣'.", http.StatusBadRequest))
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything).Return(nil, nil)
	userSessionManager.On("HasValidUserSession", mock.Anything, mock.Anything, mock.Anything).Return(false)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1", rr.Header().Get("Location"))
	assert.Equal(t, "Invalid scope format: '?'.", parked,
		"the emoji is one ? and not four, and the cookie never carries a byte RFC 6749 forbids")

	authHelper.AssertExpectations(t)
}

// One authorization request asks redirectWillBeEmitted twice: HandleAuthorizeGet asks it before
// routing, to decide whether a validation failure may be answered at once or has to be parked behind
// a login, and the emitter asks it again at the last moment. Since the predicate started reading the
// registration table (#241 decision 11) those two answers need not agree, and the disagreement has a
// safe direction and an unsafe one.
//
// The unsafe one is a real bypass, not a theoretical one. A refusal from the first read is what
// makes answerClientNow true, on the reasoning that no redirect leaves this server so RFC 9700
// 4.11.2 has nothing to govern. If the second read then says yes, that reasoning has been discarded
// while its conclusion is kept: a logged-out browser holding one crafted link is redirected to the
// client's host on a request this server refused, which is attack 1 of that section verbatim and
// exactly what #213's deferral machinery exists to prevent.
//
// Both rows drive the whole handler rather than the emitter alone, because the defect is in how the
// two readers compose and neither one is wrong by itself.
func TestHandleAuthorizeGet_RegistrationReadDisagreesWithItself(t *testing.T) {
	const redirectURI = "https://legit.example/cb"

	for _, tc := range []struct {
		name       string
		hasSession bool
		firstRead  func(*mocks_data.Database)
		secondRead func(*mocks_data.Database)
		wantReads  int
		why        string
	}{
		{
			name:       "a refusal is never widened into a redirect",
			hasSession: false,
			firstRead: func(database *mocks_data.Database) {
				database.On("GetRedirectURIsByClientId", mock.Anything, mock.Anything).
					Return(nil, errors.New("the database is unavailable")).Once()
			},
			secondRead: func(database *mocks_data.Database) {
				database.On("GetRedirectURIsByClientId", mock.Anything, mock.Anything).
					Return([]models.RedirectURI{{URI: redirectURI}}, nil).Maybe()
			},
			wantReads: 1,
			why: "the first read failed, which is what routed this logged-out browser to an immediate " +
				"answer instead of a login. The second read recovering must not turn that into a 302: " +
				"the refusal is a floor, carried on redirectAlreadyWithheld",
		},
		{
			name:       "a permission is still narrowed into a refusal",
			hasSession: true,
			firstRead: func(database *mocks_data.Database) {
				database.On("GetRedirectURIsByClientId", mock.Anything, mock.Anything).
					Return([]models.RedirectURI{{URI: redirectURI}}, nil).Once()
			},
			secondRead: func(database *mocks_data.Database) {
				database.On("GetRedirectURIsByClientId", mock.Anything, mock.Anything).
					Return([]models.RedirectURI{}, nil).Maybe()
			},
			wantReads: 2,
			why: "the other direction, and it must still work: an administrator deleting the callback " +
				"between the two reads is the whole point of the gate, so a yes may become a no. Without " +
				"this row the floor could be implemented as a cache and nothing would notice",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			authHelper := mocks_handlerhelpers.NewAuthHelper(t)
			userSessionManager := mocks_user.NewUserSessionManager(t)
			database := mocks_data.NewDatabase(t)
			authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
			auditLogger := mocks_audit.NewAuditLogger(t)
			permissionChecker := mocks_user.NewPermissionChecker(t)
			tokenParser := mocks_oauth.NewTokenParser(t)

			handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil,
				authorizeValidator, auditLogger, permissionChecker, tokenParser)

			target := "/authorize?client_id=test-client&redirect_uri=" + url.QueryEscape(redirectURI) +
				"&response_type=code&scope=" + url.QueryEscape("openid bogus")
			req := httptest.NewRequest("GET", target, nil)
			req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings,
				&models.Settings{}))
			rr := httptest.NewRecorder()

			authHelper.On("SaveAuthContext", rr, req, mock.AnythingOfType("*oauth.AuthContext")).Return(nil)
			authHelper.On("ClearAuthContext", rr, req).Return(nil)

			authorizeValidator.On("ValidateClientAndRedirectURI",
				mock.AnythingOfType("*validators.ValidateClientAndRedirectURIInput")).Return(nil)
			database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(
				&models.Client{Id: 1, ClientIdentifier: "test-client", CreatedViaDCR: false}, nil)
			authorizeValidator.On("ValidateUnsupportedRequestParameters",
				mock.AnythingOfType("*validators.ValidateUnsupportedRequestParametersInput")).Return(nil)
			authorizeValidator.On("ValidateRequest",
				mock.AnythingOfType("*validators.ValidateRequestInput")).Return(nil)
			authorizeValidator.On("ValidateScopes", "openid bogus").Return(
				customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
					"Invalid scope format: 'bogus'.", http.StatusBadRequest))

			// Strictly sequential, which is the whole fixture: the first read is consumed .Once()
			// and the second answer is left standing, rather than one stable stub answering both.
			// A stub that answers both reads identically cannot express a disagreement, which is
			// why the existing tables did not catch this.
			//
			// The second answer is the DANGEROUS one and it is deliberately left available: the
			// row does not prove the floor by withholding the temptation, it proves it by making
			// the wrong answer reachable and then asserting the code never went back for it.
			tc.firstRead(database)
			tc.secondRead(database)

			database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything).
				Return(&models.UserSession{Id: 1, UserId: 1}, nil).Maybe()
			userSessionManager.On("HasValidUserSession", mock.Anything, mock.Anything, mock.Anything).
				Return(tc.hasSession).Maybe()

			httpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html",
				"/auth_redirect_blocked.html", mock.Anything).Return(nil)

			handler.ServeHTTP(rr, req)

			assert.Empty(t, rr.Header().Get("Location"),
				"a withheld redirect must never become a Location: %s", tc.why)

			// The count is the assertion that separates the two rows. One read means the emitter
			// short-circuited on the floor instead of asking again; two means it asked and took
			// the newer, stricter answer. Caching the first answer would make both rows read once
			// and the second row would fail.
			database.AssertNumberOfCalls(t, "GetRedirectURIsByClientId", tc.wantReads)

			httpHelper.AssertExpectations(t)
			authHelper.AssertExpectations(t)
		})
	}
}
