package server

import (
    "net/http"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/inputsanitizer"
	core_middleware "github.com/leodip/goiabada/core/middleware"
    "github.com/leodip/goiabada/core/oauth"
    oauthdb "github.com/leodip/goiabada/core/oauthdb"
	"github.com/leodip/goiabada/core/otp"
	"github.com/leodip/goiabada/core/user"
	"github.com/leodip/goiabada/core/validators"
)

func (s *Server) initRoutes() {

	auditLogger := audit.NewAuditLogger(s.auditLogsInConsole)
	authorizeValidator := validators.NewAuthorizeValidator(s.database)
    tokenParser := oauthdb.NewTokenParser(s.database)
	permissionChecker := user.NewPermissionChecker(s.database)
	tokenValidator := validators.NewTokenValidator(s.database, tokenParser, permissionChecker)
	emailValidator := validators.NewEmailValidator(s.database)
	passwordValidator := validators.NewPasswordValidator()
	profileValidator := validators.NewProfileValidator(s.database)
	addressValidator := validators.NewAddressValidator(s.database)
	phoneValidator := validators.NewPhoneValidator(s.database)
	identifierValidator := validators.NewIdentifierValidator()
	inputSanitizer := inputsanitizer.NewInputSanitizer()

	codeIssuer := oauth.NewCodeIssuer(s.database)
	userSessionManager := user.NewUserSessionManager(codeIssuer, s.sessionStore, constants.AuthServerSessionName, s.database)
	otpSecretGenerator := otp.NewOTPSecretGenerator()
    tokenIssuer := oauth.NewTokenIssuer(s.database, s.baseURL)
	userCreator := user.NewUserCreator(s.database)
	emailSender := communication.NewEmailSender()

	httpHelper := handlerhelpers.NewHttpHelper(s.templateFS)
	authHelper := handlerhelpers.NewAuthHelper(s.sessionStore, constants.AuthServerSessionName, s.baseURL, s.adminConsoleBaseURL)

    middlewareJwt := core_middleware.NewMiddlewareJwt(
        s.sessionStore,
        constants.AuthServerSessionName,
        tokenParser,
        authHelper,
        &http.Client{},
        s.baseURL,
        s.adminConsoleBaseURL,
        "",
        "",
    )
	authHeaderToContext := middlewareJwt.JwtAuthorizationHeaderToContext()

	authServerConfig := config.GetAuthServer()
	rateLimiter := core_middleware.NewRateLimiterMiddleware(
		authHelper,
		authServerConfig.RateLimiterEnabled,
	)

	s.router.NotFound(handlers.HandleNotFoundGet(httpHelper))
	s.router.Get("/", handlers.HandleIndexGet(httpHelper))
	s.router.Get("/unauthorized", handlers.HandleUnauthorizedGet(httpHelper))
	s.router.Get("/forgot-password", handlers.HandleForgotPasswordGet(httpHelper))
	s.router.Post("/forgot-password", handlers.HandleForgotPasswordPost(httpHelper, s.database, emailSender))
	s.router.With(rateLimiter.LimitResetPwd).Get("/reset-password", handlers.HandleResetPasswordGet(httpHelper, s.database))
	s.router.Post("/reset-password", handlers.HandleResetPasswordPost(httpHelper, s.database, passwordValidator))
	s.router.Get("/.well-known/openid-configuration", handlers.HandleWellKnownOIDCConfigGet(httpHelper))
	s.router.Get("/certs", handlers.HandleCertsGet(httpHelper, s.database))
	s.router.With(authHeaderToContext, middleware.RequireBearerTokenScope(constants.AuthServerResourceIdentifier+":"+constants.UserinfoPermissionIdentifier)).Get("/userinfo", handlers.HandleUserInfoGetPost(httpHelper, s.database, auditLogger))
	s.router.With(authHeaderToContext, middleware.RequireBearerTokenScope(constants.AuthServerResourceIdentifier+":"+constants.UserinfoPermissionIdentifier)).Post("/userinfo", handlers.HandleUserInfoGetPost(httpHelper, s.database, auditLogger))
	s.router.Get("/health", handlers.HandleHealthCheckGet(httpHelper))
	s.router.Get("/openapi.yaml", handlers.HandleOpenAPIGet())

	// Dynamic Client Registration endpoint (RFC 7591)
	// Note: Already CSRF-exempt via middleware (server-to-server API)
	s.router.With(rateLimiter.LimitDCR).Post("/connect/register",
		handlers.HandleDynamicClientRegistrationPost(httpHelper, s.database, auditLogger))

	// Public API endpoints (no authentication required)
	publicSettingsHandler := handlers.NewHandlerPublicSettings(s.database)
	s.router.Get("/api/public/settings", publicSettingsHandler.ServeHTTP)

	s.router.Route("/auth", func(r chi.Router) {
		r.Get("/authorize", handlers.HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, s.database, s.templateFS, authorizeValidator, auditLogger))
		r.Get("/level1", handlers.HandleAuthLevel1Get(httpHelper, authHelper))
		r.Get("/level1completed", handlers.HandleAuthLevel1CompletedGet(httpHelper, authHelper, userSessionManager, s.database))
		r.Get("/level2", handlers.HandleAuthLevel2Get(httpHelper, authHelper, s.database))
		r.Get("/completed", handlers.HandleAuthCompletedGet(httpHelper, authHelper, userSessionManager, s.database, s.templateFS, auditLogger, permissionChecker))
		r.Get("/issue", handlers.HandleIssueGet(httpHelper, authHelper, s.templateFS, codeIssuer, auditLogger))
		r.Get("/pwd", handlers.HandleAuthPwdGet(httpHelper, authHelper, s.database))
		r.With(rateLimiter.LimitPwd).Post("/pwd", handlers.HandleAuthPwdPost(httpHelper, authHelper, s.database, auditLogger))
		r.Get("/otp", handlers.HandleAuthOtpGet(httpHelper, s.sessionStore, authHelper, s.database, otpSecretGenerator))
		r.With(rateLimiter.LimitOtp).Post("/otp", handlers.HandleAuthOtpPost(httpHelper, s.sessionStore, authHelper, s.database, auditLogger))
		r.Get("/consent", handlers.HandleConsentGet(httpHelper, authHelper, s.database))
		r.Post("/consent", handlers.HandleConsentPost(httpHelper, authHelper, s.database, s.templateFS, auditLogger))
		r.Post("/token", handlers.HandleTokenPost(httpHelper, userSessionManager, s.database, tokenIssuer, tokenValidator, auditLogger))
        r.Get("/logout", handlers.HandleAccountLogoutGet(httpHelper, s.sessionStore, authHelper, s.database, tokenParser, auditLogger))
        r.Post("/logout", handlers.HandleAccountLogoutPost(httpHelper, s.sessionStore, authHelper, s.database, auditLogger))
	})

	s.router.Route("/account", func(r chi.Router) {
		r.Get("/register", accounthandlers.HandleAccountRegisterGet(httpHelper))
		r.Post("/register", accounthandlers.HandleAccountRegisterPost(httpHelper, s.database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger))
		r.With(rateLimiter.LimitActivate).Get("/activate", accounthandlers.HandleAccountActivateGet(httpHelper, s.database, userCreator, auditLogger))
	})

	// Admin API routes
	s.router.Route("/api/v1/admin", func(r chi.Router) {
		r.Use(middleware.APIDebugMiddleware())
		r.Use(authHeaderToContext)
		r.Use(middleware.RequireBearerTokenScope(constants.AuthServerResourceIdentifier + ":" + constants.ManagePermissionIdentifier))

		// User management routes
		r.Get("/users/search", apihandlers.HandleAPIUsersSearchGet(s.database))
		r.Get("/users/{id}", apihandlers.HandleAPIUserGet(s.database))
		r.Put("/users/{id}/enabled", apihandlers.HandleAPIUserEnabledPut(s.database, auditLogger))
		r.Put("/users/{id}/profile", apihandlers.HandleAPIUserProfilePut(s.database, profileValidator, inputSanitizer, auditLogger))
		r.Put("/users/{id}/address", apihandlers.HandleAPIUserAddressPut(s.database, addressValidator, inputSanitizer, auditLogger))
		r.Put("/users/{id}/email", apihandlers.HandleAPIUserEmailPut(s.database, emailValidator, inputSanitizer, auditLogger))
		r.Put("/users/{id}/phone", apihandlers.HandleAPIUserPhonePut(s.database, phoneValidator, inputSanitizer, auditLogger))
		r.Put("/users/{id}/password", apihandlers.HandleAPIUserPasswordPut(s.database, passwordValidator, auditLogger))
		r.Put("/users/{id}/otp", apihandlers.HandleAPIUserOTPPut(s.database, auditLogger))
		r.Post("/users/create", apihandlers.HandleAPIUserCreatePost(httpHelper, s.database, userCreator, emailValidator, profileValidator, passwordValidator, auditLogger, emailSender))
		r.Delete("/users/{id}", apihandlers.HandleAPIUserDelete(s.database, auditLogger))

		// User attributes routes
		r.Get("/users/{id}/attributes", apihandlers.HandleAPIUserAttributesGet(s.database))
		r.Get("/user-attributes/{id}", apihandlers.HandleAPIUserAttributeGet(s.database))
		r.Post("/user-attributes", apihandlers.HandleAPIUserAttributeCreatePost(s.database, identifierValidator, inputSanitizer, auditLogger))
		r.Put("/user-attributes/{id}", apihandlers.HandleAPIUserAttributeUpdatePut(s.database, identifierValidator, inputSanitizer, auditLogger))
		r.Delete("/user-attributes/{id}", apihandlers.HandleAPIUserAttributeDelete(s.database, auditLogger))

		// User session routes
		r.Get("/users/{id}/sessions", apihandlers.HandleAPIUserSessionsGet(s.database))
		r.Get("/user-sessions/{sessionIdentifier}", apihandlers.HandleAPIUserSessionGet(s.database))
		r.Put("/user-sessions/{sessionIdentifier}", apihandlers.HandleAPIUserSessionPut(s.database))
		r.Delete("/user-sessions/{id}", apihandlers.HandleAPIUserSessionDelete(s.database, authHelper, auditLogger))

		// User consent routes
		r.Get("/users/{id}/consents", apihandlers.HandleAPIUserConsentsGet(httpHelper, s.database))
		r.Delete("/user-consents/{id}", apihandlers.HandleAPIUserConsentDelete(httpHelper, s.database, auditLogger))

		// Group management routes
		r.Get("/groups", apihandlers.HandleAPIGroupsGet(httpHelper, s.database))
		r.Post("/groups", apihandlers.HandleAPIGroupCreatePost(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
		r.Get("/groups/{id}", apihandlers.HandleAPIGroupGet(httpHelper, s.database))
		r.Put("/groups/{id}", apihandlers.HandleAPIGroupUpdatePut(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
		r.Delete("/groups/{id}", apihandlers.HandleAPIGroupDelete(httpHelper, authHelper, s.database, auditLogger))
		r.Get("/groups/{id}/members", apihandlers.HandleAPIGroupMembersGet(httpHelper, s.database))
		r.Post("/groups/{id}/members", apihandlers.HandleAPIGroupMemberAddPost(httpHelper, authHelper, s.database, auditLogger))
		r.Delete("/groups/{id}/members/{userId}", apihandlers.HandleAPIGroupMemberDelete(httpHelper, authHelper, s.database, auditLogger))
		r.Get("/users/{id}/groups", apihandlers.HandleAPIUserGroupsGet(httpHelper, s.database))
		r.Put("/users/{id}/groups", apihandlers.HandleAPIUserGroupsPut(httpHelper, s.database, authHelper, auditLogger))

		// Group search (annotated with permission)
		r.Get("/groups/search", apihandlers.HandleAPIGroupsSearchGet(s.database))

		// Group attributes routes
		r.Get("/groups/{id}/attributes", apihandlers.HandleAPIGroupAttributesGet(httpHelper, s.database))
		r.Post("/group-attributes", apihandlers.HandleAPIGroupAttributeCreatePost(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
		r.Get("/group-attributes/{id}", apihandlers.HandleAPIGroupAttributeGet(httpHelper, s.database))
		r.Put("/group-attributes/{id}", apihandlers.HandleAPIGroupAttributeUpdatePut(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
		r.Delete("/group-attributes/{id}", apihandlers.HandleAPIGroupAttributeDelete(httpHelper, authHelper, s.database, auditLogger))

		// User permissions routes
		r.Get("/users/{id}/permissions", apihandlers.HandleAPIUserPermissionsGet(s.database))
		r.Put("/users/{id}/permissions", apihandlers.HandleAPIUserPermissionsPut(s.database, authHelper, auditLogger))

		// Group permissions routes
		r.Get("/groups/{id}/permissions", apihandlers.HandleAPIGroupPermissionsGet(s.database))
		r.Put("/groups/{id}/permissions", apihandlers.HandleAPIGroupPermissionsPut(s.database, authHelper, auditLogger))

		// Users with a permission
		r.Get("/permissions/{permissionId}/users", apihandlers.HandleAPIPermissionUsersGet(s.database))

        // Resources routes
        r.Get("/resources", apihandlers.HandleAPIResourcesGet(s.database))
        r.Post("/resources", apihandlers.HandleAPIResourceCreatePost(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
        r.Get("/resources/{id}", apihandlers.HandleAPIResourceGet(httpHelper, s.database))
        r.Put("/resources/{id}", apihandlers.HandleAPIResourceUpdatePut(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
        r.Delete("/resources/{id}", apihandlers.HandleAPIResourceDelete(httpHelper, authHelper, s.database, auditLogger))
        r.Get("/resources/{resourceId}/permissions", apihandlers.HandleAPIPermissionsByResourceGet(s.database))
        r.Put("/resources/{resourceId}/permissions", apihandlers.HandleAPIResourcePermissionsPut(s.database, authHelper, identifierValidator, inputSanitizer, auditLogger))

        // Client management routes
        r.Get("/clients", apihandlers.HandleAPIClientsGet(httpHelper, s.database))
        r.Get("/clients/{id}", apihandlers.HandleAPIClientGet(httpHelper, s.database))
        r.Get("/clients/{id}/sessions", apihandlers.HandleAPIClientSessionsGet(s.database))
        r.Post("/clients", apihandlers.HandleAPIClientCreatePost(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
        r.Put("/clients/{id}", apihandlers.HandleAPIClientUpdatePut(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
        r.Put("/clients/{id}/authentication", apihandlers.HandleAPIClientAuthenticationPut(httpHelper, authHelper, s.database, auditLogger))
        r.Put("/clients/{id}/oauth2-flows", apihandlers.HandleAPIClientOAuth2FlowsPut(httpHelper, authHelper, s.database, auditLogger))
        r.Put("/clients/{id}/redirect-uris", apihandlers.HandleAPIClientRedirectURIsPut(httpHelper, authHelper, s.database, auditLogger))
        r.Put("/clients/{id}/web-origins", apihandlers.HandleAPIClientWebOriginsPut(httpHelper, authHelper, s.database, auditLogger))
        r.Put("/clients/{id}/tokens", apihandlers.HandleAPIClientTokensPut(httpHelper, authHelper, s.database, auditLogger))
        r.Get("/clients/{id}/permissions", apihandlers.HandleAPIClientPermissionsGet(s.database))
        r.Put("/clients/{id}/permissions", apihandlers.HandleAPIClientPermissionsPut(s.database, authHelper, auditLogger))
        r.Delete("/clients/{id}", apihandlers.HandleAPIClientDelete(httpHelper, authHelper, s.database, auditLogger))


			// Settings - General
			r.Get("/settings/general", apihandlers.HandleAPISettingsGeneralGet(httpHelper))
			r.Put("/settings/general", apihandlers.HandleAPISettingsGeneralPut(httpHelper, authHelper, s.database, inputSanitizer, auditLogger))

			// Settings - Email
			r.Get("/settings/email", apihandlers.HandleAPISettingsEmailGet(httpHelper))
			r.Put("/settings/email", apihandlers.HandleAPISettingsEmailPut(httpHelper, authHelper, s.database, inputSanitizer, emailValidator, auditLogger))
			r.Post("/settings/email/send-test", apihandlers.HandleAPISettingsEmailSendTestPost(httpHelper, emailValidator, emailSender, authHelper, auditLogger))

            // Settings - Sessions
            r.Get("/settings/sessions", apihandlers.HandleAPISettingsSessionsGet(httpHelper))
            r.Put("/settings/sessions", apihandlers.HandleAPISettingsSessionsPut(httpHelper, authHelper, s.database, auditLogger))

            // Settings - UI Theme
            r.Get("/settings/ui-theme", apihandlers.HandleAPISettingsUIThemeGet(httpHelper))
            r.Put("/settings/ui-theme", apihandlers.HandleAPISettingsUIThemePut(httpHelper, authHelper, s.database, auditLogger))

            // Settings - Tokens
            r.Get("/settings/tokens", apihandlers.HandleAPISettingsTokensGet(httpHelper))
            r.Put("/settings/tokens", apihandlers.HandleAPISettingsTokensPut(httpHelper, authHelper, s.database, auditLogger))

            // Settings - Keys
            r.Get("/settings/keys", apihandlers.HandleAPISettingsKeysGet(httpHelper, s.database))
            r.Post("/settings/keys/rotate", apihandlers.HandleAPISettingsKeysRotatePost(authHelper, s.database, auditLogger))
            r.Delete("/settings/keys/{id}", apihandlers.HandleAPISettingsKeyDelete(authHelper, s.database, auditLogger))

		// Reference data routes
		r.Get("/phone-countries", apihandlers.HandleAPIPhoneCountriesGet())
	})

    // Account API routes (self-service)
    s.router.Route("/api/v1/account", func(r chi.Router) {
        r.Use(middleware.APIDebugMiddleware())
        r.Use(authHeaderToContext)
        r.Use(middleware.RequireBearerTokenScope(constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier))

        r.Get("/profile", apihandlers.HandleAPIAccountProfileGet(s.database))
        r.Put("/profile", apihandlers.HandleAPIAccountProfilePut(s.database, profileValidator, inputSanitizer, auditLogger))
        r.Put("/email", apihandlers.HandleAPIAccountEmailPut(s.database, emailValidator, inputSanitizer, auditLogger))
        r.Post("/email/verification/send", apihandlers.HandleAPIAccountEmailVerificationSendPost(httpHelper, s.database, emailSender, auditLogger))
        r.Post("/email/verification", apihandlers.HandleAPIAccountEmailVerificationPost(s.database, auditLogger))
        r.Put("/phone", apihandlers.HandleAPIAccountPhonePut(s.database, phoneValidator, inputSanitizer, auditLogger))
        r.Put("/address", apihandlers.HandleAPIAccountAddressPut(s.database, addressValidator, inputSanitizer, auditLogger))
        r.Put("/password", apihandlers.HandleAPIAccountPasswordPut(s.database, passwordValidator, auditLogger))
        r.Get("/otp/enrollment", apihandlers.HandleAPIAccountOTPEnrollmentGet(s.database, otpSecretGenerator))
        r.Put("/otp", apihandlers.HandleAPIAccountOTPPut(s.database, auditLogger))
        r.Get("/consents", apihandlers.HandleAPIAccountConsentsGet(httpHelper, s.database))
        r.Delete("/consents/{id}", apihandlers.HandleAPIAccountConsentDelete(httpHelper, s.database, auditLogger))

        // Sessions (self-service)
        r.Get("/sessions", apihandlers.HandleAPIAccountSessionsGet(s.database))
        r.Delete("/sessions/{id}", apihandlers.HandleAPIAccountSessionDelete(s.database, authHelper, auditLogger))

        // Logout request (self-service)
        r.Post("/logout-request", apihandlers.HandleAPIAccountLogoutRequestPost(httpHelper, s.database))
    })
}
