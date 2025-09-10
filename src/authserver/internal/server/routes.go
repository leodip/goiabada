package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/audit"
	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/inputsanitizer"
	core_middleware "github.com/leodip/goiabada/core/middleware"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/otp"
	"github.com/leodip/goiabada/core/user"
	"github.com/leodip/goiabada/core/validators"
)

func (s *Server) initRoutes() {

	auditLogger := audit.NewAuditLogger(s.auditLogsInConsole)
	authorizeValidator := validators.NewAuthorizeValidator(s.database)
	tokenParser := oauth.NewTokenParser(s.database)
	permissionChecker := user.NewPermissionChecker(s.database)
	tokenValidator := validators.NewTokenValidator(s.database, tokenParser, permissionChecker, auditLogger)
	emailValidator := validators.NewEmailValidator(s.database)
	passwordValidator := validators.NewPasswordValidator()
	profileValidator := validators.NewProfileValidator(s.database)
	addressValidator := validators.NewAddressValidator(s.database)
	phoneValidator := validators.NewPhoneValidator(s.database)
	identifierValidator := validators.NewIdentifierValidator(s.database)
	inputSanitizer := inputsanitizer.NewInputSanitizer()

	codeIssuer := oauth.NewCodeIssuer(s.database)
	userSessionManager := user.NewUserSessionManager(codeIssuer, s.sessionStore, s.database)
	otpSecretGenerator := otp.NewOTPSecretGenerator()
	tokenIssuer := oauth.NewTokenIssuer(s.database, tokenParser, s.baseURL)
	userCreator := user.NewUserCreator(s.database)
	emailSender := communication.NewEmailSender()

	httpHelper := handlerhelpers.NewHttpHelper(s.templateFS, s.database)
	authHelper := handlerhelpers.NewAuthHelper(s.sessionStore, s.baseURL, s.adminConsoleBaseURL)

	middlewareJwt := core_middleware.NewMiddlewareJwt(s.sessionStore, tokenParser, s.database, authHelper, &http.Client{}, s.baseURL, s.adminConsoleBaseURL)
	authHeaderToContext := middlewareJwt.JwtAuthorizationHeaderToContext()

	rateLimiter := core_middleware.NewRateLimiterMiddleware(authHelper)

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
		r.Use(middleware.RequireBearerTokenScope(constants.AdminConsoleResourceIdentifier + ":" + constants.ManageAdminConsolePermissionIdentifier))

		// User management routes
		r.Get("/users/search", apihandlers.HandleAPIUsersSearchGet(httpHelper, s.database))
		r.Get("/users/{id}", apihandlers.HandleAPIUserGet(httpHelper, s.database))
		r.Put("/users/{id}/enabled", apihandlers.HandleAPIUserEnabledPut(httpHelper, s.database, authHelper, auditLogger))
		r.Put("/users/{id}/profile", apihandlers.HandleAPIUserProfilePut(httpHelper, s.database, profileValidator, inputSanitizer, auditLogger))
		r.Put("/users/{id}/address", apihandlers.HandleAPIUserAddressPut(httpHelper, s.database, addressValidator, inputSanitizer, auditLogger))
		r.Put("/users/{id}/email", apihandlers.HandleAPIUserEmailPut(httpHelper, s.database, emailValidator, inputSanitizer, auditLogger))
		r.Put("/users/{id}/phone", apihandlers.HandleAPIUserPhonePut(httpHelper, s.database, phoneValidator, inputSanitizer, auditLogger))
		r.Put("/users/{id}/password", apihandlers.HandleAPIUserPasswordPut(httpHelper, s.database, passwordValidator, authHelper, auditLogger))
		r.Put("/users/{id}/otp", apihandlers.HandleAPIUserOTPPut(httpHelper, s.database, auditLogger))
		r.Post("/users/create", apihandlers.HandleAPIUserCreatePost(httpHelper, s.database, userCreator, emailValidator, profileValidator, passwordValidator, authHelper, auditLogger, emailSender))
		r.Delete("/users/{id}", apihandlers.HandleAPIUserDelete(httpHelper, s.database, authHelper, auditLogger))

		// User attributes routes
		r.Get("/users/{id}/attributes", apihandlers.HandleAPIUserAttributesGet(httpHelper, s.database))
		r.Get("/user-attributes/{id}", apihandlers.HandleAPIUserAttributeGet(httpHelper, s.database))
		r.Post("/user-attributes", apihandlers.HandleAPIUserAttributeCreatePost(httpHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
		r.Put("/user-attributes/{id}", apihandlers.HandleAPIUserAttributeUpdatePut(httpHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
		r.Delete("/user-attributes/{id}", apihandlers.HandleAPIUserAttributeDelete(httpHelper, s.database, auditLogger))

		// User session routes
		r.Get("/users/{id}/sessions", apihandlers.HandleAPIUserSessionsGet(httpHelper, s.database))
		r.Get("/user-sessions/{sessionIdentifier}", apihandlers.HandleAPIUserSessionGet(httpHelper, s.database))
		r.Put("/user-sessions/{sessionIdentifier}", apihandlers.HandleAPIUserSessionPut(httpHelper, s.database))
		r.Delete("/user-sessions/{id}", apihandlers.HandleAPIUserSessionDelete(httpHelper, s.database, authHelper, auditLogger))

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
		r.Get("/groups/search", apihandlers.HandleAPIGroupsSearchGet(httpHelper, s.database))

		// Group attributes routes
		r.Get("/groups/{id}/attributes", apihandlers.HandleAPIGroupAttributesGet(httpHelper, s.database))
		r.Post("/group-attributes", apihandlers.HandleAPIGroupAttributeCreatePost(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
		r.Get("/group-attributes/{id}", apihandlers.HandleAPIGroupAttributeGet(httpHelper, s.database))
		r.Put("/group-attributes/{id}", apihandlers.HandleAPIGroupAttributeUpdatePut(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
		r.Delete("/group-attributes/{id}", apihandlers.HandleAPIGroupAttributeDelete(httpHelper, authHelper, s.database, auditLogger))

		// User permissions routes
		r.Get("/users/{id}/permissions", apihandlers.HandleAPIUserPermissionsGet(httpHelper, s.database))
		r.Put("/users/{id}/permissions", apihandlers.HandleAPIUserPermissionsPut(httpHelper, s.database, authHelper, auditLogger))

		// Group permissions routes
		r.Get("/groups/{id}/permissions", apihandlers.HandleAPIGroupPermissionsGet(httpHelper, s.database))
		r.Put("/groups/{id}/permissions", apihandlers.HandleAPIGroupPermissionsPut(httpHelper, s.database, authHelper, auditLogger))

		// Users with a permission
		r.Get("/permissions/{permissionId}/users", apihandlers.HandleAPIPermissionUsersGet(httpHelper, s.database))

        // Resources routes
        r.Get("/resources", apihandlers.HandleAPIResourcesGet(httpHelper, s.database))
        r.Post("/resources", apihandlers.HandleAPIResourceCreatePost(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
        r.Get("/resources/{id}", apihandlers.HandleAPIResourceGet(httpHelper, s.database))
        r.Put("/resources/{id}", apihandlers.HandleAPIResourceUpdatePut(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
        r.Delete("/resources/{id}", apihandlers.HandleAPIResourceDelete(httpHelper, authHelper, s.database, auditLogger))
        r.Get("/resources/{resourceId}/permissions", apihandlers.HandleAPIPermissionsByResourceGet(httpHelper, s.database))
        r.Put("/resources/{resourceId}/permissions", apihandlers.HandleAPIResourcePermissionsPut(httpHelper, s.database, authHelper, identifierValidator, inputSanitizer, auditLogger))

        // Client management routes
        r.Get("/clients", apihandlers.HandleAPIClientsGet(httpHelper, s.database))
        r.Get("/clients/{id}", apihandlers.HandleAPIClientGet(httpHelper, s.database))
        r.Get("/clients/{id}/sessions", apihandlers.HandleAPIClientSessionsGet(httpHelper, s.database))
        r.Post("/clients", apihandlers.HandleAPIClientCreatePost(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
        r.Put("/clients/{id}", apihandlers.HandleAPIClientUpdatePut(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer, auditLogger))
        r.Put("/clients/{id}/authentication", apihandlers.HandleAPIClientAuthenticationPut(httpHelper, authHelper, s.database, auditLogger))
        r.Put("/clients/{id}/oauth2-flows", apihandlers.HandleAPIClientOAuth2FlowsPut(httpHelper, authHelper, s.database, auditLogger))
        r.Put("/clients/{id}/redirect-uris", apihandlers.HandleAPIClientRedirectURIsPut(httpHelper, authHelper, s.database, auditLogger))
        r.Put("/clients/{id}/web-origins", apihandlers.HandleAPIClientWebOriginsPut(httpHelper, authHelper, s.database, auditLogger))
        r.Put("/clients/{id}/tokens", apihandlers.HandleAPIClientTokensPut(httpHelper, authHelper, s.database, auditLogger))
        r.Get("/clients/{id}/permissions", apihandlers.HandleAPIClientPermissionsGet(httpHelper, s.database))
        r.Put("/clients/{id}/permissions", apihandlers.HandleAPIClientPermissionsPut(httpHelper, s.database, authHelper, auditLogger))
        r.Delete("/clients/{id}", apihandlers.HandleAPIClientDelete(httpHelper, authHelper, s.database, auditLogger))


			// Settings - General
			r.Get("/settings/general", apihandlers.HandleAPISettingsGeneralGet(httpHelper, s.database))
			r.Put("/settings/general", apihandlers.HandleAPISettingsGeneralPut(httpHelper, authHelper, s.database, inputSanitizer, auditLogger))

			// Settings - Email
			r.Get("/settings/email", apihandlers.HandleAPISettingsEmailGet(httpHelper, s.database))
			r.Put("/settings/email", apihandlers.HandleAPISettingsEmailPut(httpHelper, authHelper, s.database, inputSanitizer, emailValidator, auditLogger))
			r.Post("/settings/email/send-test", apihandlers.HandleAPISettingsEmailSendTestPost(httpHelper, s.database, emailValidator, emailSender, authHelper, auditLogger))

            // Settings - Sessions
            r.Get("/settings/sessions", apihandlers.HandleAPISettingsSessionsGet(httpHelper, s.database))
            r.Put("/settings/sessions", apihandlers.HandleAPISettingsSessionsPut(httpHelper, authHelper, s.database, auditLogger))

            // Settings - UI Theme
            r.Get("/settings/ui-theme", apihandlers.HandleAPISettingsUIThemeGet(httpHelper, s.database))
            r.Put("/settings/ui-theme", apihandlers.HandleAPISettingsUIThemePut(httpHelper, authHelper, s.database, auditLogger))

            // Settings - Tokens
            r.Get("/settings/tokens", apihandlers.HandleAPISettingsTokensGet(httpHelper, s.database))
            r.Put("/settings/tokens", apihandlers.HandleAPISettingsTokensPut(httpHelper, authHelper, s.database, auditLogger))

            // Settings - Keys
            r.Get("/settings/keys", apihandlers.HandleAPISettingsKeysGet(httpHelper, s.database))
            r.Post("/settings/keys/rotate", apihandlers.HandleAPISettingsKeysRotatePost(httpHelper, authHelper, s.database, auditLogger))
            r.Delete("/settings/keys/{id}", apihandlers.HandleAPISettingsKeyDelete(httpHelper, authHelper, s.database, auditLogger))

		// Reference data routes
		r.Get("/phone-countries", apihandlers.HandleAPIPhoneCountriesGet(httpHelper))
	})

    // Account API routes (self-service)
    s.router.Route("/api/v1/account", func(r chi.Router) {
        r.Use(middleware.APIDebugMiddleware())
        r.Use(authHeaderToContext)
        r.Use(middleware.RequireBearerTokenScope(constants.AdminConsoleResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier))

        r.Get("/profile", apihandlers.HandleAPIAccountProfileGet(httpHelper, s.database))
        r.Put("/profile", apihandlers.HandleAPIAccountProfilePut(httpHelper, s.database, profileValidator, inputSanitizer, auditLogger))
        r.Put("/email", apihandlers.HandleAPIAccountEmailPut(httpHelper, s.database, emailValidator, inputSanitizer, auditLogger))
        r.Post("/email/verification/send", apihandlers.HandleAPIAccountEmailVerificationSendPost(httpHelper, s.database, emailSender, auditLogger))
        r.Post("/email/verification", apihandlers.HandleAPIAccountEmailVerificationPost(httpHelper, s.database, auditLogger))
        r.Put("/phone", apihandlers.HandleAPIAccountPhonePut(httpHelper, s.database, phoneValidator, inputSanitizer, auditLogger))
        r.Put("/address", apihandlers.HandleAPIAccountAddressPut(httpHelper, s.database, addressValidator, inputSanitizer, auditLogger))
        r.Put("/password", apihandlers.HandleAPIAccountPasswordPut(httpHelper, s.database, passwordValidator, auditLogger))
        r.Get("/otp/enrollment", apihandlers.HandleAPIAccountOTPEnrollmentGet(httpHelper, s.database, otpSecretGenerator))
        r.Put("/otp", apihandlers.HandleAPIAccountOTPPut(httpHelper, s.database, auditLogger))
        r.Get("/consents", apihandlers.HandleAPIAccountConsentsGet(httpHelper, s.database))
        r.Delete("/consents/{id}", apihandlers.HandleAPIAccountConsentDelete(httpHelper, s.database, auditLogger))

        // Sessions (self-service)
        r.Get("/sessions", apihandlers.HandleAPIAccountSessionsGet(httpHelper, s.database))
        r.Delete("/sessions/{id}", apihandlers.HandleAPIAccountSessionDelete(httpHelper, s.database, authHelper, auditLogger))

        // Logout request (self-service)
        r.Post("/logout-request", apihandlers.HandleAPIAccountLogoutRequestPost(httpHelper, s.database))
    })
}
