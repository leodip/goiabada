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
		r.Use(authHeaderToContext)
		r.Use(middleware.RequireBearerTokenScope(constants.AdminConsoleResourceIdentifier + ":" + constants.ManageAdminConsolePermissionIdentifier))

		// User management routes
		r.Get("/users/search", apihandlers.HandleAPIUsersSearchGet(httpHelper, s.database))
		r.Get("/users/{id}", apihandlers.HandleAPIUserGet(httpHelper, s.database))
		r.Put("/users/{id}/enabled", apihandlers.HandleAPIUserEnabledPut(httpHelper, s.database, authHelper, auditLogger))
		r.Put("/users/{id}/profile", apihandlers.HandleAPIUserProfilePut(httpHelper, s.database, profileValidator, inputSanitizer, auditLogger))
		r.Put("/users/{id}/address", apihandlers.HandleAPIUserAddressPut(httpHelper, s.database, addressValidator, inputSanitizer, auditLogger))
		r.Put("/users/{id}/email", apihandlers.HandleAPIUserEmailPut(httpHelper, s.database, emailValidator, inputSanitizer, auditLogger))
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
		r.Get("/user-sessions/{sessionIdentifier}", apihandlers.HandleAPIUserSessionGet(httpHelper, s.database))
		r.Put("/user-sessions/{sessionIdentifier}", apihandlers.HandleAPIUserSessionPut(httpHelper, s.database))

		// User consent routes
		r.Get("/users/{id}/consents", apihandlers.HandleAPIUserConsentsGet(httpHelper, s.database))
		r.Delete("/user-consents/{id}", apihandlers.HandleAPIUserConsentDelete(httpHelper, s.database, auditLogger))

		// Group management routes
		r.Get("/groups", apihandlers.HandleAPIGroupsGet(httpHelper, s.database))
		r.Get("/users/{id}/groups", apihandlers.HandleAPIUserGroupsGet(httpHelper, s.database))
		r.Put("/users/{id}/groups", apihandlers.HandleAPIUserGroupsPut(httpHelper, s.database, authHelper, auditLogger))
	})
}
