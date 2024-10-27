package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/core/audit"
	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/middleware"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/otp"
	"github.com/leodip/goiabada/core/user"
	"github.com/leodip/goiabada/core/validators"
)

func (s *Server) initRoutes() {

	auditLogger := audit.NewAuditLogger()
	authorizeValidator := validators.NewAuthorizeValidator(s.database)
	tokenParser := oauth.NewTokenParser(s.database)
	permissionChecker := user.NewPermissionChecker(s.database)
	tokenValidator := validators.NewTokenValidator(s.database, tokenParser, permissionChecker, auditLogger)
	emailValidator := validators.NewEmailValidator(s.database)
	passwordValidator := validators.NewPasswordValidator()

	codeIssuer := oauth.NewCodeIssuer(s.database)
	userSessionManager := user.NewUserSessionManager(codeIssuer, s.sessionStore, s.database)
	otpSecretGenerator := otp.NewOTPSecretGenerator()
	tokenIssuer := oauth.NewTokenIssuer(s.database, tokenParser)
	userCreator := user.NewUserCreator(s.database)
	emailSender := communication.NewEmailSender()

	httpHelper := handlerhelpers.NewHttpHelper(s.templateFS, s.database)
	authHelper := handlerhelpers.NewAuthHelper(s.sessionStore)

	middlewareJwt := middleware.NewMiddlewareJwt(s.sessionStore, tokenParser, s.database, authHelper, &http.Client{})
	authHeaderToContext := middlewareJwt.JwtAuthorizationHeaderToContext()

	rateLimiter := middleware.NewRateLimiterMiddleware(authHelper)

	s.router.NotFound(handlers.HandleNotFoundGet(httpHelper))
	s.router.Get("/", handlers.HandleIndexGet(httpHelper))
	s.router.Get("/unauthorized", handlers.HandleUnauthorizedGet(httpHelper))
	s.router.Get("/.well-known/openid-configuration", handlers.HandleWellKnownOIDCConfigGet(httpHelper))
	s.router.Get("/certs", handlers.HandleCertsGet(httpHelper, s.database))
	s.router.With(authHeaderToContext).Get("/userinfo", handlers.HandleUserInfoGetPost(httpHelper, s.database, auditLogger))
	s.router.With(authHeaderToContext).Post("/userinfo", handlers.HandleUserInfoGetPost(httpHelper, s.database, auditLogger))
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
}
