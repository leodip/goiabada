package server

import (
	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/communication"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/authserver/internal/handlers/handlerhelpers"
	"github.com/leodip/goiabada/authserver/internal/oauth"
	"github.com/leodip/goiabada/authserver/internal/otp"
	"github.com/leodip/goiabada/authserver/internal/users"
	"github.com/leodip/goiabada/authserver/internal/validators"
)

func (s *Server) initRoutes() {

	authorizeValidator := validators.NewAuthorizeValidator(s.database)
	tokenParser := oauth.NewTokenParser(s.database)
	permissionChecker := users.NewPermissionChecker(s.database)
	tokenValidator := validators.NewTokenValidator(s.database, tokenParser, permissionChecker)
	emailValidator := validators.NewEmailValidator(s.database)
	passwordValidator := validators.NewPasswordValidator()

	codeIssuer := oauth.NewCodeIssuer(s.database)
	userSessionManager := users.NewUserSessionManager(codeIssuer, s.sessionStore, s.database)
	otpSecretGenerator := otp.NewOTPSecretGenerator()
	tokenIssuer := oauth.NewTokenIssuer(s.database, tokenParser)
	userCreator := users.NewUserCreator(s.database)
	emailSender := communication.NewEmailSender()

	httpHelper := handlerhelpers.NewHttpHelper(s.templateFS, s.database)
	authHelper := handlerhelpers.NewAuthHelper(s.sessionStore)

	middlewareJwt := NewMiddlewareJwt(tokenParser)
	authHeaderToContext := middlewareJwt.JwtAuthorizationHeaderToContext()

	s.router.NotFound(handlers.HandleNotFoundGet(httpHelper))
	s.router.Get("/", handlers.HandleIndexGet(httpHelper))
	s.router.Get("/unauthorized", handlers.HandleUnauthorizedGet(httpHelper))
	s.router.Get("/.well-known/openid-configuration", handlers.HandleWellKnownOIDCConfigGet(httpHelper))
	s.router.Get("/certs", handlers.HandleCertsGet(httpHelper, s.database))
	s.router.With(authHeaderToContext).Get("/userinfo", handlers.HandleUserInfoGetPost(httpHelper, s.database))
	s.router.With(authHeaderToContext).Post("/userinfo", handlers.HandleUserInfoGetPost(httpHelper, s.database))
	s.router.Get("/health", handlers.HandleHealthCheckGet(httpHelper))
	s.router.Get("/test", handlers.HandleRequestTestGet(httpHelper))

	s.router.Route("/auth", func(r chi.Router) {
		r.Get("/authorize", handlers.HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, s.database, s.templateFS, authorizeValidator))
		r.Get("/pwd", handlers.HandleAuthPwdGet(httpHelper, authHelper, s.database))
		r.Post("/pwd", handlers.HandleAuthPwdPost(httpHelper, authHelper, userSessionManager, s.database))
		r.Get("/otp", handlers.HandleAuthOtpGet(httpHelper, s.sessionStore, authHelper, s.database, otpSecretGenerator))
		r.Post("/otp", handlers.HandleAuthOtpPost(httpHelper, s.sessionStore, authHelper, userSessionManager, s.database))
		r.Get("/consent", handlers.HandleConsentGet(httpHelper, authHelper, s.database, s.templateFS, codeIssuer, permissionChecker))
		r.Post("/consent", handlers.HandleConsentPost(httpHelper, authHelper, s.database, s.templateFS, codeIssuer))
		r.Post("/token", handlers.HandleTokenPost(httpHelper, userSessionManager, s.database, tokenIssuer, tokenValidator))
		r.Get("/logout", handlers.HandleAccountLogoutGet(httpHelper, s.sessionStore, authHelper, s.database, tokenParser))
		r.Post("/logout", handlers.HandleAccountLogoutPost(httpHelper, s.sessionStore, authHelper, s.database))
	})

	s.router.Route("/account", func(r chi.Router) {
		r.Get("/register", accounthandlers.HandleAccountRegisterGet(httpHelper))
		r.Post("/register", accounthandlers.HandleAccountRegisterPost(httpHelper, s.database, userCreator, emailValidator, passwordValidator, emailSender))
		r.Get("/activate", accounthandlers.HandleAccountActivateGet(httpHelper, s.database, userCreator))
	})
}
