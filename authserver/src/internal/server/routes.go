package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/internal/core"
	core_account "github.com/leodip/goiabada/internal/core/account"
	core_admin "github.com/leodip/goiabada/internal/core/admin"
	core_authorize "github.com/leodip/goiabada/internal/core/authorize"
	core_token "github.com/leodip/goiabada/internal/core/token"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) initRoutes() {

	authorizeValidator := core_authorize.NewAuthorizeValidator(s.database)
	tokenValidator := core_token.NewTokenValidator(s.database)
	profileValidator := core_account.NewProfileValidator(s.database)
	emailValidator := core_account.NewEmailValidator(s.database)
	addressValidator := core_account.NewAddressValidator(s.database)
	phoneValidator := core_account.NewPhoneValidator(s.database)
	passwordValidator := core.NewPasswordValidator()
	identifierValidator := core_admin.NewIdentifierValidator(s.database)
	inputSanitizer := core.NewInputSanitizer()

	codeIssuer := core_authorize.NewCodeIssuer(s.database)
	loginManager := core_authorize.NewLoginManager(codeIssuer)
	otpSecretGenerator := core.NewOTPSecretGenerator()
	tokenIssuer := core_token.NewTokenIssuer()
	emailSender := core.NewEmailSender(s.database)
	smsSender := core.NewSMSSender(s.database)

	s.router.Get("/", s.handleIndexGet())
	s.router.Get("/unauthorized", s.handleUnauthorizedGet())
	s.router.Get("/forgot-password", s.handleForgotPasswordGet())
	s.router.Post("/forgot-password", s.handleForgotPasswordPost(emailSender))
	s.router.Get("/reset-password", s.handleResetPasswordGet())
	s.router.Post("/reset-password", s.handleResetPasswordPost(passwordValidator))

	s.router.Route("/auth", func(r chi.Router) {
		r.Get("/authorize", s.handleAuthorizeGet(authorizeValidator, codeIssuer, loginManager))
		r.Get("/pwd", s.handleAuthPwdGet())
		r.Post("/pwd", s.handleAuthPwdPost(authorizeValidator, loginManager))
		r.Get("/otp", s.handleAuthOtpGet(otpSecretGenerator))
		r.Post("/otp", s.handleAuthOtpPost())
		r.Get("/consent", s.handleConsentGet(codeIssuer))
		r.Post("/consent", s.handleConsentPost(codeIssuer))
		r.Post("/token", s.handleTokenPost(tokenIssuer, tokenValidator))
		r.Post("/callback", s.handleAuthCallbackPost(tokenIssuer, tokenValidator))
		r.Get("/logout", s.handleAccountLogoutGet())
	})
	s.router.Route("/account", func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, lib.GetBaseUrl()+"/account/profile", http.StatusFound)
		})
		r.Get("/profile", s.withJwt(s.handleAccountProfileGet()))
		r.Post("/profile", s.withJwt(s.handleAccountProfilePost(profileValidator, inputSanitizer)))
		r.Get("/email", s.withJwt(s.handleAccountEmailGet()))
		r.Post("/email", s.withJwt(s.handleAccountEmailPost(emailValidator, emailSender)))
		r.Post("/email-send-verification", s.withJwt(s.handleAccountEmailSendVerificationPost(emailSender)))
		r.Get("/email-verify", s.withJwt(s.handleAccountEmailVerifyGet()))
		r.Get("/address", s.withJwt(s.handleAccountAddressGet()))
		r.Post("/address", s.withJwt(s.handleAccountAddressPost(addressValidator, inputSanitizer)))
		r.Get("/phone", s.withJwt(s.handleAccountPhoneGet()))
		r.Post("/phone", s.withJwt(s.handleAccountPhonePost(phoneValidator)))
		r.Post("/phone-send-verification", s.withJwt(s.handleAccountPhoneSendVerificationPost(smsSender)))
		r.Get("/phone-verify", s.withJwt(s.handleAccountPhoneVerifyGet()))
		r.Post("/phone-verify", s.withJwt(s.handleAccountPhoneVerifyPost()))
		r.Get("/change-password", s.withJwt(s.handleAccountChangePasswordGet()))
		r.Post("/change-password", s.withJwt(s.handleAccountChangePasswordPost(passwordValidator)))
		r.Get("/otp", s.withJwt(s.handleAccountOtpGet(otpSecretGenerator)))
		r.Post("/otp", s.withJwt(s.handleAccountOtpPost()))
		r.Get("/manage-consents", s.withJwt(s.handleAccountManageConsentsGet()))
		r.Post("/manage-consents", s.withJwt(s.handleAccountManageConsentsRevokePost()))
		r.Get("/sessions", s.withJwt(s.handleAccountSessionsGet()))
		r.Post("/sessions", s.withJwt(s.handleAccountSessionsEndSesssionPost()))
		r.Get("/register", s.handleAccountRegisterGet())
		r.Post("/register", s.handleAccountRegisterPost(emailValidator, passwordValidator, emailSender))
		r.Get("/activate", s.handleAccountActivateGet(emailSender))
	})

	s.router.Route("/admin", func(r chi.Router) {
		r.Get("/clients", s.withJwt(s.handleAdminClientsGet()))
		r.Get("/clients/{clientId}/settings", s.withJwt(s.handleAdminClientSettingsGet()))
		r.Post("/clients/{clientId}/settings", s.withJwt(s.handleAdminClientSettingsPost(identifierValidator, inputSanitizer)))
		r.Get("/clients/{clientId}/authentication", s.withJwt(s.handleAdminClientAuthenticationGet()))
		r.Post("/clients/{clientId}/authentication", s.withJwt(s.handleAdminClientAuthenticationPost()))
		r.Get("/clients/{clientId}/oauth2-flows", s.withJwt(s.handleAdminClientOAuth2Get()))
		r.Post("/clients/{clientId}/oauth2-flows", s.withJwt(s.handleAdminClientOAuth2Post()))
		r.Get("/clients/{clientId}/redirect-uris", s.withJwt(s.handleAdminClientRedirectURIsGet()))
		r.Post("/clients/{clientId}/redirect-uris", s.withJwt(s.handleAdminClientRedirectURIsPost()))
		r.Get("/clients/{clientId}/permissions", s.withJwt(s.handleAdminClientPermissionsGet()))
		r.Post("/clients/{clientId}/permissions", s.withJwt(s.handleAdminClientPermissionsPost()))
		r.Get("/clients/generate-new-secret", s.withJwt(s.handleAdminClientGenerateNewSecretGet()))
		r.Get("/clients/get-permissions", s.withJwt(s.handleAdminClientGetPermissionsGet()))
		r.Get("/clients/{clientId}/delete", s.withJwt(s.handleAdminClientDeleteGet()))
		r.Post("/clients/{clientId}/delete", s.withJwt(s.handleAdminClientDeletePost()))
		r.Get("/clients/new", s.withJwt(s.handleAdminClientAddNewGet()))
		r.Post("/clients/new", s.withJwt(s.handleAdminClientAddNewPost(identifierValidator)))

		r.Get("/resources", s.withJwt(s.handleAdminResourcesGet()))
		r.Get("/resources/{resourceId}/settings", s.withJwt(s.handleAdminResourceSettingsGet()))
		r.Post("/resources/{resourceId}/settings", s.withJwt(s.handleAdminResourceSettingsPost(identifierValidator, inputSanitizer)))
		r.Get("/resources/{resourceId}/permissions", s.withJwt(s.handleAdminResourcePermissionsGet()))
		r.Post("/resources/{resourceId}/permissions", s.withJwt(s.handleAdminResourcePermissionsPost(identifierValidator, inputSanitizer)))
		r.Post("/resources/validate-permission", s.withJwt(s.handleAdminResourceValidatePermissionPost(identifierValidator, inputSanitizer)))
		r.Get("/resources/{resourceId}/delete", s.withJwt(s.handleAdminResourceDeleteGet()))
		r.Post("/resources/{resourceId}/delete", s.withJwt(s.handleAdminResourceDeletePost()))
		r.Get("/resources/new", s.withJwt(s.handleAdminResourceAddNewGet()))
		r.Post("/resources/new", s.withJwt(s.handleAdminResourceAddNewPost(identifierValidator, inputSanitizer)))

		r.Get("/roles", s.withJwt(s.handleAdminRolesGet()))
		r.Get("/roles/{roleId}/settings", s.withJwt(s.handleAdminRoleSettingsGet()))
		r.Post("/roles/{roleId}/settings", s.withJwt(s.handleAdminRoleSettingsPost(identifierValidator, inputSanitizer)))
		r.Get("/roles/{roleId}/users-in-role", s.withJwt(s.handleAdminRoleUsersInRoleGet()))
		r.Get("/roles/{roleId}/users-in-role/add", s.withJwt(s.handleAdminRoleUsersInRoleAddGet()))
		r.Post("/roles/{roleId}/users-in-role/add", s.withJwt(s.handleAdminRoleUsersInRoleAddPost()))
		r.Post("/roles/{roleId}/users-in-role/remove/{userId}", s.withJwt(s.handleAdminRoleUsersInRoleRemoveUserPost()))
		r.Get("/roles/{roleId}/users-in-role/search", s.withJwt(s.handleAdminRoleUsersInRoleSearchGet()))
	})
}

func (s *Server) withJwt(handlerFunc http.HandlerFunc) http.HandlerFunc {
	return MiddlewareJwt(handlerFunc, s.database, s.sessionStore, s.tokenValidator)
}
