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

	s.router.NotFound(s.handleNotFoundGet())
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
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, lib.GetBaseUrl()+"/account/profile", http.StatusFound)
		})
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Get("/profile", s.handleAccountProfileGet())
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Post("/profile", s.handleAccountProfilePost(profileValidator, inputSanitizer))
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Get("/email", s.handleAccountEmailGet())
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Post("/email", s.handleAccountEmailPost(emailValidator, emailSender))
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Post("/email-send-verification", s.handleAccountEmailSendVerificationPost(emailSender))
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Get("/email-verify", s.handleAccountEmailVerifyGet())
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Get("/address", s.handleAccountAddressGet())
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Post("/address", s.handleAccountAddressPost(addressValidator, inputSanitizer))
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Get("/phone", s.handleAccountPhoneGet())
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Post("/phone", s.handleAccountPhonePost(phoneValidator))
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Post("/phone-send-verification", s.handleAccountPhoneSendVerificationPost(smsSender))
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Get("/phone-verify", s.handleAccountPhoneVerifyGet())
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Post("/phone-verify", s.handleAccountPhoneVerifyPost())
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Get("/change-password", s.handleAccountChangePasswordGet())
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Post("/change-password", s.handleAccountChangePasswordPost(passwordValidator))
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Get("/otp", s.handleAccountOtpGet(otpSecretGenerator))
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Post("/otp", s.handleAccountOtpPost())
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Get("/manage-consents", s.handleAccountManageConsentsGet())
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Post("/manage-consents", s.handleAccountManageConsentsRevokePost())
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Get("/sessions", s.handleAccountSessionsGet())
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Post("/sessions", s.handleAccountSessionsEndSesssionPost())
		r.Get("/register", s.handleAccountRegisterGet())
		r.Post("/register", s.handleAccountRegisterPost(emailValidator, passwordValidator, emailSender))
		r.Get("/activate", s.handleAccountActivateGet(emailSender))
	})

	s.router.With(s.jwtSessionToContext).With(s.requiresAdminScope).Route("/admin", func(r chi.Router) {

		r.Get("/get-permissions", s.handleAdminGetPermissionsGet())

		r.Get("/clients", s.handleAdminClientsGet())
		r.Get("/clients/{clientId}/settings", s.handleAdminClientSettingsGet())
		r.Post("/clients/{clientId}/settings", s.handleAdminClientSettingsPost(identifierValidator, inputSanitizer))
		r.Get("/clients/{clientId}/authentication", s.handleAdminClientAuthenticationGet())
		r.Post("/clients/{clientId}/authentication", s.handleAdminClientAuthenticationPost())
		r.Get("/clients/{clientId}/oauth2-flows", s.handleAdminClientOAuth2Get())
		r.Post("/clients/{clientId}/oauth2-flows", s.handleAdminClientOAuth2Post())
		r.Get("/clients/{clientId}/redirect-uris", s.handleAdminClientRedirectURIsGet())
		r.Post("/clients/{clientId}/redirect-uris", s.handleAdminClientRedirectURIsPost())
		r.Get("/clients/{clientId}/permissions", s.handleAdminClientPermissionsGet())
		r.Post("/clients/{clientId}/permissions", s.handleAdminClientPermissionsPost())
		r.Get("/clients/generate-new-secret", s.handleAdminClientGenerateNewSecretGet())
		r.Get("/clients/{clientId}/delete", s.handleAdminClientDeleteGet())
		r.Post("/clients/{clientId}/delete", s.handleAdminClientDeletePost())
		r.Get("/clients/new", s.handleAdminClientAddNewGet())
		r.Post("/clients/new", s.handleAdminClientAddNewPost(identifierValidator, inputSanitizer))

		r.Get("/resources", s.handleAdminResourcesGet())
		r.Get("/resources/{resourceId}/settings", s.handleAdminResourceSettingsGet())
		r.Post("/resources/{resourceId}/settings", s.handleAdminResourceSettingsPost(identifierValidator, inputSanitizer))
		r.Get("/resources/{resourceId}/permissions", s.handleAdminResourcePermissionsGet())
		r.Post("/resources/{resourceId}/permissions", s.handleAdminResourcePermissionsPost(identifierValidator, inputSanitizer))
		r.Post("/resources/validate-permission", s.handleAdminResourceValidatePermissionPost(identifierValidator, inputSanitizer))
		r.Get("/resources/{resourceId}/delete", s.handleAdminResourceDeleteGet())
		r.Post("/resources/{resourceId}/delete", s.handleAdminResourceDeletePost())
		r.Get("/resources/new", s.handleAdminResourceAddNewGet())
		r.Post("/resources/new", s.handleAdminResourceAddNewPost(identifierValidator, inputSanitizer))

		r.Get("/groups", s.handleAdminGroupsGet())
		r.Get("/groups/{groupId}/settings", s.handleAdminGroupSettingsGet())
		r.Get("/groups/{groupId}/attributes", s.handleAdminGroupAttributesGet())
		r.Get("/groups/{groupId}/attributes/add", s.handleAdminGroupAttributesAddGet())
		r.Post("/groups/{groupId}/attributes/add", s.handleAdminGroupAttributesAddPost(identifierValidator, inputSanitizer))
		r.Get("/groups/{groupId}/attributes/edit/{attributeId}", s.handleAdminGroupAttributesEditGet())
		r.Post("/groups/{groupId}/attributes/edit/{attributeId}", s.handleAdminGroupAttributesEditPost(identifierValidator, inputSanitizer))
		r.Post("/groups/{groupId}/attributes/remove/{attributeId}", s.handleAdminGroupAttributesRemovePost())
		r.Post("/groups/{groupId}/settings", s.handleAdminGroupSettingsPost(identifierValidator, inputSanitizer))
		r.Get("/groups/{groupId}/users-in-group", s.handleAdminGroupUsersInGroupGet())
		r.Get("/groups/{groupId}/users-in-group/add", s.handleAdminGroupUsersInGroupAddGet())
		r.Post("/groups/{groupId}/users-in-group/add", s.handleAdminGroupUsersInGroupAddPost())
		r.Post("/groups/{groupId}/users-in-group/remove/{userId}", s.handleAdminGroupUsersInGroupRemoveUserPost())
		r.Get("/groups/{groupId}/users-in-group/search", s.handleAdminGroupUsersInGroupSearchGet())
		r.Get("/groups/{groupId}/permissions", s.handleAdminGroupPermissionsGet())
		r.Post("/groups/{groupId}/permissions", s.handleAdminGroupPermissionsPost())
		r.Get("/groups/{groupId}/delete", s.handleAdminGroupDeleteGet())
		r.Post("/groups/{groupId}/delete", s.handleAdminGroupDeletePost())
		r.Get("/groups/new", s.handleAdminGroupAddNewGet())
		r.Post("/groups/new", s.handleAdminGroupAddNewPost(identifierValidator, inputSanitizer))
	})
}

func (s *Server) jwtSessionToContext(handler http.Handler) http.Handler {
	return MiddlewareJwtSessionToContext(handler, s.sessionStore, s.tokenValidator)
}

func (s *Server) requiresAdminScope(handler http.Handler) http.Handler {
	return MiddlewareRequiresScope(handler, s, "system-website", []string{"authserver:admin-website"})
}

func (s *Server) requiresAccountScope(handler http.Handler) http.Handler {
	return MiddlewareRequiresScope(handler, s, "system-website", []string{"authserver:account"})
}
