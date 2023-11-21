package server

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/core"
	core_authorize "github.com/leodip/goiabada/internal/core/authorize"
	core_senders "github.com/leodip/goiabada/internal/core/senders"
	core_token "github.com/leodip/goiabada/internal/core/token"
	core_validators "github.com/leodip/goiabada/internal/core/validators"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) initRoutes() {

	authorizeValidator := core_validators.NewAuthorizeValidator(s.database)
	tokenParser := core_token.NewTokenParser(s.database)
	permissionChecker := core.NewPermissionChecker(s.database)
	tokenValidator := core_validators.NewTokenValidator(s.database, tokenParser, permissionChecker)
	profileValidator := core_validators.NewProfileValidator(s.database)
	emailValidator := core_validators.NewEmailValidator(s.database)
	addressValidator := core_validators.NewAddressValidator(s.database)
	phoneValidator := core_validators.NewPhoneValidator(s.database)
	passwordValidator := core_validators.NewPasswordValidator()
	identifierValidator := core_validators.NewIdentifierValidator(s.database)
	inputSanitizer := core.NewInputSanitizer()

	codeIssuer := core_authorize.NewCodeIssuer(s.database)
	loginManager := core_authorize.NewLoginManager(codeIssuer)
	otpSecretGenerator := core.NewOTPSecretGenerator()
	tokenIssuer := core_token.NewTokenIssuer(s.database, tokenParser)
	emailSender := core_senders.NewEmailSender(s.database)
	smsSender := core_senders.NewSMSSender(s.database)
	userCreator := core.NewUserCreator(s.database)

	s.router.NotFound(s.handleNotFoundGet())
	s.router.Get("/", s.handleIndexGet())
	s.router.Get("/unauthorized", s.handleUnauthorizedGet())
	s.router.Get("/forgot-password", s.handleForgotPasswordGet())
	s.router.Post("/forgot-password", s.handleForgotPasswordPost(emailSender))
	s.router.Get("/reset-password", s.handleResetPasswordGet())
	s.router.Post("/reset-password", s.handleResetPasswordPost(passwordValidator))
	s.router.Get("/.well-known/openid-configuration", s.handleWellKnownOIDCConfigGet())
	s.router.Get("/certs", s.handleCertsGet())
	s.router.With(s.jwtAuthorizationHeaderToContext).Get("/userinfo", s.handleUserInfoGetPost())
	s.router.With(s.jwtAuthorizationHeaderToContext).Post("/userinfo", s.handleUserInfoGetPost())
	s.router.Get("/health", s.handleHealthCheckGet())

	s.router.Route("/auth", func(r chi.Router) {
		r.Get("/authorize", s.handleAuthorizeGet(authorizeValidator, codeIssuer, loginManager))
		r.Get("/pwd", s.handleAuthPwdGet())
		r.Post("/pwd", s.handleAuthPwdPost(authorizeValidator, loginManager))
		r.Get("/otp", s.handleAuthOtpGet(otpSecretGenerator))
		r.Post("/otp", s.handleAuthOtpPost())
		r.Get("/consent", s.handleConsentGet(codeIssuer, permissionChecker))
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
		r.With(s.jwtSessionToContext).With(s.requiresAccountScope).Post("/email", s.handleAccountEmailPost(emailValidator, inputSanitizer))
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
		r.Post("/register", s.handleAccountRegisterPost(userCreator, emailValidator, passwordValidator, emailSender))
		r.Get("/activate", s.handleAccountActivateGet(userCreator, emailSender))
	})

	s.router.With(s.jwtSessionToContext).With(s.requiresAdminScope).Route("/admin", func(r chi.Router) {

		r.Get("/get-permissions", s.handleAdminGetPermissionsGet())

		r.Get("/clients", s.handleAdminClientsGet())
		r.Get("/clients/{clientId}/settings", s.handleAdminClientSettingsGet())
		r.Post("/clients/{clientId}/settings", s.handleAdminClientSettingsPost(identifierValidator, inputSanitizer))
		r.Get("/clients/{clientId}/tokens", s.handleAdminClientTokensGet())
		r.Post("/clients/{clientId}/tokens", s.handleAdminClientTokensPost())
		r.Get("/clients/{clientId}/authentication", s.handleAdminClientAuthenticationGet())
		r.Post("/clients/{clientId}/authentication", s.handleAdminClientAuthenticationPost())
		r.Get("/clients/{clientId}/oauth2-flows", s.handleAdminClientOAuth2Get())
		r.Post("/clients/{clientId}/oauth2-flows", s.handleAdminClientOAuth2Post())
		r.Get("/clients/{clientId}/redirect-uris", s.handleAdminClientRedirectURIsGet())
		r.Post("/clients/{clientId}/redirect-uris", s.handleAdminClientRedirectURIsPost())
		r.Get("/clients/{clientId}/web-origins", s.handleAdminClientWebOriginsGet())
		r.Post("/clients/{clientId}/web-origins", s.handleAdminClientWebOriginsPost())
		r.Get("/clients/{clientId}/user-sessions", s.handleAdminClientUserSessionsGet())
		r.Post("/clients/{clientId}/user-sessions/delete", s.handleAdminClientUserSessionsPost())
		r.Get("/clients/{clientId}/permissions", s.handleAdminClientPermissionsGet())
		r.Post("/clients/{clientId}/permissions", s.handleAdminClientPermissionsPost())
		r.Get("/clients/generate-new-secret", s.handleAdminClientGenerateNewSecretGet())
		r.Get("/clients/{clientId}/delete", s.handleAdminClientDeleteGet())
		r.Post("/clients/{clientId}/delete", s.handleAdminClientDeletePost())
		r.Get("/clients/new", s.handleAdminClientNewGet())
		r.Post("/clients/new", s.handleAdminClientNewPost(identifierValidator, inputSanitizer))

		r.Get("/resources", s.handleAdminResourcesGet())
		r.Get("/resources/{resourceId}/settings", s.handleAdminResourceSettingsGet())
		r.Post("/resources/{resourceId}/settings", s.handleAdminResourceSettingsPost(identifierValidator, inputSanitizer))
		r.Get("/resources/{resourceId}/permissions", s.handleAdminResourcePermissionsGet())
		r.Post("/resources/{resourceId}/permissions", s.handleAdminResourcePermissionsPost(identifierValidator, inputSanitizer))
		r.Post("/resources/validate-permission", s.handleAdminResourceValidatePermissionPost(identifierValidator, inputSanitizer))
		r.Get("/resources/{resourceId}/users-with-permission", s.handleAdminResourceUsersWithPermissionGet())
		r.Post("/resources/{resourceId}/users-with-permission/remove/{userId}/{permissionId}", s.handleAdminResourceUsersWithPermissionRemovePermissionPost())
		r.Get("/resources/{resourceId}/users-with-permission/add/{permissionId}", s.handleAdminResourceUsersWithPermissionAddGet())
		r.Post("/resources/{resourceId}/users-with-permission/add/{userId}/{permissionId}", s.handleAdminResourceUsersWithPermissionAddPermissionPost())
		r.Get("/resources/{resourceId}/users-with-permission/search/{permissionId}", s.handleAdminResourceUsersWithPermissionSearchGet())
		r.Get("/resources/{resourceId}/groups-with-permission", s.handleAdminResourceGroupsWithPermissionGet())
		r.Post("/resources/{resourceId}/groups-with-permission/add/{groupId}/{permissionId}", s.handleAdminResourceGroupsWithPermissionAddPermissionPost())
		r.Post("/resources/{resourceId}/groups-with-permission/remove/{groupId}/{permissionId}", s.handleAdminResourceGroupsWithPermissionRemovePermissionPost())
		r.Get("/resources/{resourceId}/delete", s.handleAdminResourceDeleteGet())
		r.Post("/resources/{resourceId}/delete", s.handleAdminResourceDeletePost())
		r.Get("/resources/new", s.handleAdminResourceNewGet())
		r.Post("/resources/new", s.handleAdminResourceNewPost(identifierValidator, inputSanitizer))

		r.Get("/groups", s.handleAdminGroupsGet())
		r.Get("/groups/{groupId}/settings", s.handleAdminGroupSettingsGet())
		r.Get("/groups/{groupId}/attributes", s.handleAdminGroupAttributesGet())
		r.Get("/groups/{groupId}/attributes/add", s.handleAdminGroupAttributesAddGet())
		r.Post("/groups/{groupId}/attributes/add", s.handleAdminGroupAttributesAddPost(identifierValidator, inputSanitizer))
		r.Get("/groups/{groupId}/attributes/edit/{attributeId}", s.handleAdminGroupAttributesEditGet())
		r.Post("/groups/{groupId}/attributes/edit/{attributeId}", s.handleAdminGroupAttributesEditPost(identifierValidator, inputSanitizer))
		r.Post("/groups/{groupId}/attributes/remove/{attributeId}", s.handleAdminGroupAttributesRemovePost())
		r.Post("/groups/{groupId}/settings", s.handleAdminGroupSettingsPost(identifierValidator, inputSanitizer))
		r.Get("/groups/{groupId}/members", s.handleAdminGroupMembersGet())
		r.Get("/groups/{groupId}/members/add", s.handleAdminGroupMembersAddGet())
		r.Post("/groups/{groupId}/members/add", s.handleAdminGroupMembersAddPost())
		r.Post("/groups/{groupId}/members/remove/{userId}", s.handleAdminGroupMembersRemoveUserPost())
		r.Get("/groups/{groupId}/members/search", s.handleAdminGroupMembersSearchGet())
		r.Get("/groups/{groupId}/permissions", s.handleAdminGroupPermissionsGet())
		r.Post("/groups/{groupId}/permissions", s.handleAdminGroupPermissionsPost())
		r.Get("/groups/{groupId}/delete", s.handleAdminGroupDeleteGet())
		r.Post("/groups/{groupId}/delete", s.handleAdminGroupDeletePost())
		r.Get("/groups/new", s.handleAdminGroupNewGet())
		r.Post("/groups/new", s.handleAdminGroupNewPost(identifierValidator, inputSanitizer))

		r.Get("/users", s.handleAdminUsersGet())
		r.Get("/users/{userId}/details", s.handleAdminUserDetailsGet())
		r.Post("/users/{userId}/details", s.handleAdminUserDetailsPost())
		r.Get("/users/{userId}/profile", s.handleAdminUserProfileGet())
		r.Post("/users/{userId}/profile", s.handleAdminUserProfilePost(profileValidator, inputSanitizer))
		r.Get("/users/{userId}/email", s.handleAdminUserEmailGet())
		r.Post("/users/{userId}/email", s.handleAdminUserEmailPost(emailValidator, inputSanitizer))
		r.Get("/users/{userId}/phone", s.handleAdminUserPhoneGet())
		r.Post("/users/{userId}/phone", s.handleAdminUserPhonePost(phoneValidator, inputSanitizer))
		r.Get("/users/{userId}/address", s.handleAdminUserAddressGet())
		r.Post("/users/{userId}/address", s.handleAdminUserAddressPost(addressValidator, inputSanitizer))
		r.Get("/users/{userId}/authentication", s.handleAdminUserAuthenticationGet())
		r.Post("/users/{userId}/authentication", s.handleAdminUserAuthenticationPost(passwordValidator, inputSanitizer))
		r.Get("/users/{userId}/consents", s.handleAdminUserConsentsGet())
		r.Post("/users/{userId}/consents", s.handleAdminUserConsentsPost())
		r.Get("/users/{userId}/sessions", s.handleAdminUserSessionsGet())
		r.Post("/users/{userId}/sessions", s.handleAdminUserSessionsPost())
		r.Get("/users/{userId}/attributes", s.handleAdminUserAttributesGet())
		r.Get("/users/{userId}/attributes/add", s.handleAdminUserAttributesAddGet())
		r.Post("/users/{userId}/attributes/add", s.handleAdminUserAttributesAddPost(identifierValidator, inputSanitizer))
		r.Get("/users/{userId}/attributes/edit/{attributeId}", s.handleAdminUserAttributesEditGet())
		r.Post("/users/{userId}/attributes/edit/{attributeId}", s.handleAdminUserAttributesEditPost(identifierValidator, inputSanitizer))
		r.Post("/users/{userId}/attributes/remove/{attributeId}", s.handleAdminUserAttributesRemovePost())
		r.Get("/users/{userId}/permissions", s.handleAdminUserPermissionsGet())
		r.Post("/users/{userId}/permissions", s.handleAdminUserPermissionsPost())
		r.Get("/users/{userId}/groups", s.handleAdminUserGroupsGet())
		r.Post("/users/{userId}/groups", s.handleAdminUserGroupsPost())
		r.Get("/users/{userId}/delete", s.handleAdminUserDeleteGet())
		r.Post("/users/{userId}/delete", s.handleAdminUserDeletePost())
		r.Get("/users/new", s.handleAdminUserNewGet())
		r.Post("/users/new", s.handleAdminUserNewPost(userCreator, profileValidator, emailValidator, passwordValidator, inputSanitizer, emailSender))

		r.Get("/settings/general", s.handleAdminSettingsGeneralGet())
		r.Post("/settings/general", s.handleAdminSettingsGeneralPost(inputSanitizer))
		r.Get("/settings/ui-theme", s.handleAdminSettingsUIThemeGet())
		r.Post("/settings/ui-theme", s.handleAdminSettingsUIThemePost())
		r.Get("/settings/sessions", s.handleAdminSettingsSessionsGet())
		r.Post("/settings/sessions", s.handleAdminSettingsSessionsPost())
		r.Get("/settings/tokens", s.handleAdminSettingsTokensGet())
		r.Post("/settings/tokens", s.handleAdminSettingsTokensPost())
		r.Get("/settings/keys", s.handleAdminSettingsKeysGet())
		r.Post("/settings/keys/rotate", s.handleAdminSettingsKeysRotatePost())
		r.Post("/settings/keys/revoke", s.handleAdminSettingsKeysRevokePost())
		r.Get("/settings/email", s.handleAdminSettingsEmailGet())
		r.Post("/settings/email", s.handleAdminSettingsEmailPost(emailValidator, inputSanitizer))
		r.Get("/settings/email/send-test-email", s.handleAdminSettingsEmailSendTestGet())
		r.Post("/settings/email/send-test-email", s.handleAdminSettingsEmailSendTestPost(emailValidator, emailSender))
		r.Get("/settings/sms", s.handleAdminSettingsSMSGet())
		r.Post("/settings/sms", s.handleAdminSettingsSMSPost(inputSanitizer))
	})
}

func (s *Server) jwtSessionToContext(handler http.Handler) http.Handler {
	return MiddlewareJwtSessionToContext(handler, s.sessionStore, s.tokenParser)
}

func (s *Server) jwtAuthorizationHeaderToContext(handler http.Handler) http.Handler {
	return MiddlewareJwtAuthorizationHeaderToContext(handler, s.sessionStore, s.tokenParser)
}

func (s *Server) requiresAdminScope(handler http.Handler) http.Handler {
	return MiddlewareRequiresScope(handler, s, constants.SystemClientIdentifier,
		[]string{fmt.Sprintf("%v:%v", constants.AuthServerResourceIdentifier, constants.AdminWebsitePermissionIdentifier)})
}

func (s *Server) requiresAccountScope(handler http.Handler) http.Handler {
	return MiddlewareRequiresScope(handler, s, constants.SystemClientIdentifier,
		[]string{fmt.Sprintf("%v:%v", constants.AuthServerResourceIdentifier, constants.ManageAccountPermissionIdentifier)})
}
