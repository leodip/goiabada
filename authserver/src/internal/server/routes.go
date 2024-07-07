package server

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/internal/communication"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/internal/handlers/adminclienthandlers"
	"github.com/leodip/goiabada/internal/handlers/admingrouphandlers"
	"github.com/leodip/goiabada/internal/handlers/adminresourcehandlers"
	"github.com/leodip/goiabada/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/internal/handlers/adminuserhandlers"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/security"
	"github.com/leodip/goiabada/internal/users"
	"github.com/leodip/goiabada/internal/validators"
)

func (s *Server) initRoutes() {

	authorizeValidator := validators.NewAuthorizeValidator(s.database)
	tokenParser := security.NewTokenParser(s.database)
	permissionChecker := security.NewPermissionChecker(s.database)
	tokenValidator := validators.NewTokenValidator(s.database, tokenParser, permissionChecker)
	profileValidator := validators.NewProfileValidator(s.database)
	emailValidator := validators.NewEmailValidator(s.database)
	addressValidator := validators.NewAddressValidator(s.database)
	phoneValidator := validators.NewPhoneValidator(s.database)
	passwordValidator := validators.NewPasswordValidator()
	identifierValidator := validators.NewIdentifierValidator(s.database)
	inputSanitizer := lib.NewInputSanitizer()

	codeIssuer := security.NewCodeIssuer(s.database)
	loginManager := security.NewLoginManager(codeIssuer)
	otpSecretGenerator := lib.NewOTPSecretGenerator()
	tokenIssuer := security.NewTokenIssuer(s.database, tokenParser)
	emailSender := communication.NewEmailSender(s.database)
	smsSender := communication.NewSMSSender(s.database)
	userCreator := users.NewUserCreator(s.database)

	jwtSessionToContext := MiddlewareJwtSessionToContext(s.sessionStore, tokenParser)

	s.router.NotFound(handlers.HandleNotFoundGet(s, s.sessionStore, s, s.database))
	s.router.Get("/", handlers.HandleIndexGet(s, s.sessionStore, s, s.database))
	s.router.Get("/unauthorized", handlers.HandleUnauthorizedGet(s, s.sessionStore, s, s.database))
	s.router.Get("/forgot-password", handlers.HandleForgotPasswordGet(s, s.sessionStore, s, s.database))
	s.router.Post("/forgot-password", handlers.HandleForgotPasswordPost(s, s.sessionStore, s, s.database, emailSender))
	s.router.Get("/reset-password", handlers.HandleResetPasswordGet(s, s.sessionStore, s, s.database))
	s.router.Post("/reset-password", handlers.HandleResetPasswordPost(s, s.sessionStore, s, s.database, passwordValidator))
	s.router.Get("/.well-known/openid-configuration", handlers.HandleWellKnownOIDCConfigGet())
	s.router.Get("/certs", handlers.HandleCertsGet(s, s.sessionStore, s, s.database))
	s.router.With(s.jwtAuthorizationHeaderToContext).Get("/userinfo", handlers.HandleUserInfoGetPost(s, s.sessionStore, s, s.database))
	s.router.With(s.jwtAuthorizationHeaderToContext).Post("/userinfo", handlers.HandleUserInfoGetPost(s, s.sessionStore, s, s.database))
	s.router.Get("/health", handlers.HandleHealthCheckGet())
	s.router.Get("/test", handlers.HandleRequestTestGet())

	s.router.With(jwtSessionToContext).Route("/auth", func(r chi.Router) {
		r.Get("/authorize", handlers.HandleAuthorizeGet(s, s.sessionStore, s, s, s.database, s.templateFS, authorizeValidator, loginManager))
		r.Get("/pwd", handlers.HandleAuthPwdGet(s, s.sessionStore, s, s.database))
		r.Post("/pwd", handlers.HandleAuthPwdPost(s, s.sessionStore, s, s, s.database, loginManager))
		r.Get("/otp", handlers.HandleAuthOtpGet(s, s.sessionStore, s, s.database, otpSecretGenerator))
		r.Post("/otp", handlers.HandleAuthOtpPost(s, s.sessionStore, s, s, s.database))
		r.Get("/consent", handlers.HandleConsentGet(s, s.sessionStore, s, s.database, s.templateFS, codeIssuer, permissionChecker))
		r.Post("/consent", handlers.HandleConsentPost(s, s.sessionStore, s, s.database, s.templateFS, codeIssuer))
		r.Post("/token", handlers.HandleTokenPost(s, s.sessionStore, s, s, s.database, tokenIssuer, tokenValidator))
		r.Post("/callback", handlers.HandleAuthCallbackPost(s, s.sessionStore, s, s.database, s.tokenParser, tokenIssuer, tokenValidator))
		r.Get("/logout", accounthandlers.HandleAccountLogoutGet(s, s.sessionStore, s, s.database, s.tokenParser))
		r.Post("/logout", accounthandlers.HandleAccountLogoutPost(s, s.sessionStore, s, s.database))
		r.Post("/logout", accounthandlers.HandleAccountLogoutPost(s, s.sessionStore, s, s.database))
	})
	s.router.Route("/account", func(r chi.Router) {
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, lib.GetBaseUrl()+"/account/profile", http.StatusFound)
		})
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Get("/profile", accounthandlers.HandleAccountProfileGet(s, s.sessionStore, s.database))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Post("/profile", accounthandlers.HandleAccountProfilePost(s, s.sessionStore, s, s.database, profileValidator, inputSanitizer))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Get("/email", accounthandlers.HandleAccountEmailGet(s, s.sessionStore, s.database))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Post("/email", accounthandlers.HandleAccountEmailPost(s, s.sessionStore, s, s.database, emailValidator, inputSanitizer))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Post("/email-send-verification", accounthandlers.HandleAccountEmailSendVerificationPost(s, s.database, emailSender))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Get("/email-verify", accounthandlers.HandleAccountEmailVerifyGet(s, s, s.database))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Get("/address", accounthandlers.HandleAccountAddressGet(s, s.sessionStore, s.database))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Post("/address", accounthandlers.HandleAccountAddressPost(s, s.sessionStore, s, s.database, addressValidator, inputSanitizer))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Get("/phone", accounthandlers.HandleAccountPhoneGet(s, s.sessionStore, s.database))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Post("/phone", accounthandlers.HandleAccountPhonePost(s, s.sessionStore, s, s.database, phoneValidator))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Post("/phone-send-verification", accounthandlers.HandleAccountPhoneSendVerificationPost(s, s, s.database, smsSender))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Get("/phone-verify", accounthandlers.HandleAccountPhoneVerifyGet(s, s.database))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Post("/phone-verify", accounthandlers.HandleAccountPhoneVerifyPost(s, s, s.database))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Get("/change-password", accounthandlers.HandleAccountChangePasswordGet(s))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Post("/change-password", accounthandlers.HandleAccountChangePasswordPost(s, s, s.database, passwordValidator))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Get("/otp", accounthandlers.HandleAccountOtpGet(s, s.sessionStore, s.database, otpSecretGenerator))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Post("/otp", accounthandlers.HandleAccountOtpPost(s, s.sessionStore, s, s.database))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Get("/manage-consents", accounthandlers.HandleAccountManageConsentsGet(s, s.database))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Post("/manage-consents", accounthandlers.HandleAccountManageConsentsRevokePost(s, s, s.database))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Get("/sessions", accounthandlers.HandleAccountSessionsGet(s, s.database))
		r.With(jwtSessionToContext).With(s.requiresAccountScope).Post("/sessions", accounthandlers.HandleAccountSessionsEndSesssionPost(s, s, s.database))
		r.Get("/register", accounthandlers.HandleAccountRegisterGet(s))
		r.Post("/register", accounthandlers.HandleAccountRegisterPost(s, s.database, userCreator, emailValidator, passwordValidator, emailSender))
		r.Get("/activate", accounthandlers.HandleAccountActivateGet(s, s.database, userCreator))
	})

	s.router.With(jwtSessionToContext).With(s.requiresAdminScope).Route("/admin", func(r chi.Router) {

		r.Get("/get-permissions", handlers.HandleAdminGetPermissionsGet(s, s.sessionStore, s, s.database))

		r.Get("/clients", adminclienthandlers.HandleAdminClientsGet(s, s.database))
		r.Get("/clients/{clientId}/settings", adminclienthandlers.HandleAdminClientSettingsGet(s, s.sessionStore, s.database))
		r.Post("/clients/{clientId}/settings", adminclienthandlers.HandleAdminClientSettingsPost(s, s.sessionStore, s, s.database, identifierValidator, inputSanitizer))
		r.Get("/clients/{clientId}/tokens", adminclienthandlers.HandleAdminClientTokensGet(s, s.sessionStore, s.database))
		r.Post("/clients/{clientId}/tokens", adminclienthandlers.HandleAdminClientTokensPost(s, s.sessionStore, s, s.database))
		r.Get("/clients/{clientId}/authentication", adminclienthandlers.HandleAdminClientAuthenticationGet(s, s.sessionStore, s.database))
		r.Post("/clients/{clientId}/authentication", adminclienthandlers.HandleAdminClientAuthenticationPost(s, s.sessionStore, s, s.database))
		r.Get("/clients/{clientId}/oauth2-flows", adminclienthandlers.HandleAdminClientOAuth2Get(s, s.sessionStore, s.database))
		r.Post("/clients/{clientId}/oauth2-flows", adminclienthandlers.HandleAdminClientOAuth2Post(s, s.sessionStore, s, s.database))
		r.Get("/clients/{clientId}/redirect-uris", adminclienthandlers.HandleAdminClientRedirectURIsGet(s, s.sessionStore, s.database))
		r.Post("/clients/{clientId}/redirect-uris", adminclienthandlers.HandleAdminClientRedirectURIsPost(s, s.sessionStore, s, s.database))
		r.Get("/clients/{clientId}/web-origins", adminclienthandlers.HandleAdminClientWebOriginsGet(s, s.sessionStore, s.database))
		r.Post("/clients/{clientId}/web-origins", adminclienthandlers.HandleAdminClientWebOriginsPost(s, s.sessionStore, s, s.database))
		r.Get("/clients/{clientId}/user-sessions", adminclienthandlers.HandleAdminClientUserSessionsGet(s, s.database))
		r.Post("/clients/{clientId}/user-sessions/delete", adminclienthandlers.HandleAdminClientUserSessionsPost(s, s, s.database))
		r.Get("/clients/{clientId}/permissions", adminclienthandlers.HandleAdminClientPermissionsGet(s, s.sessionStore, s.database))
		r.Post("/clients/{clientId}/permissions", adminclienthandlers.HandleAdminClientPermissionsPost(s, s.sessionStore, s, s.database))
		r.Get("/clients/generate-new-secret", adminclienthandlers.HandleAdminClientGenerateNewSecretGet())
		r.Get("/clients/{clientId}/delete", adminclienthandlers.HandleAdminClientDeleteGet(s, s.database))
		r.Post("/clients/{clientId}/delete", adminclienthandlers.HandleAdminClientDeletePost(s, s, s.database))
		r.Get("/clients/new", adminclienthandlers.HandleAdminClientNewGet(s))
		r.Post("/clients/new", adminclienthandlers.HandleAdminClientNewPost(s, s, s.database, identifierValidator, inputSanitizer))

		r.Get("/resources", adminresourcehandlers.HandleAdminResourcesGet(s, s.database))
		r.Get("/resources/{resourceId}/settings", adminresourcehandlers.HandleAdminResourceSettingsGet(s, s.sessionStore, s.database))
		r.Post("/resources/{resourceId}/settings", adminresourcehandlers.HandleAdminResourceSettingsPost(s, s.sessionStore, s, s.database, identifierValidator, inputSanitizer))
		r.Get("/resources/{resourceId}/permissions", adminresourcehandlers.HandleAdminResourcePermissionsGet(s, s.sessionStore, s.database))
		r.Post("/resources/{resourceId}/permissions", adminresourcehandlers.HandleAdminResourcePermissionsPost(s, s.sessionStore, s, s.database, identifierValidator, inputSanitizer))
		r.Post("/resources/validate-permission", adminresourcehandlers.HandleAdminResourceValidatePermissionPost(s, identifierValidator, inputSanitizer))
		r.Get("/resources/{resourceId}/users-with-permission", adminresourcehandlers.HandleAdminResourceUsersWithPermissionGet(s, s.sessionStore, s.database))
		r.Post("/resources/{resourceId}/users-with-permission/remove/{userId}/{permissionId}", adminresourcehandlers.HandleAdminResourceUsersWithPermissionRemovePermissionPost(s, s, s.database))
		r.Get("/resources/{resourceId}/users-with-permission/add/{permissionId}", adminresourcehandlers.HandleAdminResourceUsersWithPermissionAddGet(s, s.database))
		r.Post("/resources/{resourceId}/users-with-permission/add/{userId}/{permissionId}", adminresourcehandlers.HandleAdminResourceUsersWithPermissionAddPermissionPost(s, s, s.database))
		r.Get("/resources/{resourceId}/users-with-permission/search/{permissionId}", adminresourcehandlers.HandleAdminResourceUsersWithPermissionSearchGet(s, s.database))
		r.Get("/resources/{resourceId}/groups-with-permission", adminresourcehandlers.HandleAdminResourceGroupsWithPermissionGet(s, s.sessionStore, s.database))
		r.Post("/resources/{resourceId}/groups-with-permission/add/{groupId}/{permissionId}", adminresourcehandlers.HandleAdminResourceGroupsWithPermissionAddPermissionPost(s, s, s.database))
		r.Post("/resources/{resourceId}/groups-with-permission/remove/{groupId}/{permissionId}", adminresourcehandlers.HandleAdminResourceGroupsWithPermissionRemovePermissionPost(s, s, s.database))
		r.Get("/resources/{resourceId}/delete", adminresourcehandlers.HandleAdminResourceDeleteGet(s, s.database))
		r.Post("/resources/{resourceId}/delete", adminresourcehandlers.HandleAdminResourceDeletePost(s, s, s.database))
		r.Get("/resources/new", adminresourcehandlers.HandleAdminResourceNewGet(s))
		r.Post("/resources/new", adminresourcehandlers.HandleAdminResourceNewPost(s, s, s.database, identifierValidator, inputSanitizer))

		r.Get("/groups", admingrouphandlers.HandleAdminGroupsGet(s, s.database))
		r.Get("/groups/{groupId}/settings", admingrouphandlers.HandleAdminGroupSettingsGet(s, s.sessionStore, s.database))
		r.Get("/groups/{groupId}/attributes", admingrouphandlers.HandleAdminGroupAttributesGet(s, s.database))
		r.Get("/groups/{groupId}/attributes/add", admingrouphandlers.HandleAdminGroupAttributesAddGet(s, s.database))
		r.Post("/groups/{groupId}/attributes/add", admingrouphandlers.HandleAdminGroupAttributesAddPost(s, s, s.database, identifierValidator, inputSanitizer))
		r.Get("/groups/{groupId}/attributes/edit/{attributeId}", admingrouphandlers.HandleAdminGroupAttributesEditGet(s, s.database))
		r.Post("/groups/{groupId}/attributes/edit/{attributeId}", admingrouphandlers.HandleAdminGroupAttributesEditPost(s, s, s.database, identifierValidator, inputSanitizer))
		r.Post("/groups/{groupId}/attributes/remove/{attributeId}", admingrouphandlers.HandleAdminGroupAttributesRemovePost(s, s, s.database))
		r.Post("/groups/{groupId}/settings", admingrouphandlers.HandleAdminGroupSettingsPost(s, s.sessionStore, s, s.database, identifierValidator, inputSanitizer))
		r.Get("/groups/{groupId}/members", admingrouphandlers.HandleAdminGroupMembersGet(s, s.database))
		r.Get("/groups/{groupId}/members/add", admingrouphandlers.HandleAdminGroupMembersAddGet(s, s.database))
		r.Post("/groups/{groupId}/members/add", admingrouphandlers.HandleAdminGroupMembersAddPost(s, s, s.database))
		r.Post("/groups/{groupId}/members/remove/{userId}", admingrouphandlers.HandleAdminGroupMembersRemoveUserPost(s, s, s.database))
		r.Get("/groups/{groupId}/members/search", admingrouphandlers.HandleAdminGroupMembersSearchGet(s, s.database))
		r.Get("/groups/{groupId}/permissions", admingrouphandlers.HandleAdminGroupPermissionsGet(s, s.sessionStore, s.database))
		r.Post("/groups/{groupId}/permissions", admingrouphandlers.HandleAdminGroupPermissionsPost(s, s.sessionStore, s, s.database))
		r.Get("/groups/{groupId}/delete", admingrouphandlers.HandleAdminGroupDeleteGet(s, s.database))
		r.Post("/groups/{groupId}/delete", admingrouphandlers.HandleAdminGroupDeletePost(s, s, s.database))
		r.Get("/groups/new", admingrouphandlers.HandleAdminGroupNewGet(s, s.database))
		r.Post("/groups/new", admingrouphandlers.HandleAdminGroupNewPost(s, s, s.database, identifierValidator, inputSanitizer))

		r.Get("/users", adminuserhandlers.HandleAdminUsersGet(s, s.sessionStore, s, s.database))
		r.Get("/users/{userId}/details", adminuserhandlers.HandleAdminUserDetailsGet(s, s.sessionStore, s, s.database))
		r.Post("/users/{userId}/details", adminuserhandlers.HandleAdminUserDetailsPost(s, s.sessionStore, s, s.database))
		r.Get("/users/{userId}/profile", adminuserhandlers.HandleAdminUserProfileGet(s, s.sessionStore, s, s.database))
		r.Post("/users/{userId}/profile", adminuserhandlers.HandleAdminUserProfilePost(s, s.sessionStore, s, s.database, profileValidator, inputSanitizer))
		r.Get("/users/{userId}/email", adminuserhandlers.HandleAdminUserEmailGet(s, s.sessionStore, s, s.database))
		r.Post("/users/{userId}/email", adminuserhandlers.HandleAdminUserEmailPost(s, s.sessionStore, s, s.database, emailValidator, inputSanitizer))
		r.Get("/users/{userId}/phone", adminuserhandlers.HandleAdminUserPhoneGet(s, s.sessionStore, s, s.database))
		r.Post("/users/{userId}/phone", adminuserhandlers.HandleAdminUserPhonePost(s, s.sessionStore, s, s.database, phoneValidator, inputSanitizer))
		r.Get("/users/{userId}/address", adminuserhandlers.HandleAdminUserAddressGet(s, s.sessionStore, s, s.database))
		r.Post("/users/{userId}/address", adminuserhandlers.HandleAdminUserAddressPost(s, s.sessionStore, s, s.database, addressValidator, inputSanitizer))
		r.Get("/users/{userId}/authentication", adminuserhandlers.HandleAdminUserAuthenticationGet(s, s.sessionStore, s, s.database))
		r.Post("/users/{userId}/authentication", adminuserhandlers.HandleAdminUserAuthenticationPost(s, s.sessionStore, s, s.database, passwordValidator))
		r.Get("/users/{userId}/consents", adminuserhandlers.HandleAdminUserConsentsGet(s, s.sessionStore, s, s.database))
		r.Post("/users/{userId}/consents", adminuserhandlers.HandleAdminUserConsentsPost(s, s.sessionStore, s, s.database))
		r.Get("/users/{userId}/sessions", adminuserhandlers.HandleAdminUserSessionsGet(s, s.sessionStore, s, s.database))
		r.Post("/users/{userId}/sessions", adminuserhandlers.HandleAdminUserSessionsPost(s, s.sessionStore, s, s.database))
		r.Get("/users/{userId}/attributes", adminuserhandlers.HandleAdminUserAttributesGet(s, s.sessionStore, s, s.database))
		r.Get("/users/{userId}/attributes/add", adminuserhandlers.HandleAdminUserAttributesAddGet(s, s.sessionStore, s, s.database))
		r.Post("/users/{userId}/attributes/add", adminuserhandlers.HandleAdminUserAttributesAddPost(s, s.sessionStore, s, s.database, identifierValidator, inputSanitizer))
		r.Get("/users/{userId}/attributes/edit/{attributeId}", adminuserhandlers.HandleAdminUserAttributesEditGet(s, s.sessionStore, s, s.database))
		r.Post("/users/{userId}/attributes/edit/{attributeId}", adminuserhandlers.HandleAdminUserAttributesEditPost(s, s.sessionStore, s, s.database, identifierValidator, inputSanitizer))
		r.Post("/users/{userId}/attributes/remove/{attributeId}", adminuserhandlers.HandleAdminUserAttributesRemovePost(s, s.sessionStore, s, s.database))
		r.Get("/users/{userId}/permissions", adminuserhandlers.HandleAdminUserPermissionsGet(s, s.sessionStore, s, s.database))
		r.Post("/users/{userId}/permissions", adminuserhandlers.HandleAdminUserPermissionsPost(s, s.sessionStore, s, s.database))
		r.Get("/users/{userId}/groups", adminuserhandlers.HandleAdminUserGroupsGet(s, s.sessionStore, s, s.database))
		r.Post("/users/{userId}/groups", adminuserhandlers.HandleAdminUserGroupsPost(s, s.sessionStore, s, s.database))
		r.Get("/users/{userId}/delete", adminuserhandlers.HandleAdminUserDeleteGet(s, s.sessionStore, s, s.database))
		r.Post("/users/{userId}/delete", adminuserhandlers.HandleAdminUserDeletePost(s, s.sessionStore, s, s.database))
		r.Get("/users/new", adminuserhandlers.HandleAdminUserNewGet(s, s.sessionStore, s, s.database))
		r.Post("/users/new", adminuserhandlers.HandleAdminUserNewPost(s, s.sessionStore, s, s.database, userCreator, profileValidator, emailValidator, passwordValidator, inputSanitizer, emailSender))

		r.Get("/settings/general", adminsettingshandlers.HandleAdminSettingsGeneralGet(s, s.sessionStore, s, s.database))
		r.Post("/settings/general", adminsettingshandlers.HandleAdminSettingsGeneralPost(s, s.sessionStore, s, s.database, inputSanitizer))
		r.Get("/settings/ui-theme", adminsettingshandlers.HandleAdminSettingsUIThemeGet(s, s.sessionStore, s, s.database))
		r.Post("/settings/ui-theme", adminsettingshandlers.HandleAdminSettingsUIThemePost(s, s.sessionStore, s, s.database))
		r.Get("/settings/sessions", adminsettingshandlers.HandleAdminSettingsSessionsGet(s, s.sessionStore, s, s.database))
		r.Post("/settings/sessions", adminsettingshandlers.HandleAdminSettingsSessionsPost(s, s.sessionStore, s, s.database))
		r.Get("/settings/tokens", adminsettingshandlers.HandleAdminSettingsTokensGet(s, s.sessionStore, s, s.database))
		r.Post("/settings/tokens", adminsettingshandlers.HandleAdminSettingsTokensPost(s, s.sessionStore, s, s.database))
		r.Get("/settings/keys", adminsettingshandlers.HandleAdminSettingsKeysGet(s, s.sessionStore, s, s.database))
		r.Post("/settings/keys/rotate", adminsettingshandlers.HandleAdminSettingsKeysRotatePost(s, s.sessionStore, s, s.database))
		r.Post("/settings/keys/revoke", adminsettingshandlers.HandleAdminSettingsKeysRevokePost(s, s.sessionStore, s, s.database))
		r.Get("/settings/email", adminsettingshandlers.HandleAdminSettingsEmailGet(s, s.sessionStore, s, s.database))
		r.Post("/settings/email", adminsettingshandlers.HandleAdminSettingsEmailPost(s, s.sessionStore, s, s.database, emailValidator, inputSanitizer))
		r.Get("/settings/email/send-test-email", adminsettingshandlers.HandleAdminSettingsEmailSendTestGet(s, s.sessionStore, s, s.database))
		r.Post("/settings/email/send-test-email", adminsettingshandlers.HandleAdminSettingsEmailSendTestPost(s, s.sessionStore, s, s.database, emailValidator, emailSender))
		r.Get("/settings/sms", adminsettingshandlers.HandleAdminSettingsSMSGet(s, s.sessionStore, s, s.database))
		r.Post("/settings/sms", adminsettingshandlers.HandleAdminSettingsSMSPost(s, s.sessionStore, s, s.database))
	})
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
