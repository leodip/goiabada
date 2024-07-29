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
	"github.com/leodip/goiabada/internal/handlers/handlerhelpers"
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
	userSessionManager := security.NewUserSessionManager(codeIssuer, s.sessionStore, s.database)
	otpSecretGenerator := lib.NewOTPSecretGenerator()
	tokenIssuer := security.NewTokenIssuer(s.database, tokenParser)
	emailSender := communication.NewEmailSender(s.database)
	smsSender := communication.NewSMSSender(s.database)
	userCreator := users.NewUserCreator(s.database)

	httpHelper := handlerhelpers.NewHttpHelper(s.templateFS, s.database)
	authHelper := handlerhelpers.NewAuthHelper(s.sessionStore)

	middlewareRefreshToken := NewMiddlewareTokenRefresh(
		s.sessionStore,
		tokenIssuer,
		tokenValidator,
		tokenParser,
		userSessionManager,
		s.database,
	)

	middlewareJwt := NewMiddlewareJwt(authHelper, tokenParser, s.sessionStore)
	jwtSessionToContext := middlewareJwt.JwtSessionToContext()
	authHeaderToContext := middlewareJwt.JwtAuthorizationHeaderToContext()
	requiresAdminScope := middlewareJwt.RequiresScope([]string{fmt.Sprintf("%v:%v", constants.AuthServerResourceIdentifier, constants.AdminWebsitePermissionIdentifier)})
	requiresAccountScope := middlewareJwt.RequiresScope([]string{fmt.Sprintf("%v:%v", constants.AuthServerResourceIdentifier, constants.ManageAccountPermissionIdentifier)})

	jwtChainMiddleware := func(next http.Handler) http.Handler {
		return middlewareRefreshToken.RefreshExpiredToken()(jwtSessionToContext(next))
	}
	s.router.NotFound(handlers.HandleNotFoundGet(httpHelper))
	s.router.Get("/", handlers.HandleIndexGet(httpHelper))
	s.router.Get("/unauthorized", handlers.HandleUnauthorizedGet(httpHelper))
	s.router.Get("/forgot-password", handlers.HandleForgotPasswordGet(httpHelper))
	s.router.Post("/forgot-password", handlers.HandleForgotPasswordPost(httpHelper, s.database, emailSender))
	s.router.Get("/reset-password", handlers.HandleResetPasswordGet(httpHelper, s.database))
	s.router.Post("/reset-password", handlers.HandleResetPasswordPost(httpHelper, s.database, passwordValidator))
	s.router.Get("/.well-known/openid-configuration", handlers.HandleWellKnownOIDCConfigGet(httpHelper))
	s.router.Get("/certs", handlers.HandleCertsGet(httpHelper, s.database))
	s.router.With(authHeaderToContext).Get("/userinfo", handlers.HandleUserInfoGetPost(httpHelper, s.database))
	s.router.With(authHeaderToContext).Post("/userinfo", handlers.HandleUserInfoGetPost(httpHelper, s.database))
	s.router.Get("/health", handlers.HandleHealthCheckGet(httpHelper))
	s.router.Get("/test", handlers.HandleRequestTestGet(httpHelper))

	s.router.With(jwtChainMiddleware).Route("/auth", func(r chi.Router) {
		r.Get("/authorize", handlers.HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, s.database, s.templateFS, authorizeValidator))
		r.Get("/pwd", handlers.HandleAuthPwdGet(httpHelper, authHelper, s.database))
		r.Post("/pwd", handlers.HandleAuthPwdPost(httpHelper, authHelper, userSessionManager, s.database))
		r.Get("/otp", handlers.HandleAuthOtpGet(httpHelper, s.sessionStore, authHelper, s.database, otpSecretGenerator))
		r.Post("/otp", handlers.HandleAuthOtpPost(httpHelper, s.sessionStore, authHelper, userSessionManager, s.database))
		r.Get("/consent", handlers.HandleConsentGet(httpHelper, authHelper, s.database, s.templateFS, codeIssuer, permissionChecker))
		r.Post("/consent", handlers.HandleConsentPost(httpHelper, authHelper, s.database, s.templateFS, codeIssuer))
		r.Post("/token", handlers.HandleTokenPost(httpHelper, userSessionManager, s.database, tokenIssuer, tokenValidator))
		r.Post("/callback", handlers.HandleAuthCallbackPost(httpHelper, s.sessionStore, s.database, s.tokenParser, tokenIssuer, tokenValidator))
		r.Get("/logout", accounthandlers.HandleAccountLogoutGet(httpHelper, s.sessionStore, authHelper, s.database, s.tokenParser))
		r.Post("/logout", accounthandlers.HandleAccountLogoutPost(httpHelper, s.sessionStore, authHelper, s.database))
		r.Post("/logout", accounthandlers.HandleAccountLogoutPost(httpHelper, s.sessionStore, authHelper, s.database))
	})
	s.router.Route("/account", func(r chi.Router) {
		r.With(jwtChainMiddleware).With(requiresAccountScope).Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, lib.GetBaseUrl()+"/account/profile", http.StatusFound)
		})
		r.With(jwtChainMiddleware).With(requiresAccountScope).Get("/profile", accounthandlers.HandleAccountProfileGet(httpHelper, s.sessionStore, s.database))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Post("/profile", accounthandlers.HandleAccountProfilePost(httpHelper, s.sessionStore, authHelper, s.database, profileValidator, inputSanitizer))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Get("/email", accounthandlers.HandleAccountEmailGet(httpHelper, s.sessionStore, s.database))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Post("/email", accounthandlers.HandleAccountEmailPost(httpHelper, s.sessionStore, authHelper, s.database, emailValidator, inputSanitizer))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Post("/email-send-verification", accounthandlers.HandleAccountEmailSendVerificationPost(httpHelper, s.database, emailSender))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Get("/email-verify", accounthandlers.HandleAccountEmailVerifyGet(httpHelper, authHelper, s.database))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Get("/address", accounthandlers.HandleAccountAddressGet(httpHelper, s.sessionStore, s.database))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Post("/address", accounthandlers.HandleAccountAddressPost(httpHelper, s.sessionStore, authHelper, s.database, addressValidator, inputSanitizer))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Get("/phone", accounthandlers.HandleAccountPhoneGet(httpHelper, s.sessionStore, s.database))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Post("/phone", accounthandlers.HandleAccountPhonePost(httpHelper, s.sessionStore, authHelper, s.database, phoneValidator))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Post("/phone-send-verification", accounthandlers.HandleAccountPhoneSendVerificationPost(httpHelper, authHelper, s.database, smsSender))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Get("/phone-verify", accounthandlers.HandleAccountPhoneVerifyGet(httpHelper, s.database))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Post("/phone-verify", accounthandlers.HandleAccountPhoneVerifyPost(httpHelper, authHelper, s.database))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Get("/change-password", accounthandlers.HandleAccountChangePasswordGet(httpHelper))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Post("/change-password", accounthandlers.HandleAccountChangePasswordPost(httpHelper, authHelper, s.database, passwordValidator))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Get("/otp", accounthandlers.HandleAccountOtpGet(httpHelper, s.sessionStore, s.database, otpSecretGenerator))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Post("/otp", accounthandlers.HandleAccountOtpPost(httpHelper, s.sessionStore, authHelper, s.database))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Get("/manage-consents", accounthandlers.HandleAccountManageConsentsGet(httpHelper, s.database))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Post("/manage-consents", accounthandlers.HandleAccountManageConsentsRevokePost(httpHelper, authHelper, s.database))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Get("/sessions", accounthandlers.HandleAccountSessionsGet(httpHelper, s.database))
		r.With(jwtChainMiddleware).With(requiresAccountScope).Post("/sessions", accounthandlers.HandleAccountSessionsEndSesssionPost(httpHelper, authHelper, s.database))
		r.Get("/register", accounthandlers.HandleAccountRegisterGet(httpHelper))
		r.Post("/register", accounthandlers.HandleAccountRegisterPost(httpHelper, s.database, userCreator, emailValidator, passwordValidator, emailSender))
		r.Get("/activate", accounthandlers.HandleAccountActivateGet(httpHelper, s.database, userCreator))
	})

	s.router.With(jwtChainMiddleware).With(requiresAdminScope).Route("/admin", func(r chi.Router) {

		r.Get("/get-permissions", handlers.HandleAdminGetPermissionsGet(httpHelper, s.database))

		r.Get("/clients", adminclienthandlers.HandleAdminClientsGet(httpHelper, s.database))
		r.Get("/clients/{clientId}/settings", adminclienthandlers.HandleAdminClientSettingsGet(httpHelper, s.sessionStore, s.database))
		r.Post("/clients/{clientId}/settings", adminclienthandlers.HandleAdminClientSettingsPost(httpHelper, s.sessionStore, authHelper, s.database, identifierValidator, inputSanitizer))
		r.Get("/clients/{clientId}/tokens", adminclienthandlers.HandleAdminClientTokensGet(httpHelper, s.sessionStore, s.database))
		r.Post("/clients/{clientId}/tokens", adminclienthandlers.HandleAdminClientTokensPost(httpHelper, s.sessionStore, authHelper, s.database))
		r.Get("/clients/{clientId}/authentication", adminclienthandlers.HandleAdminClientAuthenticationGet(httpHelper, s.sessionStore, s.database))
		r.Post("/clients/{clientId}/authentication", adminclienthandlers.HandleAdminClientAuthenticationPost(httpHelper, s.sessionStore, authHelper, s.database))
		r.Get("/clients/{clientId}/oauth2-flows", adminclienthandlers.HandleAdminClientOAuth2Get(httpHelper, s.sessionStore, s.database))
		r.Post("/clients/{clientId}/oauth2-flows", adminclienthandlers.HandleAdminClientOAuth2Post(httpHelper, s.sessionStore, authHelper, s.database))
		r.Get("/clients/{clientId}/redirect-uris", adminclienthandlers.HandleAdminClientRedirectURIsGet(httpHelper, s.sessionStore, s.database))
		r.Post("/clients/{clientId}/redirect-uris", adminclienthandlers.HandleAdminClientRedirectURIsPost(httpHelper, s.sessionStore, authHelper, s.database))
		r.Get("/clients/{clientId}/web-origins", adminclienthandlers.HandleAdminClientWebOriginsGet(httpHelper, s.sessionStore, s.database))
		r.Post("/clients/{clientId}/web-origins", adminclienthandlers.HandleAdminClientWebOriginsPost(httpHelper, s.sessionStore, authHelper, s.database))
		r.Get("/clients/{clientId}/user-sessions", adminclienthandlers.HandleAdminClientUserSessionsGet(httpHelper, s.database))
		r.Post("/clients/{clientId}/user-sessions/delete", adminclienthandlers.HandleAdminClientUserSessionsPost(httpHelper, authHelper, s.database))
		r.Get("/clients/{clientId}/permissions", adminclienthandlers.HandleAdminClientPermissionsGet(httpHelper, s.sessionStore, s.database))
		r.Post("/clients/{clientId}/permissions", adminclienthandlers.HandleAdminClientPermissionsPost(httpHelper, s.sessionStore, authHelper, s.database))
		r.Get("/clients/generate-new-secret", adminclienthandlers.HandleAdminClientGenerateNewSecretGet(httpHelper))
		r.Get("/clients/{clientId}/delete", adminclienthandlers.HandleAdminClientDeleteGet(httpHelper, s.database))
		r.Post("/clients/{clientId}/delete", adminclienthandlers.HandleAdminClientDeletePost(httpHelper, authHelper, s.database))
		r.Get("/clients/new", adminclienthandlers.HandleAdminClientNewGet(httpHelper))
		r.Post("/clients/new", adminclienthandlers.HandleAdminClientNewPost(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer))

		r.Get("/resources", adminresourcehandlers.HandleAdminResourcesGet(httpHelper, s.database))
		r.Get("/resources/{resourceId}/settings", adminresourcehandlers.HandleAdminResourceSettingsGet(httpHelper, s.sessionStore, s.database))
		r.Post("/resources/{resourceId}/settings", adminresourcehandlers.HandleAdminResourceSettingsPost(httpHelper, s.sessionStore, authHelper, s.database, identifierValidator, inputSanitizer))
		r.Get("/resources/{resourceId}/permissions", adminresourcehandlers.HandleAdminResourcePermissionsGet(httpHelper, s.sessionStore, s.database))
		r.Post("/resources/{resourceId}/permissions", adminresourcehandlers.HandleAdminResourcePermissionsPost(httpHelper, s.sessionStore, authHelper, s.database, identifierValidator, inputSanitizer))
		r.Post("/resources/validate-permission", adminresourcehandlers.HandleAdminResourceValidatePermissionPost(httpHelper, identifierValidator, inputSanitizer))
		r.Get("/resources/{resourceId}/users-with-permission", adminresourcehandlers.HandleAdminResourceUsersWithPermissionGet(httpHelper, s.sessionStore, s.database))
		r.Post("/resources/{resourceId}/users-with-permission/remove/{userId}/{permissionId}", adminresourcehandlers.HandleAdminResourceUsersWithPermissionRemovePermissionPost(httpHelper, authHelper, s.database))
		r.Get("/resources/{resourceId}/users-with-permission/add/{permissionId}", adminresourcehandlers.HandleAdminResourceUsersWithPermissionAddGet(httpHelper, s.database))
		r.Post("/resources/{resourceId}/users-with-permission/add/{userId}/{permissionId}", adminresourcehandlers.HandleAdminResourceUsersWithPermissionAddPermissionPost(httpHelper, authHelper, s.database))
		r.Get("/resources/{resourceId}/users-with-permission/search/{permissionId}", adminresourcehandlers.HandleAdminResourceUsersWithPermissionSearchGet(httpHelper, s.database))
		r.Get("/resources/{resourceId}/groups-with-permission", adminresourcehandlers.HandleAdminResourceGroupsWithPermissionGet(httpHelper, s.sessionStore, s.database))
		r.Post("/resources/{resourceId}/groups-with-permission/add/{groupId}/{permissionId}", adminresourcehandlers.HandleAdminResourceGroupsWithPermissionAddPermissionPost(httpHelper, authHelper, s.database))
		r.Post("/resources/{resourceId}/groups-with-permission/remove/{groupId}/{permissionId}", adminresourcehandlers.HandleAdminResourceGroupsWithPermissionRemovePermissionPost(httpHelper, authHelper, s.database))
		r.Get("/resources/{resourceId}/delete", adminresourcehandlers.HandleAdminResourceDeleteGet(httpHelper, s.database))
		r.Post("/resources/{resourceId}/delete", adminresourcehandlers.HandleAdminResourceDeletePost(httpHelper, authHelper, s.database))
		r.Get("/resources/new", adminresourcehandlers.HandleAdminResourceNewGet(httpHelper))
		r.Post("/resources/new", adminresourcehandlers.HandleAdminResourceNewPost(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer))

		r.Get("/groups", admingrouphandlers.HandleAdminGroupsGet(httpHelper, s.database))
		r.Get("/groups/{groupId}/settings", admingrouphandlers.HandleAdminGroupSettingsGet(httpHelper, s.sessionStore, s.database))
		r.Get("/groups/{groupId}/attributes", admingrouphandlers.HandleAdminGroupAttributesGet(httpHelper, s.database))
		r.Get("/groups/{groupId}/attributes/add", admingrouphandlers.HandleAdminGroupAttributesAddGet(httpHelper, s.database))
		r.Post("/groups/{groupId}/attributes/add", admingrouphandlers.HandleAdminGroupAttributesAddPost(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer))
		r.Get("/groups/{groupId}/attributes/edit/{attributeId}", admingrouphandlers.HandleAdminGroupAttributesEditGet(httpHelper, s.database))
		r.Post("/groups/{groupId}/attributes/edit/{attributeId}", admingrouphandlers.HandleAdminGroupAttributesEditPost(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer))
		r.Post("/groups/{groupId}/attributes/remove/{attributeId}", admingrouphandlers.HandleAdminGroupAttributesRemovePost(httpHelper, authHelper, s.database))
		r.Post("/groups/{groupId}/settings", admingrouphandlers.HandleAdminGroupSettingsPost(httpHelper, s.sessionStore, authHelper, s.database, identifierValidator, inputSanitizer))
		r.Get("/groups/{groupId}/members", admingrouphandlers.HandleAdminGroupMembersGet(httpHelper, s.database))
		r.Get("/groups/{groupId}/members/add", admingrouphandlers.HandleAdminGroupMembersAddGet(httpHelper, s.database))
		r.Post("/groups/{groupId}/members/add", admingrouphandlers.HandleAdminGroupMembersAddPost(httpHelper, authHelper, s.database))
		r.Post("/groups/{groupId}/members/remove/{userId}", admingrouphandlers.HandleAdminGroupMembersRemoveUserPost(httpHelper, authHelper, s.database))
		r.Get("/groups/{groupId}/members/search", admingrouphandlers.HandleAdminGroupMembersSearchGet(httpHelper, s.database))
		r.Get("/groups/{groupId}/permissions", admingrouphandlers.HandleAdminGroupPermissionsGet(httpHelper, s.sessionStore, s.database))
		r.Post("/groups/{groupId}/permissions", admingrouphandlers.HandleAdminGroupPermissionsPost(httpHelper, s.sessionStore, authHelper, s.database))
		r.Get("/groups/{groupId}/delete", admingrouphandlers.HandleAdminGroupDeleteGet(httpHelper, s.database))
		r.Post("/groups/{groupId}/delete", admingrouphandlers.HandleAdminGroupDeletePost(httpHelper, authHelper, s.database))
		r.Get("/groups/new", admingrouphandlers.HandleAdminGroupNewGet(httpHelper))
		r.Post("/groups/new", admingrouphandlers.HandleAdminGroupNewPost(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer))

		r.Get("/users", adminuserhandlers.HandleAdminUsersGet(httpHelper, s.database))
		r.Get("/users/{userId}/details", adminuserhandlers.HandleAdminUserDetailsGet(httpHelper, s.sessionStore, s.database))
		r.Post("/users/{userId}/details", adminuserhandlers.HandleAdminUserDetailsPost(httpHelper, s.sessionStore, authHelper, s.database))
		r.Get("/users/{userId}/profile", adminuserhandlers.HandleAdminUserProfileGet(httpHelper, s.sessionStore, s.database))
		r.Post("/users/{userId}/profile", adminuserhandlers.HandleAdminUserProfilePost(httpHelper, s.sessionStore, authHelper, s.database, profileValidator, inputSanitizer))
		r.Get("/users/{userId}/email", adminuserhandlers.HandleAdminUserEmailGet(httpHelper, s.sessionStore, s.database))
		r.Post("/users/{userId}/email", adminuserhandlers.HandleAdminUserEmailPost(httpHelper, s.sessionStore, authHelper, s.database, emailValidator, inputSanitizer))
		r.Get("/users/{userId}/phone", adminuserhandlers.HandleAdminUserPhoneGet(httpHelper, s.sessionStore, s.database))
		r.Post("/users/{userId}/phone", adminuserhandlers.HandleAdminUserPhonePost(httpHelper, s.sessionStore, authHelper, s.database, phoneValidator, inputSanitizer))
		r.Get("/users/{userId}/address", adminuserhandlers.HandleAdminUserAddressGet(httpHelper, s.sessionStore, s.database))
		r.Post("/users/{userId}/address", adminuserhandlers.HandleAdminUserAddressPost(httpHelper, s.sessionStore, authHelper, s.database, addressValidator, inputSanitizer))
		r.Get("/users/{userId}/authentication", adminuserhandlers.HandleAdminUserAuthenticationGet(httpHelper, s.sessionStore, s.database))
		r.Post("/users/{userId}/authentication", adminuserhandlers.HandleAdminUserAuthenticationPost(httpHelper, s.sessionStore, authHelper, s.database, passwordValidator))
		r.Get("/users/{userId}/consents", adminuserhandlers.HandleAdminUserConsentsGet(httpHelper, s.sessionStore, s.database))
		r.Post("/users/{userId}/consents", adminuserhandlers.HandleAdminUserConsentsPost(httpHelper, authHelper, s.database))
		r.Get("/users/{userId}/sessions", adminuserhandlers.HandleAdminUserSessionsGet(httpHelper, s.database))
		r.Post("/users/{userId}/sessions", adminuserhandlers.HandleAdminUserSessionsPost(httpHelper, authHelper, s.database))
		r.Get("/users/{userId}/attributes", adminuserhandlers.HandleAdminUserAttributesGet(httpHelper, s.database))
		r.Get("/users/{userId}/attributes/add", adminuserhandlers.HandleAdminUserAttributesAddGet(httpHelper, s.database))
		r.Post("/users/{userId}/attributes/add", adminuserhandlers.HandleAdminUserAttributesAddPost(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer))
		r.Get("/users/{userId}/attributes/edit/{attributeId}", adminuserhandlers.HandleAdminUserAttributesEditGet(httpHelper, s.database))
		r.Post("/users/{userId}/attributes/edit/{attributeId}", adminuserhandlers.HandleAdminUserAttributesEditPost(httpHelper, authHelper, s.database, identifierValidator, inputSanitizer))
		r.Post("/users/{userId}/attributes/remove/{attributeId}", adminuserhandlers.HandleAdminUserAttributesRemovePost(httpHelper, authHelper, s.database))
		r.Get("/users/{userId}/permissions", adminuserhandlers.HandleAdminUserPermissionsGet(httpHelper, s.sessionStore, s.database))
		r.Post("/users/{userId}/permissions", adminuserhandlers.HandleAdminUserPermissionsPost(httpHelper, s.sessionStore, authHelper, s.database))
		r.Get("/users/{userId}/groups", adminuserhandlers.HandleAdminUserGroupsGet(httpHelper, s.sessionStore, s.database))
		r.Post("/users/{userId}/groups", adminuserhandlers.HandleAdminUserGroupsPost(httpHelper, s.sessionStore, authHelper, s.database))
		r.Get("/users/{userId}/delete", adminuserhandlers.HandleAdminUserDeleteGet(httpHelper, s.database))
		r.Post("/users/{userId}/delete", adminuserhandlers.HandleAdminUserDeletePost(httpHelper, authHelper, s.database))
		r.Get("/users/new", adminuserhandlers.HandleAdminUserNewGet(httpHelper))
		r.Post("/users/new", adminuserhandlers.HandleAdminUserNewPost(httpHelper, s.sessionStore, authHelper, s.database, userCreator, profileValidator, emailValidator, passwordValidator, inputSanitizer, emailSender))

		r.Get("/settings/general", adminsettingshandlers.HandleAdminSettingsGeneralGet(httpHelper, s.sessionStore))
		r.Post("/settings/general", adminsettingshandlers.HandleAdminSettingsGeneralPost(httpHelper, s.sessionStore, authHelper, s.database, inputSanitizer))
		r.Get("/settings/ui-theme", adminsettingshandlers.HandleAdminSettingsUIThemeGet(httpHelper, s.sessionStore))
		r.Post("/settings/ui-theme", adminsettingshandlers.HandleAdminSettingsUIThemePost(httpHelper, s.sessionStore, authHelper, s.database))
		r.Get("/settings/sessions", adminsettingshandlers.HandleAdminSettingsSessionsGet(httpHelper, s.sessionStore))
		r.Post("/settings/sessions", adminsettingshandlers.HandleAdminSettingsSessionsPost(httpHelper, s.sessionStore, authHelper, s.database))
		r.Get("/settings/tokens", adminsettingshandlers.HandleAdminSettingsTokensGet(httpHelper, s.sessionStore))
		r.Post("/settings/tokens", adminsettingshandlers.HandleAdminSettingsTokensPost(httpHelper, s.sessionStore, authHelper, s.database))
		r.Get("/settings/keys", adminsettingshandlers.HandleAdminSettingsKeysGet(httpHelper, s.database))
		r.Post("/settings/keys/rotate", adminsettingshandlers.HandleAdminSettingsKeysRotatePost(httpHelper, authHelper, s.database))
		r.Post("/settings/keys/revoke", adminsettingshandlers.HandleAdminSettingsKeysRevokePost(httpHelper, authHelper, s.database))
		r.Get("/settings/email", adminsettingshandlers.HandleAdminSettingsEmailGet(httpHelper, s.sessionStore))
		r.Post("/settings/email", adminsettingshandlers.HandleAdminSettingsEmailPost(httpHelper, s.sessionStore, authHelper, s.database, emailValidator, inputSanitizer))
		r.Get("/settings/email/send-test-email", adminsettingshandlers.HandleAdminSettingsEmailSendTestGet(httpHelper, s.sessionStore))
		r.Post("/settings/email/send-test-email", adminsettingshandlers.HandleAdminSettingsEmailSendTestPost(httpHelper, s.sessionStore, emailValidator, emailSender))
		r.Get("/settings/sms", adminsettingshandlers.HandleAdminSettingsSMSGet(httpHelper, s.sessionStore))
		r.Post("/settings/sms", adminsettingshandlers.HandleAdminSettingsSMSPost(httpHelper, s.sessionStore, authHelper, s.database))
	})
}
