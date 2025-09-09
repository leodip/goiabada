package server

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminclienthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/admingrouphandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminresourcehandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminuserhandlers"
	"github.com/leodip/goiabada/adminconsole/internal/middleware"
	"github.com/leodip/goiabada/core/audit"
	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/inputsanitizer"
	custom_middleware "github.com/leodip/goiabada/core/middleware"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/otp"
	"github.com/leodip/goiabada/core/validators"
)

func (s *Server) initRoutes() {
	// Initialize all the service dependencies
	apiClient := apiclient.NewAuthServerClient()

	tokenParser := oauth.NewTokenParser(s.database)
	tokenExchanger := oauth.NewTokenExchanger()

	passwordValidator := validators.NewPasswordValidator()
	identifierValidator := validators.NewIdentifierValidator(s.database)
	inputSanitizer := inputsanitizer.NewInputSanitizer()

	otpSecretGenerator := otp.NewOTPSecretGenerator()
	emailSender := communication.NewEmailSender()

	auditLogger := audit.NewAuditLogger(config.GetAdminConsole().AuditLogsInConsole)

	httpHelper := handlerhelpers.NewHttpHelper(s.templateFS, s.database)
	authHelper := handlerhelpers.NewAuthHelper(s.sessionStore, config.GetAdminConsole().BaseURL, config.GetAuthServer().BaseURL)

	// Initialize middleware
	middlewareJwt := custom_middleware.NewMiddlewareJwt(s.sessionStore, tokenParser, s.database, authHelper, &http.Client{}, config.GetAuthServer().BaseURL, config.GetAdminConsole().BaseURL)
	jwtSessionHandler := middlewareJwt.JwtSessionHandler()
	requiresAdminScope := middlewareJwt.RequiresScope([]string{fmt.Sprintf("%v:%v", constants.AdminConsoleResourceIdentifier, constants.ManageAdminConsolePermissionIdentifier)})
	requiresAccountScope := middlewareJwt.RequiresScope([]string{fmt.Sprintf("%v:%v", constants.AdminConsoleResourceIdentifier, constants.ManageAccountPermissionIdentifier)})
	sessionIdentifierToContext := middleware.SessionIdentifierToContext()

	// Define middleware combinations
	baseAuth := []func(http.Handler) http.Handler{
		jwtSessionHandler,
		sessionIdentifierToContext,
	}

	accountAuth := []func(http.Handler) http.Handler{
		jwtSessionHandler,
		sessionIdentifierToContext,
		requiresAccountScope,
	}

	adminAuth := []func(http.Handler) http.Handler{
		jwtSessionHandler,
		sessionIdentifierToContext,
		requiresAdminScope,
	}

	// Base routes
	s.router.NotFound(handlers.HandleNotFoundGet(httpHelper))
	s.router.With(baseAuth...).Get("/", handlers.HandleIndexGet(authHelper, httpHelper))
	s.router.Get("/unauthorized", handlers.HandleUnauthorizedGet(httpHelper))
	s.router.Get("/health", handlers.HandleHealthCheckGet(httpHelper))

	// Auth routes
	s.router.With(baseAuth...).Route("/auth", func(r chi.Router) {
		r.Post("/callback", handlers.HandleAuthCallbackPost(httpHelper, s.sessionStore, s.database, s.tokenParser, tokenExchanger))
		r.Get("/logout", accounthandlers.HandleAccountLogoutGet(httpHelper, s.sessionStore, s.database))
	})

	// Account routes
	s.router.Route("/account", func(r chi.Router) {
		r.Use(accountAuth...)

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, config.GetAdminConsole().BaseURL+"/account/profile", http.StatusFound)
		})
		r.Get("/profile", accounthandlers.HandleAccountProfileGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/profile", accounthandlers.HandleAccountProfilePost(httpHelper, s.sessionStore, apiClient))
		r.Get("/email", accounthandlers.HandleAccountEmailGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/email", accounthandlers.HandleAccountEmailPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/email-verification", accounthandlers.HandleAccountEmailVerificationGet(httpHelper, s.sessionStore, authHelper, s.database))
		r.Post("/email-send-verification", accounthandlers.HandleAccountEmailSendVerificationPost(httpHelper, authHelper, s.database, emailSender, auditLogger))
		r.Post("/email-verification", accounthandlers.HandleAccountEmailVerificationPost(httpHelper, s.sessionStore, authHelper, s.database, auditLogger))
		r.Get("/address", accounthandlers.HandleAccountAddressGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/address", accounthandlers.HandleAccountAddressPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/phone", accounthandlers.HandleAccountPhoneGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/phone", accounthandlers.HandleAccountPhonePost(httpHelper, s.sessionStore, apiClient))
		r.Get("/change-password", accounthandlers.HandleAccountChangePasswordGet(httpHelper, authHelper))
		r.Post("/change-password", accounthandlers.HandleAccountChangePasswordPost(httpHelper, authHelper, s.database, passwordValidator, auditLogger))
		r.Get("/otp", accounthandlers.HandleAccountOtpGet(httpHelper, s.sessionStore, authHelper, s.database, otpSecretGenerator))
		r.Post("/otp", accounthandlers.HandleAccountOtpPost(httpHelper, s.sessionStore, authHelper, s.database, auditLogger))
		r.Get("/manage-consents", accounthandlers.HandleAccountManageConsentsGet(httpHelper, authHelper, s.database))
		r.Post("/manage-consents", accounthandlers.HandleAccountManageConsentsRevokePost(httpHelper, authHelper, s.database, auditLogger))
		r.Get("/sessions", accounthandlers.HandleAccountSessionsGet(httpHelper, authHelper, s.database))
		r.Post("/sessions", accounthandlers.HandleAccountSessionsEndSesssionPost(httpHelper, authHelper, s.database, auditLogger))
	})

	// Admin routes
	s.router.Route("/admin", func(r chi.Router) {
		r.Use(adminAuth...)

		r.Get("/get-permissions", handlers.HandleAdminGetPermissionsGet(httpHelper, apiClient))

		// Client routes
		r.Get("/clients", adminclienthandlers.HandleAdminClientsGet(httpHelper, apiClient))
		r.Get("/clients/{clientId}/settings", adminclienthandlers.HandleAdminClientSettingsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/clients/{clientId}/settings", adminclienthandlers.HandleAdminClientSettingsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/clients/{clientId}/tokens", adminclienthandlers.HandleAdminClientTokensGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/clients/{clientId}/tokens", adminclienthandlers.HandleAdminClientTokensPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/clients/{clientId}/authentication", adminclienthandlers.HandleAdminClientAuthenticationGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/clients/{clientId}/authentication", adminclienthandlers.HandleAdminClientAuthenticationPost(httpHelper, s.sessionStore, authHelper, apiClient))
		r.Get("/clients/{clientId}/oauth2-flows", adminclienthandlers.HandleAdminClientOAuth2Get(httpHelper, s.sessionStore, apiClient))
		r.Post("/clients/{clientId}/oauth2-flows", adminclienthandlers.HandleAdminClientOAuth2Post(httpHelper, s.sessionStore, apiClient))
		r.Get("/clients/{clientId}/redirect-uris", adminclienthandlers.HandleAdminClientRedirectURIsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/clients/{clientId}/redirect-uris", adminclienthandlers.HandleAdminClientRedirectURIsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/clients/{clientId}/web-origins", adminclienthandlers.HandleAdminClientWebOriginsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/clients/{clientId}/web-origins", adminclienthandlers.HandleAdminClientWebOriginsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/clients/{clientId}/user-sessions", adminclienthandlers.HandleAdminClientUserSessionsGet(httpHelper, apiClient))
		r.Post("/clients/{clientId}/user-sessions/delete", adminclienthandlers.HandleAdminClientUserSessionsPost(httpHelper, apiClient))
		r.Get("/clients/{clientId}/permissions", adminclienthandlers.HandleAdminClientPermissionsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/clients/{clientId}/permissions", adminclienthandlers.HandleAdminClientPermissionsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/clients/generate-new-secret", adminclienthandlers.HandleAdminClientGenerateNewSecretGet(httpHelper))
		r.Get("/clients/{clientId}/delete", adminclienthandlers.HandleAdminClientDeleteGet(httpHelper, apiClient))
		r.Post("/clients/{clientId}/delete", adminclienthandlers.HandleAdminClientDeletePost(httpHelper, apiClient))
		r.Get("/clients/new", adminclienthandlers.HandleAdminClientNewGet(httpHelper))
		r.Post("/clients/new", adminclienthandlers.HandleAdminClientNewPost(httpHelper, apiClient))

		// Resource routes
		r.Get("/resources", adminresourcehandlers.HandleAdminResourcesGet(httpHelper, apiClient))
		r.Get("/resources/{resourceId}/settings", adminresourcehandlers.HandleAdminResourceSettingsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/resources/{resourceId}/settings", adminresourcehandlers.HandleAdminResourceSettingsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/resources/{resourceId}/permissions", adminresourcehandlers.HandleAdminResourcePermissionsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/resources/{resourceId}/permissions", adminresourcehandlers.HandleAdminResourcePermissionsPost(httpHelper, s.sessionStore, apiClient))
		r.Post("/resources/validate-permission", adminresourcehandlers.HandleAdminResourceValidatePermissionPost(httpHelper, identifierValidator, inputSanitizer))
		r.Get("/resources/{resourceId}/users-with-permission", adminresourcehandlers.HandleAdminResourceUsersWithPermissionGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/resources/{resourceId}/users-with-permission/remove/{userId}/{permissionId}", adminresourcehandlers.HandleAdminResourceUsersWithPermissionRemovePermissionPost(httpHelper, apiClient))
		r.Get("/resources/{resourceId}/users-with-permission/add/{permissionId}", adminresourcehandlers.HandleAdminResourceUsersWithPermissionAddGet(httpHelper, apiClient))
		r.Post("/resources/{resourceId}/users-with-permission/add/{userId}/{permissionId}", adminresourcehandlers.HandleAdminResourceUsersWithPermissionAddPermissionPost(httpHelper, apiClient))
		r.Get("/resources/{resourceId}/users-with-permission/search/{permissionId}", adminresourcehandlers.HandleAdminResourceUsersWithPermissionSearchGet(httpHelper, apiClient))
		r.Get("/resources/{resourceId}/groups-with-permission", adminresourcehandlers.HandleAdminResourceGroupsWithPermissionGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/resources/{resourceId}/groups-with-permission/add/{groupId}/{permissionId}", adminresourcehandlers.HandleAdminResourceGroupsWithPermissionAddPermissionPost(httpHelper, apiClient))
		r.Post("/resources/{resourceId}/groups-with-permission/remove/{groupId}/{permissionId}", adminresourcehandlers.HandleAdminResourceGroupsWithPermissionRemovePermissionPost(httpHelper, apiClient))
		r.Get("/resources/{resourceId}/delete", adminresourcehandlers.HandleAdminResourceDeleteGet(httpHelper, apiClient))
		r.Post("/resources/{resourceId}/delete", adminresourcehandlers.HandleAdminResourceDeletePost(httpHelper, apiClient))
		r.Get("/resources/new", adminresourcehandlers.HandleAdminResourceNewGet(httpHelper))
		r.Post("/resources/new", adminresourcehandlers.HandleAdminResourceNewPost(httpHelper, apiClient))

		// Group routes
		r.Get("/groups", admingrouphandlers.HandleAdminGroupsGet(httpHelper, apiClient))
		r.Get("/groups/{groupId}/settings", admingrouphandlers.HandleAdminGroupSettingsGet(httpHelper, s.sessionStore, apiClient))
		r.Get("/groups/{groupId}/attributes", admingrouphandlers.HandleAdminGroupAttributesGet(httpHelper, apiClient))
		r.Get("/groups/{groupId}/attributes/add", admingrouphandlers.HandleAdminGroupAttributesAddGet(httpHelper, apiClient))
		r.Post("/groups/{groupId}/attributes/add", admingrouphandlers.HandleAdminGroupAttributesAddPost(httpHelper, apiClient))
		r.Get("/groups/{groupId}/attributes/edit/{attributeId}", admingrouphandlers.HandleAdminGroupAttributesEditGet(httpHelper, apiClient))
		r.Post("/groups/{groupId}/attributes/edit/{attributeId}", admingrouphandlers.HandleAdminGroupAttributesEditPost(httpHelper, apiClient))
		r.Post("/groups/{groupId}/attributes/remove/{attributeId}", admingrouphandlers.HandleAdminGroupAttributesRemovePost(httpHelper, apiClient))
		r.Post("/groups/{groupId}/settings", admingrouphandlers.HandleAdminGroupSettingsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/groups/{groupId}/members", admingrouphandlers.HandleAdminGroupMembersGet(httpHelper, apiClient))
		r.Get("/groups/{groupId}/members/add", admingrouphandlers.HandleAdminGroupMembersAddGet(httpHelper, apiClient))
		r.Post("/groups/{groupId}/members/add", admingrouphandlers.HandleAdminGroupMembersAddPost(httpHelper, apiClient))
		r.Post("/groups/{groupId}/members/remove/{userId}", admingrouphandlers.HandleAdminGroupMembersRemoveUserPost(httpHelper, apiClient))
		r.Get("/groups/{groupId}/members/search", admingrouphandlers.HandleAdminGroupMembersSearchGet(httpHelper, apiClient))
		r.Get("/groups/{groupId}/permissions", admingrouphandlers.HandleAdminGroupPermissionsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/groups/{groupId}/permissions", admingrouphandlers.HandleAdminGroupPermissionsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/groups/{groupId}/delete", admingrouphandlers.HandleAdminGroupDeleteGet(httpHelper, apiClient))
		r.Post("/groups/{groupId}/delete", admingrouphandlers.HandleAdminGroupDeletePost(httpHelper, apiClient))
		r.Get("/groups/new", admingrouphandlers.HandleAdminGroupNewGet(httpHelper))
		r.Post("/groups/new", admingrouphandlers.HandleAdminGroupNewPost(httpHelper, apiClient))

		// User routes
		r.Get("/users", adminuserhandlers.HandleAdminUsersGet(httpHelper, apiClient))
		r.Get("/users/{userId}/details", adminuserhandlers.HandleAdminUserDetailsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/details", adminuserhandlers.HandleAdminUserDetailsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/users/{userId}/profile", adminuserhandlers.HandleAdminUserProfileGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/profile", adminuserhandlers.HandleAdminUserProfilePost(httpHelper, s.sessionStore, apiClient))
		r.Get("/users/{userId}/email", adminuserhandlers.HandleAdminUserEmailGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/email", adminuserhandlers.HandleAdminUserEmailPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/users/{userId}/phone", adminuserhandlers.HandleAdminUserPhoneGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/phone", adminuserhandlers.HandleAdminUserPhonePost(httpHelper, s.sessionStore, apiClient))
		r.Get("/users/{userId}/address", adminuserhandlers.HandleAdminUserAddressGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/address", adminuserhandlers.HandleAdminUserAddressPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/users/{userId}/authentication", adminuserhandlers.HandleAdminUserAuthenticationGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/authentication", adminuserhandlers.HandleAdminUserAuthenticationPost(httpHelper, s.sessionStore, authHelper, apiClient, s.sessionStore))
		r.Get("/users/{userId}/consents", adminuserhandlers.HandleAdminUserConsentsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/consents", adminuserhandlers.HandleAdminUserConsentsPost(httpHelper, authHelper, apiClient, auditLogger))
		r.Get("/users/{userId}/sessions", adminuserhandlers.HandleAdminUserSessionsGet(httpHelper, apiClient))
		r.Post("/users/{userId}/sessions", adminuserhandlers.HandleAdminUserSessionsPost(httpHelper, authHelper, apiClient))
		r.Get("/users/{userId}/attributes", adminuserhandlers.HandleAdminUserAttributesGet(httpHelper, apiClient))
		r.Get("/users/{userId}/attributes/add", adminuserhandlers.HandleAdminUserAttributesAddGet(httpHelper, apiClient))
		r.Post("/users/{userId}/attributes/add", adminuserhandlers.HandleAdminUserAttributesAddPost(httpHelper, apiClient))
		r.Get("/users/{userId}/attributes/edit/{attributeId}", adminuserhandlers.HandleAdminUserAttributesEditGet(httpHelper, apiClient))
		r.Post("/users/{userId}/attributes/edit/{attributeId}", adminuserhandlers.HandleAdminUserAttributesEditPost(httpHelper, apiClient))
		r.Post("/users/{userId}/attributes/remove/{attributeId}", adminuserhandlers.HandleAdminUserAttributesRemovePost(httpHelper, apiClient))
		r.Get("/users/{userId}/permissions", adminuserhandlers.HandleAdminUserPermissionsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/permissions", adminuserhandlers.HandleAdminUserPermissionsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/users/{userId}/groups", adminuserhandlers.HandleAdminUserGroupsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/groups", adminuserhandlers.HandleAdminUserGroupsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/users/{userId}/delete", adminuserhandlers.HandleAdminUserDeleteGet(httpHelper, apiClient))
		r.Post("/users/{userId}/delete", adminuserhandlers.HandleAdminUserDeletePost(httpHelper, apiClient))
		r.Get("/users/new", adminuserhandlers.HandleAdminUserNewGet(httpHelper))
		r.Post("/users/new", adminuserhandlers.HandleAdminUserNewPost(httpHelper, s.sessionStore, apiClient))

		// Settings routes
		r.Get("/settings/general", adminsettingshandlers.HandleAdminSettingsGeneralGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/settings/general", adminsettingshandlers.HandleAdminSettingsGeneralPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/settings/ui-theme", adminsettingshandlers.HandleAdminSettingsUIThemeGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/settings/ui-theme", adminsettingshandlers.HandleAdminSettingsUIThemePost(httpHelper, s.sessionStore, apiClient))
		r.Get("/settings/sessions", adminsettingshandlers.HandleAdminSettingsSessionsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/settings/sessions", adminsettingshandlers.HandleAdminSettingsSessionsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/settings/tokens", adminsettingshandlers.HandleAdminSettingsTokensGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/settings/tokens", adminsettingshandlers.HandleAdminSettingsTokensPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/settings/keys", adminsettingshandlers.HandleAdminSettingsKeysGet(httpHelper, apiClient))
		r.Post("/settings/keys/rotate", adminsettingshandlers.HandleAdminSettingsKeysRotatePost(httpHelper, apiClient))
		r.Post("/settings/keys/revoke", adminsettingshandlers.HandleAdminSettingsKeysRevokePost(httpHelper, apiClient))
		r.Get("/settings/email", adminsettingshandlers.HandleAdminSettingsEmailGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/settings/email", adminsettingshandlers.HandleAdminSettingsEmailPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/settings/email/send-test-email", adminsettingshandlers.HandleAdminSettingsEmailSendTestGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/settings/email/send-test-email", adminsettingshandlers.HandleAdminSettingsEmailSendTestPost(httpHelper, s.sessionStore, apiClient))
	})
}
