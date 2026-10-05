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
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/inputvalidation"
)

func (s *Server) initRoutes(root chi.Router) {
	// The console's own base URL, which every redirect is built from, handed to each handler that
	// redirects as it is built (#441).
	baseURL := s.cfg.AdminConsole.BaseURL

	// Prefer internal base URL for in-cluster communication
	authBase := s.cfg.AuthServer.GetEffectiveBaseURL()

	// Initialize all the service dependencies
	apiClient := apiclient.NewAuthServerClient(authBase, s.upstream)

	// The HTTP client and the token client are main's, the same pair the session token source
	// was built on, so the sign-in's exchange, the refresh and the client-credentials grant are one
	// client with one token URL, and the JWKS fetch shares its HTTP client (#441).
	tokenParser := oauthclient.NewJWKSTokenParser(authBase, s.authServerHTTPClient, s.upstream, builtin.AdminConsoleClientIdentifier, middleware.SettingsReader{})
	tokenClient := s.tokenClient

	identifierValidator := inputvalidation.NewIdentifierValidator()

	httpHelper := render.New(s.templateFS)
	authHelper := oauthclient.NewAuthHelper(s.sessionStore, builtin.AdminConsoleSessionName, baseURL, s.cfg.AuthServer.BaseURL)

	// Initialize middleware
	middlewareJwt := middleware.NewJWT(
		s.sessionStore,
		builtin.AdminConsoleSessionName,
		tokenParser,
		tokenClient,
		authHelper,
		httpHelper,
		baseURL,
		builtin.AdminConsoleClientIdentifier,
	)
	jwtSessionHandler := middlewareJwt.SessionHandler()
	requiresAdminScope := middlewareJwt.RequiresScope([]string{fmt.Sprintf("%v:%v", builtin.AuthServerResourceIdentifier, builtin.ManagePermissionIdentifier)})
	requiresAccountScope := middlewareJwt.RequiresScope([]string{fmt.Sprintf("%v:%v", builtin.AuthServerResourceIdentifier, builtin.ManageAccountPermissionIdentifier)})
	// User-locale refinement sits inside each authenticated chain immediately
	// after JWT validation. It reads the locale claim from the validated JWT
	// (requires the profile scope, see middleware_jwt.buildScopeString) and
	// refines the localizer to the user's stored locale unless explicit
	// request intent (?ui_locales or in-flight AuthContext.UILocales) is
	// present. Falls through to the existing localizer if the claim is
	// missing — never silently jumps to English.
	localeFromJWT := middleware.LocaleFromJWT()

	// Define middleware combinations
	baseAuth := []func(http.Handler) http.Handler{
		jwtSessionHandler,
		localeFromJWT,
	}

	accountAuth := []func(http.Handler) http.Handler{
		jwtSessionHandler,
		localeFromJWT,
		requiresAccountScope,
	}

	adminAuth := []func(http.Handler) http.Handler{
		jwtSessionHandler,
		localeFromJWT,
		requiresAdminScope,
	}

	// Base routes
	root.NotFound(handlers.HandleNotFoundGet(httpHelper))
	root.With(baseAuth...).Get("/", handlers.HandleIndexGet(authHelper, httpHelper, s.sessionStore, s.cfg.AuthServer.BaseURL))
	// /unauthorized is reached by authenticated-but-forbidden users via the
	// redirect in middleware_jwt's RequiresScope path. Wrapping it through
	// baseAuth lets the user-locale refinement fire so the page renders
	// in the user's stored locale. baseAuth tolerates missing-permission
	// cases — the whole point of this page is that the user is
	// authenticated but not authorized.
	root.With(baseAuth...).Get("/unauthorized", handlers.HandleUnauthorizedGet(httpHelper))

	// Auth routes
	root.With(baseAuth...).Route("/auth", func(r chi.Router) {
		r.Post("/callback", handlers.HandleAuthCallbackPost(httpHelper, s.sessionStore, tokenParser, tokenClient))
		r.Get("/logout", accounthandlers.HandleLogoutGet(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/session-ended", handlers.HandleSessionEndedGet(httpHelper, s.sessionStore))
	})

	// Account routes
	root.Route("/account", func(r chi.Router) {
		r.Use(accountAuth...)

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, baseURL+"/account/profile", http.StatusFound)
		})
		r.Get("/profile", accounthandlers.HandleProfileGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/profile", accounthandlers.HandleProfilePost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/email", accounthandlers.HandleEmailGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/email", accounthandlers.HandleEmailPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/email-verification", accounthandlers.HandleEmailVerificationGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/email-send-verification", accounthandlers.HandleEmailSendVerificationPost(httpHelper, apiClient))
		r.Post("/email-verification", accounthandlers.HandleEmailVerificationPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/address", accounthandlers.HandleAddressGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/address", accounthandlers.HandleAddressPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/phone", accounthandlers.HandlePhoneGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/phone", accounthandlers.HandlePhonePost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/change-password", accounthandlers.HandleChangePasswordGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/change-password", accounthandlers.HandleChangePasswordPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/otp", accounthandlers.HandleOtpGet(httpHelper, apiClient))
		r.Post("/otp", accounthandlers.HandleOtpPost(httpHelper, apiClient, baseURL))
		r.Get("/manage-consents", accounthandlers.HandleManageConsentsGet(httpHelper, apiClient))
		r.Post("/manage-consents", accounthandlers.HandleManageConsentsRevokePost(httpHelper, apiClient))
		r.Get("/sessions", accounthandlers.HandleSessionsGet(httpHelper, apiClient))
		r.Post("/sessions", accounthandlers.HandleSessionsEndSessionPost(httpHelper, apiClient))

		// Profile picture page and API routes
		r.Get("/picture", accounthandlers.HandlePictureGet(httpHelper, apiClient))
		r.Post("/picture", accounthandlers.HandleProfilePicturePost(httpHelper, apiClient))
		r.Delete("/picture", accounthandlers.HandleProfilePictureDelete(httpHelper, apiClient))
	})

	// Admin routes
	root.Route("/admin", func(r chi.Router) {
		r.Use(adminAuth...)

		r.Get("/get-permissions", handlers.HandleAdminGetPermissionsGet(httpHelper, apiClient))

		// Client routes
		r.Get("/clients", adminclienthandlers.HandleListGet(httpHelper, apiClient))
		r.Get("/clients/{clientId}/settings", adminclienthandlers.HandleSettingsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/clients/{clientId}/settings", adminclienthandlers.HandleSettingsPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/clients/{clientId}/tokens", adminclienthandlers.HandleTokensGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/clients/{clientId}/tokens", adminclienthandlers.HandleTokensPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/clients/{clientId}/authentication", adminclienthandlers.HandleAuthenticationGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/clients/{clientId}/authentication", adminclienthandlers.HandleAuthenticationPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/clients/{clientId}/oauth2-flows", adminclienthandlers.HandleOAuth2FlowsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/clients/{clientId}/oauth2-flows", adminclienthandlers.HandleOAuth2FlowsPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/clients/{clientId}/redirect-uris", adminclienthandlers.HandleRedirectURIsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/clients/{clientId}/redirect-uris", adminclienthandlers.HandleRedirectURIsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/clients/{clientId}/web-origins", adminclienthandlers.HandleWebOriginsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/clients/{clientId}/web-origins", adminclienthandlers.HandleWebOriginsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/clients/{clientId}/user-sessions", adminclienthandlers.HandleUserSessionsGet(httpHelper, apiClient))
		r.Post("/clients/{clientId}/user-sessions/delete", adminclienthandlers.HandleUserSessionsPost(httpHelper, apiClient))
		r.Get("/clients/{clientId}/permissions", adminclienthandlers.HandlePermissionsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/clients/{clientId}/permissions", adminclienthandlers.HandlePermissionsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/clients/generate-new-secret", adminclienthandlers.HandleGenerateNewSecretGet(httpHelper))
		r.Get("/clients/{clientId}/delete", adminclienthandlers.HandleDeleteGet(httpHelper, apiClient))
		r.Post("/clients/{clientId}/delete", adminclienthandlers.HandleDeletePost(httpHelper, apiClient, baseURL))
		r.Get("/clients/{clientId}/logo", adminclienthandlers.HandleLogoGet(httpHelper, apiClient))
		r.Post("/clients/{clientId}/logo", adminclienthandlers.HandleLogoPost(httpHelper, apiClient))
		r.Delete("/clients/{clientId}/logo", adminclienthandlers.HandleLogoDelete(httpHelper, apiClient))
		r.Get("/clients/new", adminclienthandlers.HandleNewGet(httpHelper))
		r.Post("/clients/new", adminclienthandlers.HandleNewPost(httpHelper, apiClient, baseURL))

		// Resource routes
		r.Get("/resources", adminresourcehandlers.HandleListGet(httpHelper, apiClient))
		r.Get("/resources/{resourceId}/settings", adminresourcehandlers.HandleSettingsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/resources/{resourceId}/settings", adminresourcehandlers.HandleSettingsPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/resources/{resourceId}/permissions", adminresourcehandlers.HandlePermissionsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/resources/{resourceId}/permissions", adminresourcehandlers.HandlePermissionsPost(httpHelper, s.sessionStore, apiClient))
		r.Post("/resources/validate-permission", adminresourcehandlers.HandleValidatePermissionPost(httpHelper, identifierValidator))
		r.Get("/resources/{resourceId}/users-with-permission", adminresourcehandlers.HandleUsersWithPermissionGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/resources/{resourceId}/users-with-permission/remove/{userId}/{permissionId}", adminresourcehandlers.HandleUsersWithPermissionRemovePermissionPost(httpHelper, apiClient))
		r.Get("/resources/{resourceId}/users-with-permission/add/{permissionId}", adminresourcehandlers.HandleUsersWithPermissionAddGet(httpHelper, apiClient))
		r.Post("/resources/{resourceId}/users-with-permission/add/{userId}/{permissionId}", adminresourcehandlers.HandleUsersWithPermissionAddPermissionPost(httpHelper, apiClient))
		r.Get("/resources/{resourceId}/users-with-permission/search/{permissionId}", adminresourcehandlers.HandleUsersWithPermissionSearchGet(httpHelper, apiClient))
		r.Get("/resources/{resourceId}/groups-with-permission", adminresourcehandlers.HandleGroupsWithPermissionGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/resources/{resourceId}/groups-with-permission/add/{groupId}/{permissionId}", adminresourcehandlers.HandleGroupsWithPermissionAddPermissionPost(httpHelper, apiClient))
		r.Post("/resources/{resourceId}/groups-with-permission/remove/{groupId}/{permissionId}", adminresourcehandlers.HandleGroupsWithPermissionRemovePermissionPost(httpHelper, apiClient))
		r.Get("/resources/{resourceId}/delete", adminresourcehandlers.HandleDeleteGet(httpHelper, apiClient))
		r.Post("/resources/{resourceId}/delete", adminresourcehandlers.HandleDeletePost(httpHelper, apiClient, baseURL))
		r.Get("/resources/new", adminresourcehandlers.HandleNewGet(httpHelper))
		r.Post("/resources/new", adminresourcehandlers.HandleNewPost(httpHelper, apiClient, baseURL))

		// Group routes
		r.Get("/groups", admingrouphandlers.HandleListGet(httpHelper, apiClient))
		r.Get("/groups/{groupId}/settings", admingrouphandlers.HandleSettingsGet(httpHelper, s.sessionStore, apiClient))
		r.Get("/groups/{groupId}/attributes", admingrouphandlers.HandleAttributesGet(httpHelper, apiClient))
		r.Get("/groups/{groupId}/attributes/add", admingrouphandlers.HandleAttributesAddGet(httpHelper, apiClient))
		r.Post("/groups/{groupId}/attributes/add", admingrouphandlers.HandleAttributesAddPost(httpHelper, apiClient))
		r.Get("/groups/{groupId}/attributes/edit/{attributeId}", admingrouphandlers.HandleAttributesEditGet(httpHelper, apiClient))
		r.Post("/groups/{groupId}/attributes/edit/{attributeId}", admingrouphandlers.HandleAttributesEditPost(httpHelper, apiClient))
		r.Post("/groups/{groupId}/attributes/remove/{attributeId}", admingrouphandlers.HandleAttributesRemovePost(httpHelper, apiClient))
		r.Post("/groups/{groupId}/settings", admingrouphandlers.HandleSettingsPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/groups/{groupId}/members", admingrouphandlers.HandleMembersGet(httpHelper, apiClient))
		r.Get("/groups/{groupId}/members/add", admingrouphandlers.HandleMembersAddGet(httpHelper, apiClient))
		r.Post("/groups/{groupId}/members/add", admingrouphandlers.HandleMembersAddPost(httpHelper, apiClient))
		r.Post("/groups/{groupId}/members/remove/{userId}", admingrouphandlers.HandleMembersRemoveUserPost(httpHelper, apiClient))
		r.Get("/groups/{groupId}/members/search", admingrouphandlers.HandleMembersSearchGet(httpHelper, apiClient))
		r.Get("/groups/{groupId}/permissions", admingrouphandlers.HandlePermissionsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/groups/{groupId}/permissions", admingrouphandlers.HandlePermissionsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/groups/{groupId}/delete", admingrouphandlers.HandleDeleteGet(httpHelper, apiClient))
		r.Post("/groups/{groupId}/delete", admingrouphandlers.HandleDeletePost(httpHelper, apiClient, baseURL))
		r.Get("/groups/new", admingrouphandlers.HandleNewGet(httpHelper))
		r.Post("/groups/new", admingrouphandlers.HandleNewPost(httpHelper, apiClient, baseURL))

		// User routes
		r.Get("/users", adminuserhandlers.HandleListGet(httpHelper, apiClient))
		r.Get("/users/{userId}/details", adminuserhandlers.HandleDetailsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/details", adminuserhandlers.HandleDetailsPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/users/{userId}/profile", adminuserhandlers.HandleProfileGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/profile", adminuserhandlers.HandleProfilePost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/users/{userId}/email", adminuserhandlers.HandleEmailGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/email", adminuserhandlers.HandleEmailPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/users/{userId}/phone", adminuserhandlers.HandlePhoneGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/phone", adminuserhandlers.HandlePhonePost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/users/{userId}/address", adminuserhandlers.HandleAddressGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/address", adminuserhandlers.HandleAddressPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/users/{userId}/authentication", adminuserhandlers.HandleAuthenticationGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/authentication", adminuserhandlers.HandleAuthenticationPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/users/{userId}/consents", adminuserhandlers.HandleConsentsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/consents", adminuserhandlers.HandleConsentsPost(httpHelper, apiClient))
		r.Get("/users/{userId}/sessions", adminuserhandlers.HandleSessionsGet(httpHelper, apiClient))
		r.Post("/users/{userId}/sessions", adminuserhandlers.HandleSessionsPost(httpHelper, apiClient))
		r.Get("/users/{userId}/attributes", adminuserhandlers.HandleAttributesGet(httpHelper, apiClient))
		r.Get("/users/{userId}/attributes/add", adminuserhandlers.HandleAttributesAddGet(httpHelper, apiClient))
		r.Post("/users/{userId}/attributes/add", adminuserhandlers.HandleAttributesAddPost(httpHelper, apiClient, baseURL))
		r.Get("/users/{userId}/attributes/edit/{attributeId}", adminuserhandlers.HandleAttributesEditGet(httpHelper, apiClient))
		r.Post("/users/{userId}/attributes/edit/{attributeId}", adminuserhandlers.HandleAttributesEditPost(httpHelper, apiClient, baseURL))
		r.Post("/users/{userId}/attributes/remove/{attributeId}", adminuserhandlers.HandleAttributesRemovePost(httpHelper, apiClient))
		r.Get("/users/{userId}/permissions", adminuserhandlers.HandlePermissionsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/permissions", adminuserhandlers.HandlePermissionsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/users/{userId}/groups", adminuserhandlers.HandleGroupsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/users/{userId}/groups", adminuserhandlers.HandleGroupsPost(httpHelper, s.sessionStore, apiClient))
		r.Get("/users/{userId}/delete", adminuserhandlers.HandleDeleteGet(httpHelper, apiClient))
		r.Post("/users/{userId}/delete", adminuserhandlers.HandleDeletePost(httpHelper, apiClient, baseURL))
		r.Get("/users/new", adminuserhandlers.HandleNewGet(httpHelper))
		r.Post("/users/new", adminuserhandlers.HandleNewPost(httpHelper, s.sessionStore, apiClient, baseURL))
		// User profile picture page and API routes
		r.Get("/users/{userId}/picture", adminuserhandlers.HandlePictureGet(httpHelper, apiClient))
		r.Post("/users/{userId}/picture", adminuserhandlers.HandleProfilePicturePost(httpHelper, apiClient))
		r.Delete("/users/{userId}/picture", adminuserhandlers.HandleProfilePictureDelete(httpHelper, apiClient))

		// Settings routes
		r.Get("/settings/general", adminsettingshandlers.HandleGeneralGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/settings/general", adminsettingshandlers.HandleGeneralPost(httpHelper, s.sessionStore, apiClient, s.settingsCache, baseURL))
		r.Get("/settings/ui-theme", adminsettingshandlers.HandleUIThemeGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/settings/ui-theme", adminsettingshandlers.HandleUIThemePost(httpHelper, s.sessionStore, apiClient, s.settingsCache, baseURL))
		r.Get("/settings/sessions", adminsettingshandlers.HandleSessionsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/settings/sessions", adminsettingshandlers.HandleSessionsPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/settings/tokens", adminsettingshandlers.HandleTokensGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/settings/tokens", adminsettingshandlers.HandleTokensPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/settings/keys", adminsettingshandlers.HandleKeysGet(httpHelper, apiClient))
		r.Post("/settings/keys/rotate", adminsettingshandlers.HandleKeysRotatePost(httpHelper, apiClient))
		r.Post("/settings/keys/revoke", adminsettingshandlers.HandleKeysRevokePost(httpHelper, apiClient))
		r.Get("/settings/email", adminsettingshandlers.HandleEmailGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/settings/email", adminsettingshandlers.HandleEmailPost(httpHelper, s.sessionStore, apiClient, s.settingsCache, baseURL))
		r.Get("/settings/email/send-test-email", adminsettingshandlers.HandleEmailSendTestGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/settings/email/send-test-email", adminsettingshandlers.HandleEmailSendTestPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/settings/audit-logs", adminsettingshandlers.HandleAuditLogsGet(httpHelper, s.sessionStore, apiClient))
		r.Post("/settings/audit-logs", adminsettingshandlers.HandleAuditLogsPost(httpHelper, s.sessionStore, apiClient, baseURL))
		r.Get("/settings/audit-log-viewer", adminsettingshandlers.HandleAuditLogViewerGet(httpHelper, apiClient))
	})
}
