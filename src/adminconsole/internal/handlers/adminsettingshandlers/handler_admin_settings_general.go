package adminsettingshandlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/cache"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminSettingsGeneralGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Fetch settings from API
		apiResp, err := apiClient.GetSettingsGeneral(jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		settingsInfo := SettingsGeneral{
			AppName:                 apiResp.AppName,
			Issuer:                  apiResp.Issuer,
			SelfRegistrationEnabled: apiResp.SelfRegistrationEnabled,
			SelfRegistrationRequiresEmailVerification: apiResp.SelfRegistrationRequiresEmailVerification,
			DynamicClientRegistrationEnabled:          apiResp.DynamicClientRegistrationEnabled,
			PasswordPolicy:                            apiResp.PasswordPolicy,
			PKCERequired:                              apiResp.PKCERequired,
			ImplicitFlowEnabled:                       apiResp.ImplicitFlowEnabled,
			ResourceOwnerPasswordCredentialsEnabled:   apiResp.ResourceOwnerPasswordCredentialsEnabled,
		}

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"settings":          settingsInfo,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_general.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminSettingsGeneralPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
	settingsCache *cache.SettingsCache,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Fetch current settings to compare issuer later
		currentSettingsResp, err := apiClient.GetSettingsGeneral(jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		originalIssuer := currentSettingsResp.Issuer

		settingsInfo := SettingsGeneral{
			AppName:                 strings.TrimSpace(r.FormValue("appName")),
			Issuer:                  strings.TrimSpace(r.FormValue("issuer")),
			SelfRegistrationEnabled: r.FormValue("selfRegistrationEnabled") == "on",
			SelfRegistrationRequiresEmailVerification: r.FormValue("selfRegistrationRequiresEmailVerification") == "on",
			DynamicClientRegistrationEnabled:          r.FormValue("dynamicClientRegistrationEnabled") == "on",
			PasswordPolicy:                            r.FormValue("passwordPolicy"),
			PKCERequired:                              r.FormValue("pkceRequired") == "on",
			ImplicitFlowEnabled:                       r.FormValue("implicitFlowEnabled") == "on",
			ResourceOwnerPasswordCredentialsEnabled:   r.FormValue("ropcFlowEnabled") == "on",
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"settings":  settingsInfo,
				"csrfField": csrf.TemplateField(r),
				"error":     message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_general.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// Build API request
		updateReq := &api.UpdateSettingsGeneralRequest{
			AppName:                 strings.TrimSpace(settingsInfo.AppName),
			Issuer:                  strings.TrimSpace(settingsInfo.Issuer),
			SelfRegistrationEnabled: settingsInfo.SelfRegistrationEnabled,
			SelfRegistrationRequiresEmailVerification: settingsInfo.SelfRegistrationRequiresEmailVerification,
			DynamicClientRegistrationEnabled:          settingsInfo.DynamicClientRegistrationEnabled,
			PasswordPolicy:                            strings.TrimSpace(settingsInfo.PasswordPolicy),
			PKCERequired:                              settingsInfo.PKCERequired,
			ImplicitFlowEnabled:                       settingsInfo.ImplicitFlowEnabled,
			ResourceOwnerPasswordCredentialsEnabled:   settingsInfo.ResourceOwnerPasswordCredentialsEnabled,
		}

		updatedResp, err := apiClient.UpdateSettingsGeneral(jwtInfo.TokenResponse.AccessToken, updateReq)
		if err != nil {
			handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		// Invalidate settings cache since we just updated settings
		settingsCache.Invalidate()

		// Check if issuer was changed
		if originalIssuer != updatedResp.Issuer {
			// Clear the session
			sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			// Delete the JWT from session
			delete(sess.Values, constants.SessionKeyJwt)

			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			// Redirect to the login page
			http.Redirect(w, r, fmt.Sprintf("%v/auth/logout", config.GetAdminConsole().BaseURL), http.StatusFound)
			return
		}

		// Normal flow - set success message and redirect back to settings
		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/general", config.GetAdminConsole().BaseURL), http.StatusFound)
	}
}
