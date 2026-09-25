package adminsettingshandlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/cache"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/api"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
)

// settingsGeneralAPI is what the general settings page needs: the settings, and the write.
type settingsGeneralAPI interface {
	GetSettingsGeneral(ctx context.Context, accessToken string) (*api.SettingsGeneralResponse, error)
	UpdateSettingsGeneral(ctx context.Context, accessToken string, request *api.UpdateSettingsGeneralRequest) (*api.SettingsGeneralResponse, error)
}

func HandleAdminSettingsGeneralGet(
	httpHelper handlers.HttpHelper,
	httpSession sessionstore.Store,
	apiClient settingsGeneralAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Fetch settings from API
		apiResp, err := apiClient.GetSettingsGeneral(r.Context(), jwtInfo.TokenResponse.AccessToken)
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

		sess, err := httpSession.Get(r, coreconstants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		_, savedSuccessfully := sess.TakeFlash("savedSuccessfully")
		if savedSuccessfully {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"settings":          settingsInfo,
			"savedSuccessfully": savedSuccessfully,
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
	httpSession sessionstore.Store,
	apiClient settingsGeneralAPI,
	settingsCache *cache.SettingsCache,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Fetch current settings to compare issuer later
		currentSettingsResp, err := apiClient.GetSettingsGeneral(r.Context(), jwtInfo.TokenResponse.AccessToken)
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
				"settings": settingsInfo,
				"error":    message,
			}

			renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_general.html", bind)
			if renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
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

		updatedResp, err := apiClient.UpdateSettingsGeneral(r.Context(), jwtInfo.TokenResponse.AccessToken, updateReq)
		if err != nil {
			handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		// Invalidate settings cache since we just updated settings
		settingsCache.Invalidate()

		// Check if issuer was changed
		if originalIssuer != updatedResp.Issuer {
			// Clear the session
			sess, sessionErr := httpSession.Get(r, coreconstants.AdminConsoleSessionName)
			if sessionErr != nil {
				httpHelper.InternalServerError(w, r, sessionErr)
				return
			}

			// Delete the JWT from session, and its recorded expiry with it
			delete(sess.Values, constants.SessionKeyJwt)
			delete(sess.Values, constants.SessionKeyJwtExpiresAt)

			sessionErr = httpSession.Save(r, w, sess)
			if sessionErr != nil {
				httpHelper.InternalServerError(w, r, sessionErr)
				return
			}

			// Redirect to the login page
			http.Redirect(w, r, fmt.Sprintf("%v/auth/logout", config.GetAdminConsole().BaseURL), http.StatusFound)
			return
		}

		// Normal flow - set success message and redirect back to settings
		sess, err := httpSession.Get(r, coreconstants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.SetFlash("savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/general", config.GetAdminConsole().BaseURL), http.StatusFound)
	}
}
