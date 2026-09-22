package adminsettingshandlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"

	"github.com/leodip/goiabada/adminconsole/internal/cache"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

// settingsUIThemeAPI is what the UI theme page needs: the theme, and the write.
type settingsUIThemeAPI interface {
	GetSettingsUITheme(ctx context.Context, accessToken string) (*api.SettingsUIThemeResponse, error)
	UpdateSettingsUITheme(ctx context.Context, accessToken string, request *api.UpdateSettingsUIThemeRequest) (*api.SettingsUIThemeResponse, error)
}

func HandleAdminSettingsUIThemeGet(
	httpHelper handlers.HttpHelper,
	httpSession sessionstore.Store,
	apiClient settingsUIThemeAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Fetch from API
		apiResp, err := apiClient.GetSettingsUITheme(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		settingsInfo := SettingsUITheme{
			UITheme: apiResp.UITheme,
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
			"uiThemes":          apiResp.AvailableThemes,
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_ui_theme.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminSettingsUIThemePost(
	httpHelper handlers.HttpHelper,
	httpSession sessionstore.Store,
	apiClient settingsUIThemeAPI,
	settingsCache *cache.SettingsCache,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settingsInfo := SettingsUITheme{
			UITheme: strings.TrimSpace(r.FormValue("themeSelection")),
		}

		renderError := func(message string) {
			// Try to get themes from API to populate the dropdown on error
			uiThemes := []string{}
			if jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo); ok {
				if apiResp, err := apiClient.GetSettingsUITheme(r.Context(), jwtInfo.TokenResponse.AccessToken); err == nil {
					uiThemes = apiResp.AvailableThemes
				}
			}
			bind := map[string]interface{}{
				"settings": settingsInfo,
				"uiThemes": uiThemes,
				"error":    message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_ui_theme.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// No client-side validation; rely on API validation

		// Get access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Call API to update
		_, err := apiClient.UpdateSettingsUITheme(r.Context(), jwtInfo.TokenResponse.AccessToken, &api.UpdateSettingsUIThemeRequest{
			UITheme: settingsInfo.UITheme,
		})
		if err != nil {
			handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		// Invalidate settings cache since we just updated settings
		settingsCache.Invalidate()

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

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/ui-theme", config.GetAdminConsole().BaseURL), http.StatusFound)
	}
}
