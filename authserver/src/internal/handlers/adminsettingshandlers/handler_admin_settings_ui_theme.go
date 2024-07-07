package adminsettingshandlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
)

func HandleAdminSettingsUIThemeGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		settingsInfo := struct {
			UITheme string
		}{
			UITheme: settings.UITheme,
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = sess.Save(r, w)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"settings":          settingsInfo,
			"uiThemes":          lib.GetUIThemes(),
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
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
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settingsInfo := struct {
			UITheme string
		}{
			UITheme: strings.TrimSpace(r.FormValue("themeSelection")),
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"settings":  settingsInfo,
				"uiThemes":  lib.GetUIThemes(),
				"csrfField": csrf.TemplateField(r),
				"error":     message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_ui_theme.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		if settingsInfo.UITheme != "" {
			allThemes := lib.GetUIThemes()
			themeFound := false
			for _, theme := range allThemes {
				if theme == settingsInfo.UITheme {
					themeFound = true
					break
				}
			}

			if !themeFound {
				renderError("Invalid theme.")
				return
			}
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		settings.UITheme = settingsInfo.UITheme

		err := database.UpdateSettings(nil, settings)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditUpdatedUIThemeSettings, map[string]interface{}{
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/ui-theme", lib.GetBaseUrl()), http.StatusFound)
	}
}
