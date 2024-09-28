package adminsettingshandlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

func HandleAdminSettingsSessionsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		settingsInfo := struct {
			UserSessionIdleTimeoutInSeconds int
			UserSessionMaxLifetimeInSeconds int
		}{
			UserSessionIdleTimeoutInSeconds: settings.UserSessionIdleTimeoutInSeconds,
			UserSessionMaxLifetimeInSeconds: settings.UserSessionMaxLifetimeInSeconds,
		}

		sess, err := httpSession.Get(r, constants.SessionName)
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

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_sessions.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminSettingsSessionsPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		settingsInfo := struct {
			UserSessionIdleTimeoutInSeconds string
			UserSessionMaxLifetimeInSeconds string
		}{
			UserSessionIdleTimeoutInSeconds: r.FormValue("userSessionIdleTimeoutInSeconds"),
			UserSessionMaxLifetimeInSeconds: r.FormValue("userSessionMaxLifetimeInSeconds"),
		}

		renderError := func(message string) {

			bind := map[string]interface{}{
				"settings":  settingsInfo,
				"csrfField": csrf.TemplateField(r),
				"error":     message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_sessions.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		userSessionIdleTimeoutInSecondsInt, err := strconv.Atoi(settingsInfo.UserSessionIdleTimeoutInSeconds)
		if err != nil {
			settingsInfo.UserSessionIdleTimeoutInSeconds = strconv.Itoa(settings.UserSessionIdleTimeoutInSeconds)
			renderError("Invalid value for user session - idle timeout in seconds.")
			return
		}

		userSessionMaxLifetimeInSecondsInt, err := strconv.Atoi(settingsInfo.UserSessionMaxLifetimeInSeconds)
		if err != nil {
			settingsInfo.UserSessionMaxLifetimeInSeconds = strconv.Itoa(settings.UserSessionMaxLifetimeInSeconds)
			renderError("Invalid value for user session - max lifetime in seconds.")
			return
		}

		if userSessionIdleTimeoutInSecondsInt <= 0 {
			renderError("User session - idle timeout in seconds must be greater than zero.")
			return
		}

		if userSessionMaxLifetimeInSecondsInt <= 0 {
			renderError("User session - max lifetime in seconds must be greater than zero.")
			return
		}

		const maxValue = 160000000
		if userSessionIdleTimeoutInSecondsInt > maxValue {
			renderError(fmt.Sprintf("User session - idle timeout in seconds cannot be greater than %v.", maxValue))
			return
		}

		if userSessionMaxLifetimeInSecondsInt > maxValue {
			renderError(fmt.Sprintf("User session - max lifetime in seconds cannot be greater than %v.", maxValue))
			return
		}

		if userSessionIdleTimeoutInSecondsInt > userSessionMaxLifetimeInSecondsInt {
			renderError("User session - the idle timeout cannot be greater than the max lifetime.")
			return
		}

		settings.UserSessionIdleTimeoutInSeconds = userSessionIdleTimeoutInSecondsInt
		settings.UserSessionMaxLifetimeInSeconds = userSessionMaxLifetimeInSecondsInt

		err = database.UpdateSettings(nil, settings)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditUpdatedSessionsSettings, map[string]interface{}{
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		sess, err := httpSession.Get(r, constants.SessionName)
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

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/sessions", config.Get().BaseURL), http.StatusFound)
	}
}
