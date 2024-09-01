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

func HandleAdminSettingsTokensGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		settingsInfo := struct {
			TokenExpirationInSeconds                int
			RefreshTokenOfflineIdleTimeoutInSeconds int
			RefreshTokenOfflineMaxLifetimeInSeconds int
			IncludeOpenIDConnectClaimsInAccessToken bool
		}{
			TokenExpirationInSeconds:                settings.TokenExpirationInSeconds,
			RefreshTokenOfflineIdleTimeoutInSeconds: settings.RefreshTokenOfflineIdleTimeoutInSeconds,
			RefreshTokenOfflineMaxLifetimeInSeconds: settings.RefreshTokenOfflineMaxLifetimeInSeconds,
			IncludeOpenIDConnectClaimsInAccessToken: settings.IncludeOpenIDConnectClaimsInAccessToken,
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
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_tokens.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminSettingsTokensPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		settingsInfo := struct {
			TokenExpirationInSeconds                string
			RefreshTokenOfflineIdleTimeoutInSeconds string
			RefreshTokenOfflineMaxLifetimeInSeconds string
			IncludeOpenIDConnectClaimsInAccessToken bool
		}{
			TokenExpirationInSeconds:                r.FormValue("tokenExpirationInSeconds"),
			RefreshTokenOfflineIdleTimeoutInSeconds: r.FormValue("refreshTokenOfflineIdleTimeoutInSeconds"),
			RefreshTokenOfflineMaxLifetimeInSeconds: r.FormValue("refreshTokenOfflineMaxLifetimeInSeconds"),
			IncludeOpenIDConnectClaimsInAccessToken: r.FormValue("includeOpenIDConnectClaimsInAccessToken") == "on",
		}

		renderError := func(message string) {

			bind := map[string]interface{}{
				"settings":  settingsInfo,
				"csrfField": csrf.TemplateField(r),
				"error":     message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_tokens.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		tokenExpirationInSeconds, err := strconv.Atoi(settingsInfo.TokenExpirationInSeconds)
		if err != nil {
			settingsInfo.TokenExpirationInSeconds = strconv.Itoa(settings.TokenExpirationInSeconds)
			renderError("Invalid value for token expiration in seconds.")
			return
		}

		if tokenExpirationInSeconds <= 0 {
			renderError("Token expiration in seconds must be greater than zero.")
			return
		}

		const maxValue = 160000000
		if tokenExpirationInSeconds > maxValue {
			renderError(fmt.Sprintf("Token expiration in seconds cannot be greater than %v.", maxValue))
			return
		}

		refreshTokenOfflineIdleTimeoutInSeconds, err := strconv.Atoi(settingsInfo.RefreshTokenOfflineIdleTimeoutInSeconds)
		if err != nil {
			settingsInfo.RefreshTokenOfflineIdleTimeoutInSeconds = strconv.Itoa(settings.RefreshTokenOfflineIdleTimeoutInSeconds)
			renderError("Invalid value for refresh token offline - idle timeout in seconds.")
			return
		}

		if refreshTokenOfflineIdleTimeoutInSeconds <= 0 {
			renderError("Refresh token offline - idle timeout in seconds must be greater than zero.")
			return
		}

		if refreshTokenOfflineIdleTimeoutInSeconds > maxValue {
			renderError(fmt.Sprintf("Refresh token offline - idle timeout in seconds cannot be greater than %v.", maxValue))
			return
		}

		refreshTokenOfflineMaxLifetimeInSeconds, err := strconv.Atoi(settingsInfo.RefreshTokenOfflineMaxLifetimeInSeconds)
		if err != nil {
			settingsInfo.RefreshTokenOfflineMaxLifetimeInSeconds = strconv.Itoa(settings.RefreshTokenOfflineMaxLifetimeInSeconds)
			renderError("Invalid value for refresh token offline - max lifetime in seconds.")
			return
		}

		if refreshTokenOfflineMaxLifetimeInSeconds <= 0 {
			renderError("Refresh token offline - max lifetime in seconds must be greater than zero.")
			return
		}

		if refreshTokenOfflineMaxLifetimeInSeconds > maxValue {
			renderError(fmt.Sprintf("Refresh token offline - max lifetime in seconds cannot be greater than %v.", maxValue))
			return
		}

		if refreshTokenOfflineIdleTimeoutInSeconds > refreshTokenOfflineMaxLifetimeInSeconds {
			renderError("Refresh token offline - idle timeout cannot be greater than max lifetime.")
			return
		}

		settings.TokenExpirationInSeconds = tokenExpirationInSeconds
		settings.RefreshTokenOfflineIdleTimeoutInSeconds = refreshTokenOfflineIdleTimeoutInSeconds
		settings.RefreshTokenOfflineMaxLifetimeInSeconds = refreshTokenOfflineMaxLifetimeInSeconds
		settings.IncludeOpenIDConnectClaimsInAccessToken = settingsInfo.IncludeOpenIDConnectClaimsInAccessToken

		err = database.UpdateSettings(nil, settings)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditUpdatedTokensSettings, map[string]interface{}{
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

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/tokens", config.Get().BaseURL), http.StatusFound)
	}
}
