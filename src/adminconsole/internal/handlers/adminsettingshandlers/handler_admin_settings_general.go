package adminsettingshandlers

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
)

func HandleAdminSettingsGeneralGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		settingsInfo := SettingsGeneral{
			AppName:                 settings.AppName,
			Issuer:                  settings.Issuer,
			SelfRegistrationEnabled: settings.SelfRegistrationEnabled,
			SelfRegistrationRequiresEmailVerification: settings.SelfRegistrationRequiresEmailVerification,
			PasswordPolicy: settings.PasswordPolicy.String(),
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
	authHelper handlers.AuthHelper,
	database data.Database,
	inputSanitizer handlers.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Get the current settings to compare issuer value
		currentSettings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		originalIssuer := currentSettings.Issuer

		settingsInfo := SettingsGeneral{
			AppName:                 strings.TrimSpace(r.FormValue("appName")),
			Issuer:                  strings.TrimSpace(r.FormValue("issuer")),
			SelfRegistrationEnabled: r.FormValue("selfRegistrationEnabled") == "on",
			SelfRegistrationRequiresEmailVerification: r.FormValue("selfRegistrationRequiresEmailVerification") == "on",
			PasswordPolicy: r.FormValue("passwordPolicy"),
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

		maxLength := 30
		if len(settingsInfo.AppName) > maxLength {
			renderError(fmt.Sprintf("App name is too long. The maximum length is %v characters.", maxLength))
			return
		}

		// any value containing a ":" character MUST be a URI
		if strings.Contains(settingsInfo.Issuer, ":") {
			parsedUri, err := url.ParseRequestURI(settingsInfo.Issuer)
			if err != nil || parsedUri.Scheme == "" || parsedUri.Host == "" {
				renderError("Invalid issuer. Please enter a valid URI.")
				return
			}
		} else {
			errorMsg := "Invalid issuer. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores."

			match, _ := regexp.MatchString("^[a-zA-Z]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$", settingsInfo.Issuer)
			if !match {
				renderError(errorMsg)
				return
			}

			// check if identifier has 2 dashes or underscores in a row
			if strings.Contains(settingsInfo.Issuer, "--") || strings.Contains(settingsInfo.Issuer, "__") {
				renderError(errorMsg)
				return
			}

			minLength := 3
			if len(settingsInfo.Issuer) < minLength {
				renderError(fmt.Sprintf("Issuer is too short. The minimum length is %v characters.", minLength))
				return
			}
		}

		maxLength = 60
		if len(settingsInfo.Issuer) > maxLength {
			renderError(fmt.Sprintf("Issuer is too long. The maximum length is %v characters.", maxLength))
			return
		}

		passwordPolicy, err := enums.PasswordPolicyFromString(settingsInfo.PasswordPolicy)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		currentSettings.AppName = inputSanitizer.Sanitize(settingsInfo.AppName)
		currentSettings.Issuer = inputSanitizer.Sanitize(settingsInfo.Issuer)
		currentSettings.SelfRegistrationEnabled = settingsInfo.SelfRegistrationEnabled
		if settingsInfo.SelfRegistrationEnabled {
			currentSettings.SelfRegistrationRequiresEmailVerification = settingsInfo.SelfRegistrationRequiresEmailVerification
		} else {
			currentSettings.SelfRegistrationRequiresEmailVerification = false
		}
		currentSettings.PasswordPolicy = passwordPolicy

		err = database.UpdateSettings(nil, currentSettings)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditUpdatedGeneralSettings, map[string]interface{}{
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		// Check if issuer was changed
		if originalIssuer != currentSettings.Issuer {
			// Clear the session
			sess, err := httpSession.Get(r, constants.SessionName)
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
			http.Redirect(w, r, fmt.Sprintf("%v/auth/logout", config.Get().BaseURL), http.StatusFound)
			return
		}

		// Normal flow - set success message and redirect back to settings
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

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/general", config.Get().BaseURL), http.StatusFound)
	}
}
