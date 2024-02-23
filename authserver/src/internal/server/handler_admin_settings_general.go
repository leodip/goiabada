package server

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminSettingsGeneralGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		settingsInfo := struct {
			AppName                                   string
			Issuer                                    string
			SelfRegistrationEnabled                   bool
			SelfRegistrationRequiresEmailVerification bool
			PasswordPolicy                            string
		}{
			AppName:                 settings.AppName,
			Issuer:                  settings.Issuer,
			SelfRegistrationEnabled: settings.SelfRegistrationEnabled,
			SelfRegistrationRequiresEmailVerification: settings.SelfRegistrationRequiresEmailVerification,
			PasswordPolicy: settings.PasswordPolicy.String(),
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = sess.Save(r, w)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"settings":          settingsInfo,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_general.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminSettingsGeneralPost(inputSanitizer inputSanitizer) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settingsInfo := struct {
			AppName                                   string
			Issuer                                    string
			SelfRegistrationEnabled                   bool
			SelfRegistrationRequiresEmailVerification bool
			PasswordPolicy                            string
		}{
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

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_general.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		maxLength := 30
		if len(settingsInfo.AppName) > maxLength {
			renderError(fmt.Sprintf("App name is too long. The maximum length is %v characters.", maxLength))
			return
		}

		// any value containing a ":" character MUST be a URI
		if strings.Contains(settingsInfo.Issuer, ":") {
			_, err := url.ParseRequestURI(settingsInfo.Issuer)
			if err != nil {
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
			s.internalServerError(w, r, err)
			return
		}

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)
		settings.AppName = inputSanitizer.Sanitize(settingsInfo.AppName)
		settings.Issuer = inputSanitizer.Sanitize(settingsInfo.Issuer)
		settings.SelfRegistrationEnabled = settingsInfo.SelfRegistrationEnabled
		if settingsInfo.SelfRegistrationEnabled {
			settings.SelfRegistrationRequiresEmailVerification = settingsInfo.SelfRegistrationRequiresEmailVerification
		} else {
			settings.SelfRegistrationRequiresEmailVerification = false
		}
		settings.PasswordPolicy = passwordPolicy

		err = s.database.UpdateSettings(nil, settings)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditUpdatedGeneralSettings, map[string]interface{}{
			"loggedInUser": s.getLoggedInSubject(r),
		})

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/general", lib.GetBaseUrl()), http.StatusFound)
	}
}
