package server

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminSettingsTokensGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		settingsInfo := struct {
			TokenExpirationInSeconds int
		}{
			TokenExpirationInSeconds: settings.TokenExpirationInSeconds,
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

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_tokens.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminSettingsTokensPost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		settingsInfo := struct {
			TokenExpirationInSeconds string
		}{
			TokenExpirationInSeconds: r.FormValue("tokenExpirationInSeconds"),
		}

		renderError := func(message string) {

			bind := map[string]interface{}{
				"settings":  settingsInfo,
				"csrfField": csrf.TemplateField(r),
				"error":     message,
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_tokens.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
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

		settings.TokenExpirationInSeconds = tokenExpirationInSeconds

		_, err = s.database.SaveSettings(settings)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

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

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/tokens", lib.GetBaseUrl()), http.StatusFound)
	}
}
