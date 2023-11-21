package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminSettingsSMSGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		var smsTwilioConfig dtos.SMSTwilioConfig
		if len(settings.SMSProvider) > 0 && settings.SMSProvider == "twilio" {
			smsConfigDecrypted, err := lib.DecryptText(settings.SMSConfigEncrypted, settings.AESEncryptionKey)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			err = json.Unmarshal([]byte(smsConfigDecrypted), &smsTwilioConfig)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
		}

		settingsInfo := struct {
			SMSProvider  string
			TwilioConfig dtos.SMSTwilioConfig
		}{
			SMSProvider:  settings.SMSProvider,
			TwilioConfig: smsTwilioConfig,
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

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_sms.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminSettingsSMSPost(inputSanitizer inputSanitizer) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		provider := r.FormValue("provider")

		if provider == "twilio" {
			twilioAccountSID := r.FormValue("twilioAccountSID")
			twilioAuthToken := r.FormValue("twilioAuthToken")
			twilioFrom := r.FormValue("twilioFrom")

			settingsInfo := struct {
				SMSProvider  string
				TwilioConfig dtos.SMSTwilioConfig
			}{
				SMSProvider: provider,
				TwilioConfig: dtos.SMSTwilioConfig{
					AccountSID: twilioAccountSID,
					AuthToken:  twilioAuthToken,
					From:       twilioFrom,
				},
			}

			renderError := func(message string) {

				bind := map[string]interface{}{
					"settings":  settingsInfo,
					"csrfField": csrf.TemplateField(r),
					"error":     message,
				}

				err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_sms.html", bind)
				if err != nil {
					s.internalServerError(w, r, err)
				}
			}

			minLength := 1
			maxLength := 60
			if len(twilioAccountSID) < minLength || len(twilioAccountSID) > maxLength {
				renderError(fmt.Sprintf("Account SID must be between %v and %v characters", minLength, maxLength))
				return
			}

			if len(twilioAuthToken) < minLength || len(twilioAuthToken) > maxLength {
				renderError(fmt.Sprintf("Auth token must be between %v and %v characters", minLength, maxLength))
				return
			}

			pattern := `^\+\d+([ ]?\d+)*\d$`
			regex, err := regexp.Compile(pattern)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			if !regex.MatchString(twilioFrom) {
				renderError("Please enter a valid number. Example: +1 555 555 5555.")
				return
			}

			maxLength = 20
			if len(twilioFrom) < minLength || len(twilioFrom) > maxLength {
				renderError(fmt.Sprintf("The phone number must not exceed %v characters in length.", maxLength))
				return
			}

			settings.SMSProvider = provider
			smsConfigJson, err := json.Marshal(settingsInfo.TwilioConfig)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			smsConfigEncrypted, err := lib.EncryptText(string(smsConfigJson), settings.AESEncryptionKey)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			settings.SMSConfigEncrypted = smsConfigEncrypted
		} else if provider == "" {
			settings.SMSProvider = ""
			settings.SMSConfigEncrypted = nil
		} else {
			s.internalServerError(w, r, fmt.Errorf("unsupported SMS provider: %v", provider))
			return
		}

		_, err := s.database.SaveSettings(settings)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditUpdatedSMSSettings, map[string]interface{}{
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

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/sms", lib.GetBaseUrl()), http.StatusFound)
	}
}
