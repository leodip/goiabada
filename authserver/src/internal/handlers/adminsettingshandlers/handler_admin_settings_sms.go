package adminsettingshandlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/internal/communication"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/pkg/errors"
)

func HandleAdminSettingsSMSGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		var smsTwilioConfig communication.SMSTwilioConfig
		if len(settings.SMSProvider) > 0 && settings.SMSProvider == "twilio" {
			smsConfigDecrypted, err := lib.DecryptText(settings.SMSConfigEncrypted, settings.AESEncryptionKey)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			err = json.Unmarshal([]byte(smsConfigDecrypted), &smsTwilioConfig)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		settingsInfo := struct {
			SMSProvider  string
			TwilioConfig communication.SMSTwilioConfig
		}{
			SMSProvider:  settings.SMSProvider,
			TwilioConfig: smsTwilioConfig,
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

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_sms.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminSettingsSMSPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		provider := r.FormValue("provider")

		renderError := func(message string) {
			settingsInfo := struct {
				SMSProvider  string
				TwilioConfig communication.SMSTwilioConfig
			}{
				SMSProvider: settings.SMSProvider,
				TwilioConfig: communication.SMSTwilioConfig{
					AccountSID: r.FormValue("twilioAccountSID"),
					AuthToken:  r.FormValue("twilioAuthToken"),
					From:       r.FormValue("twilioFrom"),
				},
			}

			bind := map[string]interface{}{
				"settings":  settingsInfo,
				"csrfField": csrf.TemplateField(r),
				"error":     message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_sms.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		minLength := 1
		maxLength := 60

		switch provider {
		case "twilio":
			twilioAccountSID := r.FormValue("twilioAccountSID")
			twilioAuthToken := r.FormValue("twilioAuthToken")
			twilioFrom := r.FormValue("twilioFrom")

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
				httpHelper.InternalServerError(w, r, err)
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
			settingsInfo := communication.SMSTwilioConfig{
				AccountSID: twilioAccountSID,
				AuthToken:  twilioAuthToken,
				From:       twilioFrom,
			}
			smsConfigJson, err := json.Marshal(settingsInfo)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			smsConfigEncrypted, err := lib.EncryptText(string(smsConfigJson), settings.AESEncryptionKey)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			settings.SMSConfigEncrypted = smsConfigEncrypted

		case "":
			settings.SMSProvider = ""
			settings.SMSConfigEncrypted = nil

		default:
			httpHelper.InternalServerError(w, r, errors.WithStack(fmt.Errorf("unsupported SMS provider: %v", provider)))
			return
		}

		err := database.UpdateSettings(nil, settings)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditUpdatedSMSSettings, map[string]interface{}{
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

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/sms", lib.GetBaseUrl()), http.StatusFound)
	}
}
