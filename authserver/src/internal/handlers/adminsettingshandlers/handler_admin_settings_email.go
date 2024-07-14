package adminsettingshandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/internal/communication"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/pkg/errors"
)

func HandleAdminSettingsEmailGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		settingsInfo := struct {
			SMTPEnabled    bool
			SMTPHost       string
			SMTPPort       int
			SMTPUsername   string
			SMTPPassword   string
			SMTPEncryption string
			SMTPFromName   string
			SMTPFromEmail  string
		}{
			SMTPEnabled:    settings.SMTPEnabled,
			SMTPHost:       settings.SMTPHost,
			SMTPPort:       settings.SMTPPort,
			SMTPUsername:   settings.SMTPUsername,
			SMTPEncryption: settings.SMTPEncryption,
			SMTPFromName:   settings.SMTPFromName,
			SMTPFromEmail:  settings.SMTPFromEmail,
		}

		if settings.SMTPEnabled && len(settings.SMTPPasswordEncrypted) > 0 {
			smtpPassword, err := lib.DecryptText(settings.SMTPPasswordEncrypted, settings.AESEncryptionKey)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			settingsInfo.SMTPPassword = smtpPassword
		}

		if settings.SMTPPort == 0 {
			settingsInfo.SMTPPort = 587
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

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_email.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminSettingsEmailPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	emailValidator handlers.EmailValidator,
	inputSanitizer handlers.InputSanitizer,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settingsInfo := struct {
			SMTPEnabled    bool
			SMTPHost       string
			SMTPPort       string
			SMTPUsername   string
			SMTPPassword   string
			SMTPEncryption string
			SMTPFromName   string
			SMTPFromEmail  string
		}{
			SMTPEnabled:    r.FormValue("smtpEnabled") == "on",
			SMTPHost:       r.FormValue("hostOrIP"),
			SMTPPort:       r.FormValue("port"),
			SMTPUsername:   r.FormValue("username"),
			SMTPPassword:   r.FormValue("password"),
			SMTPEncryption: r.FormValue("smtpEncryption"),
			SMTPFromName:   r.FormValue("fromName"),
			SMTPFromEmail:  r.FormValue("fromEmail"),
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"settings":  settingsInfo,
				"csrfField": csrf.TemplateField(r),
				"error":     message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_email.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		if settingsInfo.SMTPEnabled {
			if len(settingsInfo.SMTPHost) == 0 {
				renderError("SMTP host is required.")
				return
			}
			if len(settingsInfo.SMTPPort) == 0 {
				renderError("SMTP port is required.")
				return
			}
			if len(settingsInfo.SMTPFromEmail) == 0 {
				renderError("SMTP from email is required.")
				return
			}

			maxLength := 120
			if len(settingsInfo.SMTPHost) > maxLength {
				renderError(fmt.Sprintf("SMTP host must be less than %v characters.", maxLength))
				return
			}

			smtpPortInt, err := strconv.Atoi(settingsInfo.SMTPPort)
			if err != nil {
				renderError("SMTP port must be an integer number.")
				return
			}

			if smtpPortInt < 1 || smtpPortInt > 65535 {
				renderError("SMTP port must be between 1 and 65535.")
				return
			}

			err = lib.TestTCPConnection(settingsInfo.SMTPHost, smtpPortInt)
			if err != nil {
				renderError("Unable to connect to the SMTP server: " + err.Error())
				return
			}

			smtpEncryption, err := enums.SMTPEncryptionFromString(settingsInfo.SMTPEncryption)
			if err != nil {
				renderError("Invalid SMTP encryption.")
				return
			}

			maxLength = 60
			if len(settingsInfo.SMTPUsername) > maxLength {
				renderError(fmt.Sprintf("SMTP username must be less than %v characters.", maxLength))
				return
			}

			if len(settingsInfo.SMTPFromName) > maxLength {
				renderError(fmt.Sprintf("SMTP from name must be less than %v characters.", maxLength))
				return
			}

			if len(settingsInfo.SMTPFromEmail) > maxLength {
				renderError(fmt.Sprintf("SMTP from email must be less than %v characters.", maxLength))
				return
			}

			err = emailValidator.ValidateEmailAddress(r.Context(), settingsInfo.SMTPFromEmail)
			if err != nil {
				renderError("Invalid SMTP from email address.")
				return
			}

			settings.SMTPEnabled = settingsInfo.SMTPEnabled
			settings.SMTPHost = strings.TrimSpace(settingsInfo.SMTPHost)
			settings.SMTPPort = smtpPortInt
			settings.SMTPEncryption = smtpEncryption.String()
			settings.SMTPUsername = strings.TrimSpace(settingsInfo.SMTPUsername)

			if len(settingsInfo.SMTPPassword) > 0 {
				settings.SMTPPasswordEncrypted, err = lib.EncryptText(settingsInfo.SMTPPassword, settings.AESEncryptionKey)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
			} else {
				settings.SMTPPasswordEncrypted = nil
			}

			settings.SMTPFromName = strings.TrimSpace(inputSanitizer.Sanitize(settingsInfo.SMTPFromName))
			settings.SMTPFromEmail = strings.ToLower(settingsInfo.SMTPFromEmail)
		} else {
			settings.SMTPEnabled = false
			settings.SMTPHost = ""
			settings.SMTPPort = 0
			settings.SMTPEncryption = enums.SMTPEncryptionNone.String()
			settings.SMTPUsername = ""
			settings.SMTPPasswordEncrypted = nil
			settings.SMTPFromName = ""
			settings.SMTPFromEmail = ""
		}

		err := database.UpdateSettings(nil, settings)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditUpdatedSMTPSettings, map[string]interface{}{
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

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/email", lib.GetBaseUrl()), http.StatusFound)
	}
}

func HandleAdminSettingsEmailSendTestGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

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

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		bind := map[string]interface{}{
			"smtpEnabled":       settings.SMTPEnabled,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_email_sendtest.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminSettingsEmailSendTestPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	emailValidator handlers.EmailValidator,
	emailSender handlers.EmailSender,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		if !settings.SMTPEnabled {
			httpHelper.InternalServerError(w, r, errors.WithStack(fmt.Errorf("SMTP is not enabled")))
			return
		}

		destinationEmail := r.FormValue("destinationEmail")

		renderError := func(message string) {
			bind := map[string]interface{}{
				"smtpEnabled":      settings.SMTPEnabled,
				"destinationEmail": destinationEmail,
				"error":            message,
				"csrfField":        csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_email_sendtest.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		if len(destinationEmail) == 0 {
			renderError("Destination email is required.")
			return
		}

		err := emailValidator.ValidateEmailAddress(r.Context(), destinationEmail)
		if err != nil {
			if valError, ok := err.(*customerrors.ErrorDetail); ok {
				renderError(valError.GetDescription())
			} else {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		bind := map[string]interface{}{}
		buf, err := httpHelper.RenderTemplateToBuffer(r, "/layouts/email_layout.html", "/emails/email_test.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		input := &communication.SendEmailInput{
			To:       destinationEmail,
			Subject:  "Test email",
			HtmlBody: buf.String(),
		}
		err = emailSender.SendEmail(r.Context(), input)
		if err != nil {
			renderError("Unable to send email: " + err.Error())
		}

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
		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/email/send-test-email", lib.GetBaseUrl()), http.StatusFound)
	}
}
