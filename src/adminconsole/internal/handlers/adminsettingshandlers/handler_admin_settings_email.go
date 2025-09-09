package adminsettingshandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

func HandleAdminSettingsEmailGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Fetch settings via API
		apiResp, err := apiClient.GetSettingsEmail(jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		settingsInfo := SettingsEmailGet{
			SMTPEnabled:    apiResp.SMTPEnabled,
			SMTPHost:       apiResp.SMTPHost,
			SMTPPort:       apiResp.SMTPPort,
			SMTPUsername:   apiResp.SMTPUsername,
			SMTPEncryption: apiResp.SMTPEncryption,
			SMTPFromName:   apiResp.SMTPFromName,
			SMTPFromEmail:  apiResp.SMTPFromEmail,
		}

		if apiResp.SMTPPort == 0 {
			settingsInfo.SMTPPort = 587
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
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		settingsInfo := SettingsEmailPost{
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

		// Convert port to int if possible; on error, set 0 so server validation triggers
		smtpPortInt := 0
		if len(settingsInfo.SMTPPort) > 0 {
			if p, err := strconv.Atoi(settingsInfo.SMTPPort); err == nil {
				smtpPortInt = p
			}
		}

		updateReq := &api.UpdateSettingsEmailRequest{
			SMTPEnabled:    settingsInfo.SMTPEnabled,
			SMTPHost:       strings.TrimSpace(settingsInfo.SMTPHost),
			SMTPPort:       smtpPortInt,
			SMTPUsername:   strings.TrimSpace(settingsInfo.SMTPUsername),
			SMTPPassword:   settingsInfo.SMTPPassword,
			SMTPEncryption: strings.TrimSpace(settingsInfo.SMTPEncryption),
			SMTPFromName:   strings.TrimSpace(settingsInfo.SMTPFromName),
			SMTPFromEmail:  strings.TrimSpace(settingsInfo.SMTPFromEmail),
		}

		_, err := apiClient.UpdateSettingsEmail(jwtInfo.TokenResponse.AccessToken, updateReq)
		if err != nil {
			handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

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

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/email", config.GetAdminConsole().BaseURL), http.StatusFound)
	}
}

func HandleAdminSettingsEmailSendTestGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
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

		// Fetch settings to know whether SMTP is enabled
		apiResp, err := apiClient.GetSettingsEmail(jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"smtpEnabled":       apiResp.SMTPEnabled,
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
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		destinationEmail := r.FormValue("destinationEmail")

		renderError := func(message string) {
			bind := map[string]interface{}{
				"smtpEnabled":      true,
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

		// Call API to send test email (server validates SMTP enabled and email)
		err := apiClient.SendTestEmail(jwtInfo.TokenResponse.AccessToken, &api.SendTestEmailRequest{To: destinationEmail})
		if err != nil {
			// Prefer to render form error for known API error codes
			if apiErr, ok := err.(*apiclient.APIError); ok {
				switch apiErr.Code {
				case "VALIDATION_ERROR", "SMTP_NOT_ENABLED", "SEND_FAILED":
					renderError(apiErr.Message)
				default:
					handlers.HandleAPIError(httpHelper, w, r, err)
				}
			} else {
				handlers.HandleAPIError(httpHelper, w, r, err)
			}
			return
		}

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
		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/email/send-test-email", config.GetAdminConsole().BaseURL), http.StatusFound)
	}
}
