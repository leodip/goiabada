package adminsettingshandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/sessionstore"
)

// settingsEmailAPI is what the email settings page needs: the settings, the write, and the test
// send.
type settingsEmailAPI interface {
	GetSettingsEmail(ctx context.Context, accessToken string) (*api.SettingsEmailResponse, error)
	SendTestEmail(ctx context.Context, accessToken string, request *api.SendTestEmailRequest) error
	UpdateSettingsEmail(ctx context.Context, accessToken string, request *api.UpdateSettingsEmailRequest) (*api.SettingsEmailResponse, error)
}

func HandleEmailGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient settingsEmailAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Fetch settings via API
		apiResp, err := apiClient.GetSettingsEmail(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
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
			// The password never comes back from the API, only whether one is stored, and the
			// host it is stored for is the one the page warns about leaving (#410).
			HasSMTPPassword: apiResp.HasSMTPPassword,
			SavedSMTPHost:   apiResp.SMTPHost,
		}

		if apiResp.SMTPPort == 0 {
			settingsInfo.SMTPPort = 587
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		_, savedSuccessfully := sess.TakeFlash("savedSuccessfully")
		if savedSuccessfully {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"settings":          settingsInfo,
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_email.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleEmailPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient settingsEmailAPI,
	settingsCache SettingsInvalidator,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// SMTPPassword reads with r.PostFormValue rather than r.FormValue: r.Form merges the URL
		// query behind the request body, so /admin/settings/email?password=... would have set the
		// SMTP password, leaving it in the browser's history, in the Referer of anything the page
		// loads, and in the access log of every proxy in front of the deployment. This route is
		// POST-only with a separate GET handler rendering the form, so the query was never a
		// submission. The other fields here are configuration rather than credentials and keep the
		// accessor they had (#202).
		//
		// An empty box keeps the stored password and the ticked checkbox removes it (#410).
		// hasSmtpPassword and savedHostOrIP are hidden fields carrying the state the page was
		// loaded with, which only a refused save's redraw reads: the auth server decides what the
		// save does to the password from the row it holds, not from them.
		settingsInfo := SettingsEmailPost{
			SMTPEnabled:       r.FormValue("smtpEnabled") == "on",
			SMTPHost:          r.FormValue("hostOrIP"),
			SMTPPort:          r.FormValue("port"),
			SMTPUsername:      r.FormValue("username"),
			SMTPPassword:      r.PostFormValue("password"),
			ClearSMTPPassword: r.FormValue("clearSmtpPassword") == "on",
			SMTPEncryption:    r.FormValue("smtpEncryption"),
			SMTPFromName:      r.FormValue("fromName"),
			SMTPFromEmail:     r.FormValue("fromEmail"),
			HasSMTPPassword:   r.FormValue("hasSmtpPassword") == "true",
			SavedSMTPHost:     r.FormValue("savedHostOrIP"),
		}

		renderError := func(message, errorField string) {
			bind := map[string]interface{}{
				"settings":   settingsInfo,
				"error":      message,
				"errorField": errorField,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_email.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// An empty port is sent as 0, which the auth server refuses as missing; one that is not a
		// number is refused here, at its field, rather than refused in the same words. With email
		// off the port is not saved, so it is not read.
		smtpPortInt := 0
		if port := strings.TrimSpace(settingsInfo.SMTPPort); settingsInfo.SMTPEnabled && port != "" {
			p, err := strconv.Atoi(port)
			if err != nil {
				renderError(i18n.T(r.Context(), "adminconsole.refusal.settings_email.port_invalid"), "port")
				return
			}
			smtpPortInt = p
		}

		updateReq := &api.UpdateSettingsEmailRequest{
			SMTPEnabled:       settingsInfo.SMTPEnabled,
			SMTPHost:          strings.TrimSpace(settingsInfo.SMTPHost),
			SMTPPort:          smtpPortInt,
			SMTPUsername:      strings.TrimSpace(settingsInfo.SMTPUsername),
			SMTPPassword:      settingsInfo.SMTPPassword,
			ClearSMTPPassword: settingsInfo.ClearSMTPPassword,
			SMTPEncryption:    strings.TrimSpace(settingsInfo.SMTPEncryption),
			SMTPFromName:      strings.TrimSpace(settingsInfo.SMTPFromName),
			SMTPFromEmail:     strings.TrimSpace(settingsInfo.SMTPFromEmail),
		}

		_, err := apiClient.UpdateSettingsEmail(r.Context(), jwtInfo.TokenResponse.AccessToken, updateReq)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderError(message, render.ErrorField(err, emailErrorFields))
			})
			return
		}

		// Invalidate settings cache since we just updated settings
		settingsCache.Invalidate()

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.SetFlash("savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/email", baseURL), http.StatusFound)
	}
}

func HandleEmailSendTestGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient settingsEmailAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// The address the last test email went to, which the page names in saying it was sent.
		sentTo, sent := sess.TakeFlash("testEmailSentTo")
		if sent {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		// Fetch settings to know whether SMTP is enabled
		apiResp, err := apiClient.GetSettingsEmail(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"smtpEnabled": apiResp.SMTPEnabled,
			"sentTo":      sentTo,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_email_sendtest.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleEmailSendTestPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient settingsEmailAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		destinationEmail := r.FormValue("destinationEmail")

		renderError := func(message, errorField string) {
			bind := map[string]interface{}{
				"smtpEnabled":      true,
				"destinationEmail": destinationEmail,
				"error":            message,
				"errorField":       errorField,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_email_sendtest.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		if len(destinationEmail) == 0 {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailDestinationRequired, nil).Localize(r.Context()), "destinationEmail")
			return
		}

		// Call API to send test email (server validates SMTP enabled and email)
		err := apiClient.SendTestEmail(r.Context(), jwtInfo.TokenResponse.AccessToken, &api.SendTestEmailRequest{To: destinationEmail})
		if err != nil {
			// Routed on status, as every other form is: a 400 or a 409 redraws the form with the
			// API's sentence whatever its code. It routed on three codes, VALIDATION_ERROR,
			// SMTP_NOT_ENABLED and SEND_FAILED, and sent the API's 400
			// validator.email.invalid_format for a malformed address, which the free-text field
			// invites, to the 500 page (#559 decision 5).
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderError(message, render.ErrorField(err, sendTestErrorFields))
			})
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.SetFlash("testEmailSentTo", destinationEmail)
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/email/send-test-email", baseURL), http.StatusFound)
	}
}
