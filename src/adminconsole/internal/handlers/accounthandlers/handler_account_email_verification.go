package accounthandlers

import (
    "net/http"
    "strings"

    "github.com/gorilla/csrf"
    "github.com/gorilla/sessions"
    "github.com/leodip/goiabada/adminconsole/internal/apiclient"
    "github.com/leodip/goiabada/adminconsole/internal/handlers"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/models"
    "github.com/leodip/goiabada/core/oauth"
    "github.com/pkg/errors"
)

func HandleAccountEmailVerificationGet(
    httpHelper handlers.HttpHelper,
    httpSession sessions.Store,
    apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

        // Get JWT info to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }
        user, err := apiClient.GetAccountProfile(jwtInfo.TokenResponse.AccessToken)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if !settings.SMTPEnabled {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("SMTP is not enabled")))
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

		bind := map[string]interface{}{
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"email":             user.Email,
			"emailVerified":     user.EmailVerified,
			"smtpEnabled":       settings.SMTPEnabled,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_email_verification.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountEmailSendVerificationPost(
    httpHelper handlers.HttpHelper,
    apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {


        result := EmailSendVerificationResult{}

        // Get JWT info to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.JsonError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }

        resp, err := apiClient.SendAccountEmailVerification(jwtInfo.TokenResponse.AccessToken)
        if err != nil {
            httpHelper.JsonError(w, r, err)
            return
        }

        result.EmailVerified = resp.EmailVerified
        result.EmailVerificationSent = resp.EmailVerificationSent
        result.EmailDestination = resp.EmailDestination
        result.TooManyRequests = resp.TooManyRequests
        result.WaitInSeconds = resp.WaitInSeconds
        httpHelper.EncodeJson(w, r, result)
	}
}

func HandleAccountEmailVerificationPost(
    httpHelper handlers.HttpHelper,
    httpSession sessions.Store,
    apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

        // Get JWT info for API calls and current profile rendering
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }

        user, err := apiClient.GetAccountProfile(jwtInfo.TokenResponse.AccessToken)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }

        verificationCode := strings.TrimSpace(r.FormValue("verificationCode"))
        req := &api.VerifyAccountEmailRequest{VerificationCode: verificationCode}

        if _, err := apiClient.VerifyAccountEmail(jwtInfo.TokenResponse.AccessToken, req); err != nil {
            // Handle invalid/expired code gracefully as validation error
            if apiErr, ok := err.(*apiclient.APIError); ok && apiErr.Code == "INVALID_OR_EXPIRED_VERIFICATION_CODE" {
                settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
                bind := map[string]interface{}{
                    "savedSuccessfully": false,
                    "email":             user.Email,
                    "emailVerified":     user.EmailVerified,
                    "smtpEnabled":       settings.SMTPEnabled,
                    "csrfField":         csrf.TemplateField(r),
                    "error":             apiErr.Message,
                    "verificationCode":  verificationCode,
                }
                if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_email_verification.html", bind); err != nil {
                    httpHelper.InternalServerError(w, r, err)
                }
                return
            }

            // Delegate other errors to generic handler
            handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(errorMessage string) {
                settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
                bind := map[string]interface{}{
                    "savedSuccessfully": false,
                    "email":             user.Email,
                    "emailVerified":     user.EmailVerified,
                    "smtpEnabled":       settings.SMTPEnabled,
                    "csrfField":         csrf.TemplateField(r),
                    "error":             errorMessage,
                    "verificationCode":  verificationCode,
                }
                if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_email_verification.html", bind); err != nil {
                    httpHelper.InternalServerError(w, r, err)
                }
            })
            return
        }

        sess, err := httpSession.Get(r, constants.SessionName)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }
        sess.AddFlash("true", "savedSuccessfully")
        if err := httpSession.Save(r, w, sess); err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }

        http.Redirect(w, r, config.GetAdminConsole().BaseURL+"/account/email-verification", http.StatusFound)
	}
}
