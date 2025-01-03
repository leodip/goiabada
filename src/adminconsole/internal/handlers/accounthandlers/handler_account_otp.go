package accounthandlers

import (
	"net/http"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/pquerna/otp/totp"
)

func HandleAccountOtpGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	otpSecretGenerator handlers.OtpSecretGenerator,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		loggedInSubject := authHelper.GetLoggedInSubject(r)
		if strings.TrimSpace(loggedInSubject) == "" {
			http.Redirect(w, r, config.Get().BaseURL+"/unauthorized", http.StatusFound)
			return
		}
		user, err := database.GetUserBySubject(nil, loggedInSubject)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"otpEnabled": user.OTPEnabled,
			"csrfField":  csrf.TemplateField(r),
		}

		if !user.OTPEnabled {
			// generate secret
			settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
			base64Image, secretKey, err := otpSecretGenerator.GenerateOTPSecret(user.Email, settings.AppName)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			bind["base64Image"] = base64Image
			bind["secretKey"] = secretKey

			sess, err := httpSession.Get(r, constants.SessionName)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			// save image and secret in the session state
			sess.Values[constants.SessionKeyOTPSecret] = secretKey
			sess.Values[constants.SessionKeyOTPImage] = base64Image
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_otp.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountOtpPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		loggedInSubject := authHelper.GetLoggedInSubject(r)
		if strings.TrimSpace(loggedInSubject) == "" {
			http.Redirect(w, r, config.Get().BaseURL+"/unauthorized", http.StatusFound)
			return
		}
		user, err := database.GetUserBySubject(nil, loggedInSubject)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		password := r.FormValue("password")

		renderError := func(message string, base64Image string, secretKey string) {
			bind := map[string]interface{}{
				"error":      message,
				"otpEnabled": user.OTPEnabled,
				"csrfField":  csrf.TemplateField(r),
			}

			if len(base64Image) > 0 {
				bind["base64Image"] = base64Image
				bind["secretKey"] = secretKey
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_otp.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		const authFailedError = "Authentication failed. Check your password and try again."

		if user.OTPEnabled {

			if !hashutil.VerifyPasswordHash(user.PasswordHash, password) {
				renderError(authFailedError, "", "")
				return
			}

			// disable OTP
			user.OTPSecret = ""
			user.OTPEnabled = false
			err = database.UpdateUser(nil, user)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			auditLogger.Log(constants.AuditDisabledOTP, map[string]interface{}{
				"userId": user.Id,
			})
		} else {
			// enable OTP

			sess, err := httpSession.Get(r, constants.SessionName)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			base64Image, secretKey := "", ""
			if val, ok := sess.Values[constants.SessionKeyOTPImage]; ok {
				base64Image = val.(string)
			}
			if val, ok := sess.Values[constants.SessionKeyOTPSecret]; ok {
				secretKey = val.(string)
			}

			if !hashutil.VerifyPasswordHash(user.PasswordHash, password) {
				renderError(authFailedError, base64Image, secretKey)
				return
			}

			otpCode := r.FormValue("otp")
			if len(otpCode) == 0 {
				renderError("OTP code is required.", base64Image, secretKey)
				return
			}

			otpValid := totp.Validate(otpCode, secretKey)
			if !otpValid {
				renderError("Incorrect OTP Code. OTP codes are time-sensitive and change every 30 seconds. Make sure you're using the most recent code generated by your authenticator app.", base64Image, secretKey)
				return
			}

			// save OTP secret
			user.OTPSecret = secretKey
			user.OTPEnabled = true
			err = database.UpdateUser(nil, user)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			auditLogger.Log(constants.AuditEnabledOTP, map[string]interface{}{
				"userId": user.Id,
			})
		}

		// update session to flag a level 2 auth method configuration has changed
		// this is important when deciding whether to prompt the user to authenticate with level 2 methods

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		userSession.Level2AuthConfigHasChanged = true

		err = database.UpdateUserSession(nil, userSession)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, config.Get().BaseURL+"/account/otp", http.StatusFound)
	}
}
