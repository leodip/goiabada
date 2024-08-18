package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/enums"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/pquerna/otp/totp"
)

func HandleAuthOtpGet(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	authHelper AuthHelper,
	database data.Database,
	otpSecretGenerator OtpSecretGenerator,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		authContext, err := authHelper.GetAuthContext(r)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		user, err := database.GetUserById(nil, authContext.UserId)
		if err != nil || user == nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if !user.OTPEnabled {
			// must enroll first

			// generate secret
			settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
			base64Image, secretKey, err := otpSecretGenerator.GenerateOTPSecret(user.Email, settings.AppName)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			bind := map[string]interface{}{
				"error":       nil,
				"csrfField":   csrf.TemplateField(r),
				"base64Image": base64Image,
				"secretKey":   secretKey,
			}

			// save image and secret in the session state
			sess.Values[constants.SessionKeyOTPSecret] = secretKey
			sess.Values[constants.SessionKeyOTPImage] = base64Image
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/auth_otp_enrollment.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		} else {

			delete(sess.Values, constants.SessionKeyOTPImage)
			delete(sess.Values, constants.SessionKeyOTPSecret)
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			bind := map[string]interface{}{
				"error":     nil,
				"csrfField": csrf.TemplateField(r),
			}

			err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/auth_otp.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}
	}
}

func HandleAuthOtpPost(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	authHelper AuthHelper,
	userSessionManager UserSessionManager,
	database data.Database,
	auditLogger AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		authContext, err := authHelper.GetAuthContext(r)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
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

		user, err := database.GetUserById(nil, authContext.UserId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			template := "/auth_otp.html"
			if len(base64Image) > 0 && len(secretKey) > 0 {
				template = "/auth_otp_enrollment.html"
				bind["base64Image"] = base64Image
				bind["secretKey"] = secretKey
			}

			err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", template, bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		otpCode := r.FormValue("otp")
		if len(otpCode) == 0 {
			renderError("OTP code is required.")
			return
		}

		incorrectOtpError := "Incorrect OTP Code. OTP codes are time-sensitive and change every 30 seconds. Make sure you're using the most recent code generated by your authenticator app."

		if user.OTPEnabled {
			// already has OTP enrolled
			otpValid := totp.Validate(otpCode, user.OTPSecret)
			if !otpValid {
				auditLogger.Log(constants.AuditAuthFailedOtp, map[string]interface{}{
					"userId": user.Id,
				})
				renderError(incorrectOtpError)
				return
			}
		} else {
			// is enrolling to TOTP now
			otpValid := totp.Validate(otpCode, secretKey)
			if !otpValid {
				auditLogger.Log(constants.AuditAuthFailedOtp, map[string]interface{}{
					"userId": user.Id,
				})
				renderError(incorrectOtpError)
				return
			}

			// save TOTP secret
			user.OTPSecret = secretKey
			user.OTPEnabled = true
			err = database.UpdateUser(nil, user)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		auditLogger.Log(constants.AuditAuthSuccessOtp, map[string]interface{}{
			"userId": user.Id,
		})

		if !user.Enabled {
			auditLogger.Log(constants.AuditUserDisabled, map[string]interface{}{
				"userId": user.Id,
			})
			renderError("Your account is disabled.")
			return
		}

		client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", authContext.ClientId))))
			return
		}

		requestedAcrValues := authContext.ParseRequestedAcrValues()
		targetAcrLevel := client.DefaultAcrLevel

		if len(requestedAcrValues) > 0 {
			targetAcrLevel = requestedAcrValues[0]
		}

		// start new session
		_, err = userSessionManager.StartNewUserSession(w, r, user.Id, client.Id,
			enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), targetAcrLevel.String())
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditStartedNewUserSesson, map[string]interface{}{
			"userId":   user.Id,
			"clientId": client.Id,
		})

		// redirect to consent
		authContext.AcrLevel = targetAcrLevel.String()
		authContext.AuthMethods = enums.AuthMethodPassword.String() + " " + enums.AuthMethodOTP.String()
		authContext.AuthTime = time.Now().UTC()
		authContext.AuthCompleted = true
		err = authHelper.SaveAuthContext(w, r, authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, config.AuthServerBaseUrl+"/auth/consent", http.StatusFound)
	}
}
