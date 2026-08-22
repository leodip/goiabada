package accounthandlers

import (
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

func HandleAccountOtpGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Load current user profile via API
		user, err := apiClient.GetAccountProfile(jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"otpEnabled": user.OTPEnabled,
		}

		if !user.OTPEnabled {
			// request enrollment secret and QR from API
			enrollment, err := apiClient.GetAccountOTPEnrollment(jwtInfo.TokenResponse.AccessToken)
			if err != nil {
				handlers.HandleAPIError(httpHelper, w, r, err)
				return
			}

			bind["base64Image"] = enrollment.Base64Image
			bind["secretKey"] = enrollment.SecretKey
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
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}
		// Load user to determine current OTP state
		user, err := apiClient.GetAccountProfile(jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// r.PostFormValue rather than r.FormValue, here and for the otp, secretKey and base64Image
		// reads in the enrolment branch below: r.Form merges the URL query behind the request body,
		// so /account/otp?password=... would have carried the password, and the enrolment fields are
		// the TOTP shared secret itself plus the QR image encoding it. A credential in a request
		// target reaches the browser's history, the Referer of anything the page loads, and the
		// access log of every proxy in front of the deployment. This route is POST-only with a
		// separate GET handler rendering the form, so the query was never a submission (#202).
		password := r.PostFormValue("password")

		renderError := func(message string, base64Image string, secretKey string) {
			bind := map[string]interface{}{
				"error":      message,
				"otpEnabled": user.OTPEnabled,
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

		if user.OTPEnabled {
			// disabling
			req := &api.UpdateAccountOTPRequest{
				Enabled:  false,
				Password: password,
			}
			if _, err := apiClient.UpdateAccountOTP(jwtInfo.TokenResponse.AccessToken, req); err != nil {
				if apiErr, ok := err.(*apiclient.APIError); ok {
					switch apiErr.Code {
					case "AUTHENTICATION_FAILED", "INVALID_OTP_CODE", "INVALID_OTP_SECRET",
						"OTP_CODE_AND_SECRET_REQUIRED", "OTP_ALREADY_ENABLED", "OTP_NOT_ENABLED":
						bind := map[string]interface{}{
							"error":      apiErr.Message,
							"otpEnabled": user.OTPEnabled,
						}
						if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_otp.html", bind); err != nil {
							httpHelper.InternalServerError(w, r, err)
							return
						}
						return
					}
				}
				handlers.HandleAPIError(httpHelper, w, r, err)
				return
			}
		} else {
			// enabling
			otpCode := r.PostFormValue("otp")
			secretKey := r.PostFormValue("secretKey")
			base64Image := r.PostFormValue("base64Image")

			if len(otpCode) == 0 {
				renderError("OTP code is required.", base64Image, secretKey)
				return
			}

			req := &api.UpdateAccountOTPRequest{
				Enabled:   true,
				Password:  password,
				OtpCode:   otpCode,
				SecretKey: secretKey,
			}
			if _, err := apiClient.UpdateAccountOTP(jwtInfo.TokenResponse.AccessToken, req); err != nil {
				if apiErr, ok := err.(*apiclient.APIError); ok {
					switch apiErr.Code {
					case "AUTHENTICATION_FAILED", "INVALID_OTP_CODE", "INVALID_OTP_SECRET",
						"OTP_CODE_AND_SECRET_REQUIRED", "OTP_ALREADY_ENABLED", "OTP_NOT_ENABLED":
						bind := map[string]interface{}{
							"error":       apiErr.Message,
							"otpEnabled":  user.OTPEnabled,
							"base64Image": base64Image,
							"secretKey":   secretKey,
						}
						if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_otp.html", bind); err != nil {
							httpHelper.InternalServerError(w, r, err)
							return
						}
						return
					}
				}
				handlers.HandleAPIError(httpHelper, w, r, err)
				return
			}
		}

		http.Redirect(w, r, config.GetAdminConsole().BaseURL+"/account/otp", http.StatusFound)
	}
}
