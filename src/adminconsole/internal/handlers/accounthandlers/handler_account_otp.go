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

		// r.PostFormValue rather than r.FormValue, here and for the otp read in the enrolment
		// branch below: r.Form merges the URL query behind the request body, so
		// /account/otp?password=... would have carried the password. A credential in a request
		// target reaches the browser's history, the Referer of anything the page loads, and the
		// access log of every proxy in front of the deployment. This route is POST-only with a
		// separate GET handler rendering the form, so the query was never a submission (#202).
		password := r.PostFormValue("password")

		// renderDisableError redraws the disable form, which needs nothing but the message.
		renderDisableError := func(message string) {
			bind := map[string]interface{}{
				"error":      message,
				"otpEnabled": true,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_otp.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// renderEnrollmentError redraws the enrolment form with its QR code and seed, fetched from
		// the API rather than read back out of the submitted form.
		//
		// The form used to carry them in two hidden inputs, so the browser held the TOTP shared
		// secret and an image encoding it and posted both back on every attempt. Those inputs are
		// gone, and this call is what replaces them: the enrolment endpoint is idempotent while an
		// enrolment is pending, so a rerender shows the user the same QR code they have already
		// scanned, and mints a replacement only once the pending one has expired or been used
		// (#247).
		//
		// Without it the page would still render, and that is why it is worth stating: the enable
		// branch of account_otp.html draws the <img> and the <pre> unconditionally, so a blank
		// code or a wrong password would have rerendered an empty QR code and an empty seed, and
		// the user could not have finished enrolling.
		renderEnrollmentError := func(message string) {
			enrollment, err := apiClient.GetAccountOTPEnrollment(jwtInfo.TokenResponse.AccessToken)
			if err != nil {
				handlers.HandleAPIError(httpHelper, w, r, err)
				return
			}

			bind := map[string]interface{}{
				"error":       message,
				"otpEnabled":  false,
				"base64Image": enrollment.Base64Image,
				"secretKey":   enrollment.SecretKey,
			}

			err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_otp.html", bind)
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
				if apiErr, ok := err.(*apiclient.APIError); ok && isHandledAccountOTPError(apiErr.Code) {
					renderDisableError(apiErr.Message)
					return
				}
				handlers.HandleAPIError(httpHelper, w, r, err)
				return
			}
		} else {
			// enabling
			otpCode := r.PostFormValue("otp")

			if len(otpCode) == 0 {
				renderEnrollmentError("OTP code is required.")
				return
			}

			// No secret goes up with this. The server issued the enrolment at
			// GET /api/v1/account/otp/enrollment, recorded it against this user, and enrols
			// that seed and no other, so the console has nothing to choose and nothing to
			// carry (#247).
			req := &api.UpdateAccountOTPRequest{
				Enabled:  true,
				Password: password,
				OtpCode:  otpCode,
			}
			if _, err := apiClient.UpdateAccountOTP(jwtInfo.TokenResponse.AccessToken, req); err != nil {
				if apiErr, ok := err.(*apiclient.APIError); ok {
					// An enrolment that has already succeeded, from another tab or another
					// client, reloads the page instead of redrawing the form. Redrawing it
					// would call the enrolment endpoint, which refuses for this same reason,
					// and turn a race that resolved correctly into an error page.
					if apiErr.Code == "OTP_ALREADY_ENABLED" {
						http.Redirect(w, r, config.GetAdminConsole().BaseURL+"/account/otp", http.StatusFound)
						return
					}
					if isHandledAccountOTPError(apiErr.Code) {
						renderEnrollmentError(apiErr.Message)
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

// isHandledAccountOTPError says whether a 400 from PUT /api/v1/account/otp is one this page can
// explain to the user by redrawing the form with the API's message. Anything else is a fault
// rather than something they did, and HandleAPIError sends it to the log and shows a generic
// error page.
//
// The list is kept complete against the endpoint's own codes rather than trimmed to the ones this
// client can currently provoke, which is why SECRET_KEY_NOT_ACCEPTED is here: the console no
// longer sends a secretKey, so it cannot see that refusal today, and a code missing from this list
// reaches the user as an unexplained server error rather than as the sentence the API wrote for
// them (#247).
func isHandledAccountOTPError(code string) bool {
	switch code {
	case "AUTHENTICATION_FAILED",
		"INVALID_OTP_CODE",
		"OTP_CODE_REQUIRED",
		"OTP_ENROLLMENT_NOT_PENDING",
		"SECRET_KEY_NOT_ACCEPTED",
		"OTP_ALREADY_ENABLED",
		"OTP_NOT_ENABLED":
		return true
	}
	return false
}
