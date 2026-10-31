package accounthandlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
)

// accountOTPAPI is what the account OTP page needs: the enrolment offer, the profile, and the
// write.
type accountOTPAPI interface {
	GetAccountOTPEnrollment(ctx context.Context, accessToken string) (*api.AccountOTPEnrollmentResponse, error)
	GetAccountProfile(ctx context.Context, accessToken string) (*api.UserResponse, error)
	UpdateAccountOTP(ctx context.Context, accessToken string, request *api.UpdateAccountOTPRequest) (*api.UserResponse, error)
}

func HandleOtpGet(
	httpHelper HttpHelper,
	apiClient accountOTPAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Load current user profile via API
		user, err := apiClient.GetAccountProfile(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"otpEnabled": user.OTPEnabled,
		}

		if !user.OTPEnabled {
			// request enrollment secret and QR from API
			enrollment, enrollmentErr := apiClient.GetAccountOTPEnrollment(r.Context(), jwtInfo.TokenResponse.AccessToken)
			if enrollmentErr != nil {
				render.HandleAPIError(httpHelper, w, r, enrollmentErr)
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

func HandleOtpPost(
	httpHelper HttpHelper,
	apiClient accountOTPAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}
		// The posted form says what it does, enable or disable, and the auth server is asked for
		// that and nothing else. The page used to read the user's stored state and ask for its
		// inverse, whichever form had been posted, so an enrolment form left open in one tab and
		// posted after enrolling in another switched the second factor off with nothing but the
		// password. The auth server refuses an enable for a user who has OTP and a disable for one
		// who has not, and either refusal reloads the page, which then draws the account as it is
		// now; a post naming neither form changes nothing and reloads it the same way (#562
		// decision 8).
		otpAction := r.PostFormValue("otpAction")
		if otpAction != "enable" && otpAction != "disable" {
			http.Redirect(w, r, baseURL+"/account/otp", http.StatusFound)
			return
		}

		// r.PostFormValue rather than r.FormValue, here and for the otp read in the enrolment
		// branch below: r.Form merges the URL query behind the request body, so
		// /account/otp?password=... would have carried the password. A credential in a request
		// target reaches the browser's history, the Referer of anything the page loads, and the
		// access log of every proxy in front of the deployment. This route is POST-only with a
		// separate GET handler rendering the form, so the query was never a submission (#202).
		password := r.PostFormValue("password")

		// renderDisableError redraws the disable form, which needs nothing but the message and the
		// field it is about.
		renderDisableError := func(message, errorField string) {
			bind := map[string]interface{}{
				"error":      message,
				"errorField": errorField,
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
		//
		// The enrolment endpoint refuses a user who has OTP, and an enrolment form posted by one is
		// a stale form refused on its own terms, a blank code or a wrong password, before the auth
		// server looked at the state: the page reloads, as it does for the enable itself.
		renderEnrollmentError := func(message, errorField string) {
			enrollment, err := apiClient.GetAccountOTPEnrollment(r.Context(), jwtInfo.TokenResponse.AccessToken)
			if err != nil {
				var apiErr *apiclient.APIError
				if errors.As(err, &apiErr) && apiErr.Code == "OTP_ALREADY_ENABLED" {
					http.Redirect(w, r, baseURL+"/account/otp", http.StatusFound)
					return
				}
				render.HandleAPIError(httpHelper, w, r, err)
				return
			}

			bind := map[string]interface{}{
				"error":       message,
				"errorField":  errorField,
				"otpEnabled":  false,
				"base64Image": enrollment.Base64Image,
				"secretKey":   enrollment.SecretKey,
			}

			err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_otp.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		if otpAction == "disable" {
			req := &api.UpdateAccountOTPRequest{
				Enabled:  false,
				Password: password,
			}
			if _, err := apiClient.UpdateAccountOTP(r.Context(), jwtInfo.TokenResponse.AccessToken, req); err != nil {
				if render.IsRateLimited(err) {
					renderDisableError(render.RateLimitedMessage(r.Context()), "")
					return
				}
				var apiErr *apiclient.APIError
				if errors.As(err, &apiErr) {
					// OTP already off, from another tab or another client: a stale disable form.
					if apiErr.Code == "OTP_NOT_ENABLED" {
						http.Redirect(w, r, baseURL+"/account/otp", http.StatusFound)
						return
					}
					if isHandledAccountOTPError(apiErr.Code) {
						renderDisableError(apiErr.Message, accountOTPErrorFields[apiErr.Code])
						return
					}
				}
				render.HandleAPIError(httpHelper, w, r, err)
				return
			}
		} else {
			otpCode := r.PostFormValue("otp")

			if len(otpCode) == 0 {
				renderEnrollmentError(i18n.NewLocalizedError(i18n.ErrCodeOtpCodeRequired, nil).Localize(r.Context()), "otp")
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
			if _, err := apiClient.UpdateAccountOTP(r.Context(), jwtInfo.TokenResponse.AccessToken, req); err != nil {
				if render.IsRateLimited(err) {
					renderEnrollmentError(render.RateLimitedMessage(r.Context()), "")
					return
				}
				var apiErr *apiclient.APIError
				if errors.As(err, &apiErr) {
					// An enrolment that has already succeeded, from another tab or another
					// client, reloads the page instead of redrawing the form. Redrawing it
					// would call the enrolment endpoint, which refuses for this same reason,
					// and turn a race that resolved correctly into an error page.
					if apiErr.Code == "OTP_ALREADY_ENABLED" {
						http.Redirect(w, r, baseURL+"/account/otp", http.StatusFound)
						return
					}
					if isHandledAccountOTPError(apiErr.Code) {
						renderEnrollmentError(apiErr.Message, accountOTPErrorFields[apiErr.Code])
						return
					}
				}
				render.HandleAPIError(httpHelper, w, r, err)
				return
			}
		}

		http.Redirect(w, r, baseURL+"/account/otp", http.StatusFound)
	}
}

// accountOTPErrorFields maps the refusals the page explains to the field each is about: the
// password the auth server found wrong, and the code it refused.
var accountOTPErrorFields = map[string]string{
	"AUTHENTICATION_FAILED": "password",
	"INVALID_OTP_CODE":      "otp",
	"OTP_CODE_REQUIRED":     "otp",
	"OTP_CLOCK_AHEAD":       "otp",
}

// isHandledAccountOTPError says whether a 400 or 409 from PUT /api/v1/account/otp is one this page
// can explain to the user by redrawing the form with the API's message. Anything else is a fault
// rather than something they did, and HandleAPIError sends it to the log and shows a generic
// error page. A 429 is decided before this is asked: the API allows five wrong passwords per user
// per 15 minutes here, so the form is redrawn with the console's own rate-limit sentence, in the
// page's language, rather than the API's English one (#559 decision 10).
//
// OTP_CLOCK_AHEAD is a code from the step after the auth server's current one, which only an
// authenticator whose clock runs ahead shows: the user acts on it by fixing the device's time, so it
// is shown on the code field (#142).
//
// CONCURRENT_UPDATE is the 409 the API answers when the account's authenticator changed under the
// request, from another tab or client, and nothing was saved: the user acts on it by trying again,
// so it belongs on the form (#471 decision 2).
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
		"OTP_CLOCK_AHEAD",
		"OTP_ENROLLMENT_NOT_PENDING",
		"SECRET_KEY_NOT_ACCEPTED",
		"OTP_ALREADY_ENABLED",
		"OTP_NOT_ENABLED",
		"CONCURRENT_UPDATE":
		return true
	}
	return false
}
