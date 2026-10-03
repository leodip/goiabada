package accounthandlers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
)

// accountEmailVerificationAPI is what email verification needs: the profile, the send, and the
// verify.
type accountEmailVerificationAPI interface {
	GetAccountProfile(ctx context.Context, accessToken string) (*api.UserResponse, error)
	SendAccountEmailVerification(ctx context.Context, accessToken string) (*api.AccountEmailVerificationSendResponse, error)
	VerifyAccountEmail(ctx context.Context, accessToken string, request *api.VerifyAccountEmailRequest) (*api.UserResponse, error)
}

func HandleEmailVerificationGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient accountEmailVerificationAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}
		user, err := apiClient.GetAccountProfile(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		if !settings.SMTPEnabled {
			httpHelper.InternalServerError(w, r, errs.New("SMTP is not enabled"))
			return
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
			"savedSuccessfully": savedSuccessfully,
			"email":             user.Email,
			"emailVerified":     user.EmailVerified,
			"smtpEnabled":       settings.SMTPEnabled,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_email_verification.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleEmailSendVerificationPost(
	httpHelper HttpHelper,
	apiClient accountEmailVerificationAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		result := EmailSendVerificationResult{}

		// Get JWT info to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		resp, err := apiClient.SendAccountEmailVerification(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		result.EmailVerified = resp.EmailVerified
		result.EmailVerificationSent = resp.EmailVerificationSent
		result.EmailDestination = resp.EmailDestination
		result.TooManyRequests = resp.TooManyRequests
		result.WaitInSeconds = resp.WaitInSeconds
		httpHelper.EncodeJSON(w, r, result)
	}
}

func HandleEmailVerificationPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient accountEmailVerificationAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info for API calls and current profile rendering
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		user, err := apiClient.GetAccountProfile(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// r.PostFormValue rather than r.FormValue: this code is the whole gate on an email change, so
		// r.Form merging the URL query behind the request body meant
		// /account/email-verification?verificationCode=... verified the address, leaving the code in
		// the browser's history, in the Referer of anything the page loads, and in the access log of
		// every proxy in front of the deployment. This route is POST-only with a separate GET handler
		// rendering the form, so the query was never a submission (#202).
		verificationCode := strings.TrimSpace(r.PostFormValue("verificationCode"))
		req := &api.VerifyAccountEmailRequest{VerificationCode: verificationCode}

		// renderRefused redraws the form with the code the user typed and the API's reason.
		renderRefused := func(message string) {
			settings, ok := reqctx.SettingsFrom(r.Context())
			if !ok {
				httpHelper.InternalServerError(w, r, reqctx.ErrNoSettings)
				return
			}
			bind := map[string]interface{}{
				"savedSuccessfully": false,
				"email":             user.Email,
				"emailVerified":     user.EmailVerified,
				"smtpEnabled":       settings.SMTPEnabled,
				"error":             message,
				"verificationCode":  verificationCode,
			}
			if renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_email_verification.html", bind); renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		if _, verifyErr := apiClient.VerifyAccountEmail(r.Context(), jwtInfo.TokenResponse.AccessToken, req); verifyErr != nil {
			// Handle invalid/expired code gracefully as validation error
			var apiErr *apiclient.APIError
			if errors.As(verifyErr, &apiErr) && apiErr.Code == "INVALID_OR_EXPIRED_VERIFICATION_CODE" {
				renderRefused(apiErr.Message)
				return
			}

			// Delegate other errors to generic handler
			render.HandleAPIErrorWithCallback(httpHelper, w, r, verifyErr, renderRefused)
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		sess.SetFlash("savedSuccessfully", "true")
		if err := httpSession.Save(r, w, sess); err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, baseURL+"/account/email-verification", http.StatusFound)
	}
}
