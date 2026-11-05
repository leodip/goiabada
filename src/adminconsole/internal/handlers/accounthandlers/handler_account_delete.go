package accounthandlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// accountDeleteAPI is what the Delete account page needs: the profile, for whether two-factor
// authentication is on, and the deletion.
type accountDeleteAPI interface {
	GetAccountProfile(ctx context.Context, accessToken string) (*api.UserResponse, error)
	DeleteAccount(ctx context.Context, accessToken string, request *api.DeleteAccountRequest) error
}

// accountDeleteErrorFields maps the refusals of POST /api/v1/account/deletion that the page draws
// on its form to the field each is about. A code missing a field here but listed in
// isHandledAccountDeleteError is drawn at the top of the form alone.
var accountDeleteErrorFields = map[string]string{
	"AUTHENTICATION_FAILED": "password",
	"INVALID_OTP_CODE":      "otp",
	"OTP_CLOCK_AHEAD":       "otp",
	"OTP_CODE_REQUIRED":     "otp",
	"INVALID_RECOVERY_CODE": "recoveryCode",
}

// isHandledAccountDeleteError says whether a refusal of the deletion is one the user acts on, drawn
// on the form with the API's sentence, which is already in the request's language (#783 decision
// 3): a credential refused, two refusals that are the account's state rather than a fault (the last
// administrator, and the setting turned off after the console last read the public settings), and
// both codes sent at once. Anything else, CLIENT_NOT_ALLOWED included, is a fault the classifier
// answers.
func isHandledAccountDeleteError(code string) bool {
	switch code {
	case "AUTHENTICATION_FAILED",
		"INVALID_OTP_CODE",
		"OTP_CLOCK_AHEAD",
		"OTP_CODE_REQUIRED",
		"INVALID_RECOVERY_CODE",
		"VALIDATION_ERROR",
		"LAST_ADMINISTRATOR",
		"ACCOUNT_DELETION_DISABLED":
		return true
	}
	return false
}

// accountDeletionShown says whether the page is there: only while the public settings say users
// may delete their own account, as the account menu draws it (#783 decision 6). The auth server
// checks the setting itself on every deletion, so this decides only what is shown.
func accountDeletionShown(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request) bool {
	settings, ok := reqctx.SettingsFrom(r.Context())
	if !ok {
		httpHelper.InternalServerError(w, r, reqctx.ErrNoSettings)
		return false
	}
	if !settings.AccountDeletionEnabled {
		httpHelper.NotFound(w, r)
		return false
	}
	return true
}

// HandleDeleteAccountGet draws the Delete account page: what is deleted and what is kept, the
// password, and while two-factor authentication is on, the authentication code, with the recovery
// code as the other choice (#783 decisions 2 and 9). It answers 404 while deletion is off.
func HandleDeleteAccountGet(
	httpHelper HttpHelper,
	apiClient accountDeleteAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		if !accountDeletionShown(httpHelper, w, r) {
			return
		}
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}
		renderDeleteAccountPage(httpHelper, apiClient, w, r, jwtInfo.TokenResponse.AccessToken, map[string]interface{}{
			"useRecoveryCode": false,
		})
	}
}

// HandleDeleteAccountPost asks the auth server to delete the user's own account with what they
// typed. A refusal they can act on is drawn on the form. After the deletion, the console deletes
// its own session, row and cookie, and sends the browser to /account/deleted with a 303, so a
// reload of that page resubmits nothing (#783 decision 8). The deletion has already ended the
// user's sessions at the auth server and deleted their refresh tokens.
//
// The page draws one second-factor field enabled, the other disabled, so the form posts the one the
// user chose. Which one it posted is what the redrawn form shows again, and where a refusal of a
// missing code is drawn.
func HandleDeleteAccountPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient accountDeleteAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		if !accountDeletionShown(httpHelper, w, r) {
			return
		}
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}
		accessToken := jwtInfo.TokenResponse.AccessToken

		// r.PostFormValue rather than r.FormValue: a credential in the query string would reach the
		// browser's history and every proxy's access log (#202).
		request := &api.DeleteAccountRequest{
			Password:     r.PostFormValue("password"),
			OtpCode:      r.PostFormValue("otp"),
			RecoveryCode: r.PostFormValue("recoveryCode"),
		}
		useRecoveryCode := r.PostForm.Has("recoveryCode")

		renderRefusal := func(message, errorField string) {
			if errorField == "otp" && useRecoveryCode {
				errorField = "recoveryCode"
			}
			renderDeleteAccountPage(httpHelper, apiClient, w, r, accessToken, map[string]interface{}{
				"error":           message,
				"errorField":      errorField,
				"useRecoveryCode": useRecoveryCode,
			})
		}

		if err := apiClient.DeleteAccount(r.Context(), accessToken, request); err != nil {
			if render.IsRateLimited(err) {
				renderRefusal(render.RateLimitedMessage(r.Context()), "")
				return
			}
			var apiErr *apiclient.APIError
			if errors.As(err, &apiErr) && isHandledAccountDeleteError(apiErr.Code) {
				renderRefusal(apiErr.Message, accountDeleteErrorFields[apiErr.Code])
				return
			}
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		session, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		session.Options.MaxAge = -1
		if err := httpSession.Save(r, w, session); err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, baseURL+"/account/deleted", http.StatusSeeOther)
	}
}

// renderDeleteAccountPage draws the form with bind's entries, asking for a second factor while the
// account has two-factor authentication on now, read from the auth server each time.
func renderDeleteAccountPage(httpHelper HttpHelper, apiClient accountDeleteAPI, w http.ResponseWriter, r *http.Request,
	accessToken string, bind map[string]interface{}) {

	user, err := apiClient.GetAccountProfile(r.Context(), accessToken)
	if err != nil {
		render.HandleAPIError(httpHelper, w, r, err)
		return
	}
	bind["otpEnabled"] = user.OTPEnabled

	if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_delete.html", bind); err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

// HandleAccountDeletedGet draws /account/deleted, the page a deletion lands on, on the layout
// without a menu. It is the same page for anyone who opens it: it reads no session and calls
// nothing, so it is mounted outside the account pages' sign-in (#783 decision 8).
func HandleAccountDeletedGet(
	httpHelper HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		if err := httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/account_deleted.html", nil); err != nil {
			httpHelper.InternalServerError(w, r, err)
		}
	}
}
