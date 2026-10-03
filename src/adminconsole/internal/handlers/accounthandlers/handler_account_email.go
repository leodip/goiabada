package accounthandlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/handlerhelpers"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// accountEmailAPI is what the account email page needs: the profile it renders from, and the
// email write.
type accountEmailAPI interface {
	GetAccountProfile(ctx context.Context, accessToken string) (*api.UserResponse, error)
	UpdateAccountEmail(ctx context.Context, accessToken string, request *api.UpdateAccountEmailRequest) (*api.UserResponse, error)
}

func HandleAccountEmailGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient accountEmailAPI,
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
			handlerhelpers.HandleAPIError(httpHelper, w, r, err)
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

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		bind := map[string]interface{}{
			"savedSuccessfully": savedSuccessfully,
			"email":             user.Email,
			"emailVerified":     user.EmailVerified,
			"emailConfirmation": "",
			"smtpEnabled":       settings.SMTPEnabled,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_email.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountEmailPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient accountEmailAPI,
	baseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info and current user for re-render on error
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		user, err := apiClient.GetAccountProfile(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlerhelpers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
		emailConfirmation := strings.ToLower(strings.TrimSpace(r.FormValue("emailConfirmation")))
		// The auth server refuses the change without the current password (#404). Read from the
		// request body only, as the change-password page reads it: a password in the request
		// target reaches the browser's history, Referers and proxy logs (#202). Never bound back
		// into the page, so a re-render asks for it again.
		currentPassword := r.PostFormValue("currentPassword")

		// UI-level confirmation check
		if email != emailConfirmation {
			bind := map[string]interface{}{
				"user":              user,
				"email":             email,
				"emailVerified":     user.EmailVerified,
				"emailConfirmation": emailConfirmation,
				"error":             "The email and email confirmation entries must be identical.",
			}
			if renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_email.html", bind); renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
			return
		}

		// Sent as typed: surrounding whitespace is part of a password, and the auth server
		// compares the one it was given, so trimming would refuse the right password and charge
		// the account's failure budget for it.
		req := &api.UpdateAccountEmailRequest{
			Email:           email,
			CurrentPassword: currentPassword,
		}
		_, err = apiClient.UpdateAccountEmail(r.Context(), jwtInfo.TokenResponse.AccessToken, req)
		if err != nil {
			handlerhelpers.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(errorMessage string) {
				bind := map[string]interface{}{
					"user":              user,
					"email":             email,
					"emailVerified":     user.EmailVerified,
					"emailConfirmation": emailConfirmation,
					"error":             errorMessage,
				}
				if renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_email.html", bind); renderErr != nil {
					httpHelper.InternalServerError(w, r, renderErr)
				}
			})
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

		http.Redirect(w, r, baseURL+"/account/email", http.StatusFound)
	}
}
