package accounthandlers

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// accountPasswordAPI is what the account password page needs: the one write it makes.
type accountPasswordAPI interface {
	UpdateAccountPassword(ctx context.Context, accessToken string, request *api.UpdateAccountPasswordRequest) (*api.UserResponse, error)
}

func HandleChangePasswordGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	_ accountPasswordAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Access token presence ensured by middleware; just handle flash UX
		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		_, savedSuccessfully := sess.TakeFlash("savedSuccessfully")
		if savedSuccessfully {
			if err := httpSession.Save(r, w, sess); err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"savedSuccessfully": savedSuccessfully,
		}

		if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_change_password.html", bind); err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleChangePasswordPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient accountPasswordAPI,
	baseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// r.PostFormValue rather than r.FormValue for all three: r.Form merges the URL query behind
		// the request body, so /account/change-password?currentPassword=...&newPassword=... would
		// have changed the password, and a password in a request target reaches the browser's
		// history, the Referer of anything the page loads, and the access log of every proxy in
		// front of the deployment. This route is POST-only with a separate GET handler rendering the
		// form, so the query was never a submission (#202).
		currentPassword := r.PostFormValue("currentPassword")
		newPassword := r.PostFormValue("newPassword")
		newPasswordConfirmation := r.PostFormValue("newPasswordConfirmation")

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error": message,
			}
			if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_change_password.html", bind); err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// UI-level confirmation check only; rest is validated by the API
		if newPassword != newPasswordConfirmation {
			renderError("The new password confirmation does not match the password.")
			return
		}

		// Sent as typed: surrounding whitespace is part of a password, and the auth server compares
		// and hashes the one it was given, so trimming would refuse the right current password, charging
		// the account's failure budget, and store a new one other than the one confirmed above (#472).
		req := &api.UpdateAccountPasswordRequest{
			CurrentPassword: currentPassword,
			NewPassword:     newPassword,
		}

		_, err := apiClient.UpdateAccountPassword(r.Context(), jwtInfo.TokenResponse.AccessToken, req)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(errorMessage string) {
				renderError(errorMessage)
			})
			return
		}

		// Flash success and redirect
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

		http.Redirect(w, r, baseURL+"/account/change-password", http.StatusFound)
	}
}
