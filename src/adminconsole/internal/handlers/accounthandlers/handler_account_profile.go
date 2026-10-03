package accounthandlers

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/handlerhelpers"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/locales"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/timezones"
)

// accountProfileAPI is what the account profile page needs: the profile it renders from, and the
// write.
type accountProfileAPI interface {
	GetAccountProfile(ctx context.Context, accessToken string) (*api.UserResponse, error)
	UpdateAccountProfile(ctx context.Context, accessToken string, request *api.UpdateUserProfileRequest) (*api.UserResponse, error)
}

func HandleAccountProfileGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient accountProfileAPI,
) http.HandlerFunc {

	timezones := timezones.All()
	locales := locales.All()

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

		sess, err := httpSession.Get(r, coreconstants.AdminConsoleSessionName)
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
			"user":              user,
			"timezones":         timezones,
			"locales":           locales,
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_profile.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountProfilePost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient accountProfileAPI,
	baseURL string,
) http.HandlerFunc {

	timezones := timezones.All()
	locales := locales.All()

	return func(w http.ResponseWriter, r *http.Request) {

		// Get access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Load current profile (for successful render or error rebound)
		user, err := apiClient.GetAccountProfile(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlerhelpers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		request, err := handlerhelpers.ParseProfileForm(r)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Call API to update
		updatedUser, err := apiClient.UpdateAccountProfile(r.Context(), jwtInfo.TokenResponse.AccessToken, request)
		if err != nil {
			// Render validation error retaining input
			handlerhelpers.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(errorMessage string) {
				// reflect submitted values onto user for display
				handlerhelpers.EchoProfileForm(user, request)

				bind := map[string]interface{}{
					"user":      user,
					"timezones": timezones,
					"locales":   locales,
					"error":     errorMessage,
				}

				if renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_profile.html", bind); renderErr != nil {
					httpHelper.InternalServerError(w, r, renderErr)
					return
				}
			})
			return
		}

		sess, err := httpSession.Get(r, coreconstants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		sess.SetFlash("savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		_ = updatedUser // we don't need it here besides success confirmation

		http.Redirect(w, r, baseURL+"/account/profile", http.StatusFound)
	}
}
