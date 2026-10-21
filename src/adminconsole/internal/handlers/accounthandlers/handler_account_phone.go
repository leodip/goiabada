package accounthandlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/phonecountries"
	"github.com/leodip/goiabada/core/sessionstore"
)

// accountPhoneAPI is what the account phone page needs: the profile and the phone write. The
// country list is core's, as the address page's is: the admin API's copy of it refuses a token
// carrying authserver:manage-account alone, which is every user who is not an administrator (#563).
type accountPhoneAPI interface {
	GetAccountProfile(ctx context.Context, accessToken string) (*api.UserResponse, error)
	UpdateAccountPhone(ctx context.Context, accessToken string, request *api.UpdateAccountPhoneRequest) (*api.UserResponse, error)
}

func HandlePhoneGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient accountPhoneAPI,
) http.HandlerFunc {
	phoneCountries := phonecountries.All()

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
			"selectedPhoneCountryUniqueId": user.PhoneNumberCountryUniqueId,
			"phoneNumber":                  user.PhoneNumber,
			"phoneCountries":               phoneCountries,
			"savedSuccessfully":            savedSuccessfully,
		}

		if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_phone.html", bind); err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandlePhonePost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient accountPhoneAPI,
	baseURL string,
) http.HandlerFunc {
	phoneCountries := phonecountries.All()

	return func(w http.ResponseWriter, r *http.Request) {
		// Get access token and current data for re-rendering errors
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Build request
		req := &api.UpdateAccountPhoneRequest{
			PhoneCountryUniqueId: r.FormValue("phoneCountryUniqueId"),
			PhoneNumber:          strings.TrimSpace(r.FormValue("phoneNumber")),
		}

		// On validation error, re-render with submitted values, the refused field marked.
		renderError := func(errorMessage, errorField string) {
			bind := map[string]interface{}{
				"selectedPhoneCountryUniqueId": req.PhoneCountryUniqueId,
				"phoneNumber":                  req.PhoneNumber,
				"phoneCountries":               phoneCountries,
				"error":                        errorMessage,
				"errorField":                   errorField,
			}
			if renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_phone.html", bind); renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		// Call API
		_, err := apiClient.UpdateAccountPhone(r.Context(), jwtInfo.TokenResponse.AccessToken, req)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(errorMessage string) {
				renderError(errorMessage, render.ErrorField(err, render.PhoneErrorFields))
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

		http.Redirect(w, r, baseURL+"/account/phone", http.StatusFound)
	}
}
