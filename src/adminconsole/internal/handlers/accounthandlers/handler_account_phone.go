package accounthandlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/api"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
)

// accountPhoneAPI is what the account phone page needs: the profile, the country list, and the
// phone write.
type accountPhoneAPI interface {
	GetAccountProfile(ctx context.Context, accessToken string) (*api.UserResponse, error)
	GetPhoneCountries(ctx context.Context, accessToken string) ([]api.PhoneCountryResponse, error)
	UpdateAccountPhone(ctx context.Context, accessToken string, request *api.UpdateAccountPhoneRequest) (*api.UserResponse, error)
}

func HandleAccountPhoneGet(
	httpHelper handlers.HttpHelper,
	httpSession sessionstore.Store,
	apiClient accountPhoneAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		user, err := apiClient.GetAccountProfile(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// Fetch phone countries via existing admin API
		phoneCountries, err := apiClient.GetPhoneCountries(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		sess, err := httpSession.Get(r, coreconstants.AdminConsoleSessionName)
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

func HandleAccountPhonePost(
	httpHelper handlers.HttpHelper,
	httpSession sessionstore.Store,
	apiClient accountPhoneAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get access token and current data for re-rendering errors
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Load phone countries for error rendering
		phoneCountries, err := apiClient.GetPhoneCountries(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// Build request
		req := &api.UpdateAccountPhoneRequest{
			PhoneCountryUniqueId: r.FormValue("phoneCountryUniqueId"),
			PhoneNumber:          strings.TrimSpace(r.FormValue("phoneNumber")),
		}

		// On validation error, re-render with submitted values
		renderError := func(errorMessage string) {
			bind := map[string]interface{}{
				"selectedPhoneCountryUniqueId": req.PhoneCountryUniqueId,
				"phoneNumber":                  req.PhoneNumber,
				"phoneCountries":               phoneCountries,
				"error":                        errorMessage,
			}
			if renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_phone.html", bind); renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		// Call API
		_, err = apiClient.UpdateAccountPhone(r.Context(), jwtInfo.TokenResponse.AccessToken, req)
		if err != nil {
			handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		// Flash success and redirect
		sess, err := httpSession.Get(r, coreconstants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		sess.SetFlash("savedSuccessfully", "true")
		if err := httpSession.Save(r, w, sess); err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, config.GetAdminConsole().BaseURL+"/account/phone", http.StatusFound)
	}
}
