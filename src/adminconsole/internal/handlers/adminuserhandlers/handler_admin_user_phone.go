package adminuserhandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/phonecountries"
	"github.com/leodip/goiabada/core/sessionstore"
)

// userPhoneAPI is what the user phone page needs: the user and the phone write. The country list
// it renders the form from is core's, as the account phone page's is (#563).
type userPhoneAPI interface {
	GetUserByID(ctx context.Context, accessToken string, userID int64) (*api.UserResponse, error)
	UpdateUserPhone(ctx context.Context, accessToken string, userID int64, request *api.UpdateUserPhoneRequest) (*api.UserResponse, error)
}

func HandlePhoneGet(
	httpHelper HTTPHelper,
	httpSession sessionstore.Store,
	apiClient userPhoneAPI,
) http.HandlerFunc {
	phoneCountries := phonecountries.All()

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("userId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JWTInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJWTInfo)
			return
		}

		// Get user via API
		user, err := apiClient.GetUserByID(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		_, savedSuccessfully := sess.TakeFlash(r.URL.Path, "savedSuccessfully")
		if savedSuccessfully {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"user":                         user,
			"phoneCountries":               phoneCountries,
			"selectedPhoneCountryUniqueId": user.PhoneNumberCountryUniqueID,
			"phoneNumber":                  user.PhoneNumber,
			"phoneNumberVerified":          user.PhoneNumberVerified,
			"page":                         r.URL.Query().Get("page"),
			"query":                        r.URL.Query().Get("query"),
			"savedSuccessfully":            savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_phone.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandlePhonePost(
	httpHelper HTTPHelper,
	httpSession sessionstore.Store,
	apiClient userPhoneAPI,
	baseURL string,
) http.HandlerFunc {
	phoneCountries := phonecountries.All()

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("userId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JWTInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJWTInfo)
			return
		}

		// The user a refused save draws the page with: its title and its tabs name the stored user.
		user, err := apiClient.GetUserByID(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Parse form input
		phoneCountryUniqueID := r.FormValue("phoneCountryUniqueId")
		phoneNumber := strings.TrimSpace(r.FormValue("phoneNumber"))
		phoneNumberVerified := r.FormValue("phoneNumberVerified") == "on"

		// Create request
		updateReq := &api.UpdateUserPhoneRequest{
			PhoneCountryUniqueID: phoneCountryUniqueID,
			PhoneNumber:          phoneNumber,
			PhoneNumberVerified:  phoneNumberVerified,
		}

		// Render error function for form validation errors
		renderError := func(errorMessage, errorField string) {
			bind := map[string]interface{}{
				"user":                         user,
				"selectedPhoneCountryUniqueId": phoneCountryUniqueID,
				"phoneNumber":                  phoneNumber,
				"phoneNumberVerified":          phoneNumberVerified,
				"phoneCountries":               phoneCountries,
				"page":                         r.URL.Query().Get("page"),
				"query":                        r.URL.Query().Get("query"),
				"error":                        errorMessage,
				"errorField":                   errorField,
			}

			err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_phone.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// Update user phone via API
		_, err = apiClient.UpdateUserPhone(r.Context(), jwtInfo.TokenResponse.AccessToken, id, updateReq)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderError(message, render.ErrorField(err, render.PhoneErrorFields))
			})
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		pagePath := fmt.Sprintf("/admin/users/%v/phone", id)
		sess.SetFlash(pagePath, "savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, withListPosition(baseURL, pagePath, r), http.StatusFound)
	}
}
