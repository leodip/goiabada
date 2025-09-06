package adminuserhandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminUserPhoneGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Get user via API
		user, err := apiClient.GetUserById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handleAPIError(httpHelper, w, r, err)
			return
		}

		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		// Get phone countries via API (with caching)
		phoneCountries, err := getPhoneCountriesWithCache(apiClient, jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handleAPIError(httpHelper, w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"user":                         user,
			"phoneCountries":               phoneCountries,
			"selectedPhoneCountryUniqueId": user.PhoneNumberCountryUniqueId,
			"phoneNumber":                  user.PhoneNumber,
			"phoneNumberVerified":          user.PhoneNumberVerified,
			"page":                         r.URL.Query().Get("page"),
			"query":                        r.URL.Query().Get("query"),
			"savedSuccessfully":            len(savedSuccessfully) > 0,
			"csrfField":                    csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_phone.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserPhonePost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Get phone countries for rendering errors (if needed) - with caching
		phoneCountries, err := getPhoneCountriesWithCache(apiClient, jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handleAPIError(httpHelper, w, r, err)
			return
		}

		// Parse form input
		phoneCountryUniqueId := r.FormValue("phoneCountryUniqueId")
		phoneNumber := strings.TrimSpace(r.FormValue("phoneNumber"))
		phoneNumberVerified := r.FormValue("phoneNumberVerified") == "on"

		// Create request
		updateReq := &api.UpdateUserPhoneRequest{
			PhoneCountryUniqueId: phoneCountryUniqueId,
			PhoneNumber:          phoneNumber,
			PhoneNumberVerified:  phoneNumberVerified,
		}

		// Render error function for form validation errors
		renderError := func(errorMessage string) {
			bind := map[string]interface{}{
				"selectedPhoneCountryUniqueId": phoneCountryUniqueId,
				"phoneNumber":                  phoneNumber,
				"phoneNumberVerified":          phoneNumberVerified,
				"phoneCountries":               phoneCountries,
				"page":                         r.URL.Query().Get("page"),
				"query":                        r.URL.Query().Get("query"),
				"csrfField":                    csrf.TemplateField(r),
				"error":                        errorMessage,
			}

			err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_phone.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// Update user phone via API
		_, err = apiClient.UpdateUserPhone(jwtInfo.TokenResponse.AccessToken, id, updateReq)
		if err != nil {
			handleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/phone?page=%v&query=%v", config.GetAdminConsole().BaseURL, id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}