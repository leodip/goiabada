package accounthandlers

import (
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAccountPhoneGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		user, err := apiClient.GetAccountProfile(jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// Fetch phone countries via existing admin API
		phoneCountries, err := apiClient.GetPhoneCountries(jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			if err := httpSession.Save(r, w, sess); err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"selectedPhoneCountryUniqueId": user.PhoneNumberCountryUniqueId,
			"phoneNumber":                  user.PhoneNumber,
			"phoneCountries":               phoneCountries,
			"savedSuccessfully":            len(savedSuccessfully) > 0,
			"csrfField":                    csrf.TemplateField(r),
		}

		if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_phone.html", bind); err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountPhonePost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get access token and current data for re-rendering errors
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Load phone countries for error rendering
		phoneCountries, err := apiClient.GetPhoneCountries(jwtInfo.TokenResponse.AccessToken)
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
				"csrfField":                    csrf.TemplateField(r),
				"error":                        errorMessage,
			}
			if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_phone.html", bind); err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// Call API
		_, err = apiClient.UpdateAccountPhone(jwtInfo.TokenResponse.AccessToken, req)
		if err != nil {
			handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		// Flash success and redirect
		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		sess.AddFlash("true", "savedSuccessfully")
		if err := httpSession.Save(r, w, sess); err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, config.GetAdminConsole().BaseURL+"/account/phone", http.StatusFound)
	}
}
