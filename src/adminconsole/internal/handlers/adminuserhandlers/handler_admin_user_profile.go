package adminuserhandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/locales"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/timezones"
)

// userProfileAPI is what the user profile page needs: the user, and the profile write.
type userProfileAPI interface {
	GetUserById(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, error)
	UpdateUserProfile(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserProfileRequest) (*api.UserResponse, error)
}

func HandleProfileGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient userProfileAPI,
) http.HandlerFunc {

	timezones := timezones.All()
	locales := locales.All()

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
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		user, err := apiClient.GetUserById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
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
			"pageLanguages":     render.PageLanguageOptions(),
			"pageLanguage":      render.SelectedPageLanguage(user.PageLanguage),
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_profile.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleProfilePost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient userProfileAPI,
	baseURL string,
) http.HandlerFunc {

	timezones := timezones.All()
	locales := locales.All()

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
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		request, err := render.ParseProfileForm(r)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Call the profile update API
		user, err := apiClient.UpdateUserProfile(r.Context(), jwtInfo.TokenResponse.AccessToken, id, request)
		if err != nil {
			// Handle validation errors by showing them in the form
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(errorMessage string) {
				// Get formUser data for form display
				formUser, userErr := apiClient.GetUserById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
				if userErr != nil {
					render.HandleAPIError(httpHelper, w, r, userErr)
					return
				}

				// Update user fields with form values for display
				render.EchoProfileForm(formUser, request)

				bind := map[string]interface{}{
					"user":                 formUser,
					"submittedDateOfBirth": render.SubmittedDateOfBirth(r),
					"timezones":            timezones,
					"locales":              locales,
					"pageLanguages":        render.PageLanguageOptions(),
					"pageLanguage":         render.SelectedPageLanguage(formUser.PageLanguage),
					"page":                 r.URL.Query().Get("page"),
					"query":                r.URL.Query().Get("query"),
					"error":                errorMessage,
					"errorField":           render.ErrorField(err, render.ProfileErrorFields),
				}

				err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_profile.html", bind)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
			})
			return
		}

		// Set success flash message
		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.SetFlash("savedSuccessfully", "true")
		// An administrator who saved their own profile sees the page language the API stored on the
		// next page, as a save in Account > Profile does; an edit of another user leaves the console's
		// copy alone (#631 decision 7).
		if signedInSubject(jwtInfo.IdToken) == user.Subject && user.Subject != "" {
			sess.Values[sessionkeys.PageLanguage] = user.PageLanguage
		}
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Redirect to the profile page
		//nolint:gosec // G710: the configured base URL, a fixed path around the user's numeric id, and an encoded query
		http.Redirect(w, r, withListPosition(baseURL, fmt.Sprintf("/admin/users/%v/profile", user.Id), r), http.StatusFound)
	}
}

// signedInSubject is the subject of the console's verified ID token, the signed-in user, or empty
// when the session holds no ID token.
func signedInSubject(idToken *oauth.JwtToken) string {
	if idToken == nil {
		return ""
	}
	return idToken.StringClaim("sub")
}
