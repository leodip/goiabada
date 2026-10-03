package adminuserhandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/handlerhelpers"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/locales"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/timezones"
)

// userProfileAPI is what the user profile page needs: the user, and the profile write.
type userProfileAPI interface {
	GetUserById(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, error)
	UpdateUserProfile(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserProfileRequest) (*api.UserResponse, error)
}

func HandleAdminUserProfileGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient userProfileAPI,
) http.HandlerFunc {

	timezones := timezones.All()
	locales := locales.All()

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
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
			handlerhelpers.HandleAPIError(httpHelper, w, r, err)
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

func HandleAdminUserProfilePost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient userProfileAPI,
	baseURL string,
) http.HandlerFunc {

	timezones := timezones.All()
	locales := locales.All()

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
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

		request, err := handlerhelpers.ParseProfileForm(r)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Call the profile update API
		user, err := apiClient.UpdateUserProfile(r.Context(), jwtInfo.TokenResponse.AccessToken, id, request)
		if err != nil {
			// Handle validation errors by showing them in the form
			handlerhelpers.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(errorMessage string) {
				// Get formUser data for form display
				formUser, userErr := apiClient.GetUserById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
				if userErr != nil {
					handlerhelpers.HandleAPIError(httpHelper, w, r, userErr)
					return
				}

				// Update user fields with form values for display
				handlerhelpers.EchoProfileForm(formUser, request)

				bind := map[string]interface{}{
					"user":      formUser,
					"timezones": timezones,
					"locales":   locales,
					"page":      r.URL.Query().Get("page"),
					"query":     r.URL.Query().Get("query"),
					"error":     errorMessage,
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
