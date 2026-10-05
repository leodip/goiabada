package adminuserhandlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// userDeleteAPI is what the user delete page needs: the user, the groups it warns about, and the
// delete.
type userDeleteAPI interface {
	DeleteUser(ctx context.Context, accessToken string, userId int64) error
	GetUserById(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, error)
	GetUserGroups(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, []api.GroupResponse, error)
}

func HandleDeleteGet(
	httpHelper HttpHelper,
	apiClient userDeleteAPI,
) http.HandlerFunc {

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
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// The memberships are loaded rather than read off the user, because GET
		// /api/v1/admin/users/{id} serves none: the page listed "none" for every user,
		// whatever their real membership, and this is a confirmation screen for a
		// destructive action, so under-reporting what it discards is the whole defect (#350).
		_, groups, err := apiClient.GetUserGroups(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"user":         user,
			"userFullName": render.UserFullName(user),
			"groups":       groups,
			"page":         r.URL.Query().Get("page"),
			"query":        r.URL.Query().Get("query"),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_delete.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleDeletePost(
	httpHelper HttpHelper,
	apiClient userDeleteAPI,
	baseURL string,
) http.HandlerFunc {

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

		// A refusal the administrator can resolve, 409 LAST_ADMINISTRATOR when the user is the last
		// one holding manage, is shown on the confirmation page again rather than as the 500 page
		// (#402 decision 12).
		renderError := func(message string) {
			user, getErr := apiClient.GetUserById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
			if getErr != nil {
				render.HandleAPIError(httpHelper, w, r, getErr)
				return
			}
			if user == nil {
				httpHelper.NotFound(w, r)
				return
			}
			_, groups, getErr := apiClient.GetUserGroups(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
			if getErr != nil {
				render.HandleAPIError(httpHelper, w, r, getErr)
				return
			}

			bind := map[string]interface{}{
				"user":         user,
				"userFullName": render.UserFullName(user),
				"groups":       groups,
				"page":         r.URL.Query().Get("page"),
				"query":        r.URL.Query().Get("query"),
				"error":        message,
			}
			if renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_delete.html", bind); renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		err = apiClient.DeleteUser(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		http.Redirect(w, r, withListPosition(baseURL, "/admin/users/", r), http.StatusFound)
	}
}
