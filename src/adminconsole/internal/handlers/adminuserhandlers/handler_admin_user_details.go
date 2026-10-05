package adminuserhandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// userDetailsAPI is what the user details page needs: the user, and the enabled write.
type userDetailsAPI interface {
	GetUserById(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, error)
	UpdateUserEnabled(ctx context.Context, accessToken string, userId int64, enabled bool) (*api.UserResponse, error)
}

func HandleDetailsGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient userDetailsAPI,
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

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		_, savedSuccessfully := sess.TakeFlash("savedSuccessfully")
		_, userCreated := sess.TakeFlash("userCreated")
		if savedSuccessfully || userCreated {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"user":              user,
			"userFullName":      render.UserFullName(user),
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": savedSuccessfully,
			"userCreated":       userCreated,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_details.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleDetailsPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient userDetailsAPI,
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

		// A refusal the administrator can resolve, 409 LAST_ADMINISTRATOR when disabling the last
		// user holding manage, is shown on the details page again, with the user as stored, rather
		// than as the 500 page (#402 decision 12).
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

			bind := map[string]interface{}{
				"user":         user,
				"userFullName": render.UserFullName(user),
				"page":         r.URL.Query().Get("page"),
				"query":        r.URL.Query().Get("query"),
				"error":        message,
			}
			if renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_details.html", bind); renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		enabled := r.FormValue("enabled") == "on"
		_, err = apiClient.UpdateUserEnabled(r.Context(), jwtInfo.TokenResponse.AccessToken, id, enabled)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

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

		http.Redirect(w, r, withListPosition(baseURL, fmt.Sprintf("/admin/users/%v/details", id), r), http.StatusFound)
	}
}
