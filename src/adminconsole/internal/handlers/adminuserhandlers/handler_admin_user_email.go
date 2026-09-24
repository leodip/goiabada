package adminuserhandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/api"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
)

// userEmailAPI is what the user email page needs: the user, and the email write.
type userEmailAPI interface {
	GetUserById(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, error)
	UpdateUserEmail(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserEmailRequest) (*api.UserResponse, error)
}

func HandleAdminUserEmailGet(
	httpHelper handlers.HttpHelper,
	httpSession sessionstore.Store,
	apiClient userEmailAPI,
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
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		user, err := apiClient.GetUserById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
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
			"email":             user.Email,
			"emailVerified":     user.EmailVerified,
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_email.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserEmailPost(
	httpHelper handlers.HttpHelper,
	httpSession sessionstore.Store,
	apiClient userEmailAPI,
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
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Get user first for error handling template
		user, err := apiClient.GetUserById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Create update request
		updateReq := &api.UpdateUserEmailRequest{
			Email:         strings.ToLower(strings.TrimSpace(r.FormValue("email"))),
			EmailVerified: r.FormValue("emailVerified") == "on",
		}

		// Update user email via API
		updatedUser, err := apiClient.UpdateUserEmail(r.Context(), jwtInfo.TokenResponse.AccessToken, id, updateReq)
		if err != nil {
			// The classifier decides which failures the form can show: a 400 the API's validation
			// refused, and a 409 for an address another account took after that validation passed
			// (#425).
			handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(errorMessage string) {
				bind := map[string]interface{}{
					"user":          user,
					"email":         updateReq.Email,
					"emailVerified": updateReq.EmailVerified,
					"page":          r.URL.Query().Get("page"),
					"query":         r.URL.Query().Get("query"),
					"error":         errorMessage,
				}

				renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_email.html", bind)
				if renderErr != nil {
					httpHelper.InternalServerError(w, r, renderErr)
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

		http.Redirect(w, r, withListPosition(fmt.Sprintf("/admin/users/%v/email", updatedUser.Id), r), http.StatusFound)
	}
}
