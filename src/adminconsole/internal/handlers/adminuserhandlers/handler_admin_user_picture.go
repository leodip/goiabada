package adminuserhandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// userPictureAPI is what the user picture endpoint needs: the user, and the picture it serves.
type userPictureAPI interface {
	GetUserById(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, error)
	GetUserProfilePicture(ctx context.Context, accessToken string, userId int64) (*apiclient.ProfilePictureInfo, error)
}

func HandleAdminUserPictureGet(
	httpHelper handlers.HttpHelper,
	apiClient userPictureAPI,
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

		// Get profile picture info
		var profilePictureUrl string
		pictureInfo, err := apiClient.GetUserProfilePicture(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err == nil && pictureInfo != nil && pictureInfo.HasPicture {
			// Add cache-busting parameter to prevent browser caching
			profilePictureUrl = fmt.Sprintf("%s?t=%d", pictureInfo.PictureUrl, time.Now().UnixNano())
		}

		bind := map[string]interface{}{
			"user":              user,
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"profilePictureUrl": profilePictureUrl,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_picture.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
