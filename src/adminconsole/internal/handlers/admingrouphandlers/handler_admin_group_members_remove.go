package admingrouphandlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
)

// groupMembersRemoveAPI is what the remove member endpoint needs: the one write it makes.
type groupMembersRemoveAPI interface {
	RemoveUserFromGroup(ctx context.Context, accessToken string, groupId int64, userId int64) error
}

func HandleMembersRemoveUserPost(
	httpHelper HttpHelper,
	apiClient groupMembersRemoveAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		userIdStr := chi.URLParam(r, "userId")
		if len(userIdStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		err = apiClient.RemoveUserFromGroup(r.Context(), jwtInfo.TokenResponse.AccessToken, id, userId)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJSON(w, r, result)
	}
}
