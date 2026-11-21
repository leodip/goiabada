package admingrouphandlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
)

// groupMembersRemoveAPI is what the remove member endpoint needs: the one write it makes.
type groupMembersRemoveAPI interface {
	RemoveUserFromGroup(ctx context.Context, accessToken string, groupID int64, userID int64) error
}

func HandleMembersRemoveUserPost(
	httpHelper HTTPHelper,
	apiClient groupMembersRemoveAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("groupId")
		if len(idStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		userIDStr := r.PathValue("userId")
		if len(userIDStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		userID, err := strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JWTInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJWTInfo)
			return
		}

		err = apiClient.RemoveUserFromGroup(r.Context(), jwtInfo.TokenResponse.AccessToken, id, userID)
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
