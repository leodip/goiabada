package admingrouphandlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminGroupMembersRemoveUserPost(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		userIdStr := chi.URLParam(r, "userId")
		if len(userIdStr) == 0 {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}

		err = apiClient.RemoveUserFromGroup(jwtInfo.TokenResponse.AccessToken, id, userId)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJson(w, r, result)
	}
}
