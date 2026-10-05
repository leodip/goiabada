package admingrouphandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// groupDeleteAPI is what the group delete page needs: the group it confirms, and the delete.
type groupDeleteAPI interface {
	DeleteGroup(ctx context.Context, accessToken string, groupId int64) error
	GetGroupById(ctx context.Context, accessToken string, groupId int64) (*api.GroupResponse, error)
}

func HandleDeleteGet(
	httpHelper HttpHelper,
	apiClient groupDeleteAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "groupId")
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

		group, err := apiClient.GetGroupById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if group == nil {
			httpHelper.NotFound(w, r)
			return
		}

		countOfUsers := group.MemberCount

		bind := map[string]interface{}{
			"group":        group,
			"countOfUsers": countOfUsers,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_delete.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleDeletePost(
	httpHelper HttpHelper,
	apiClient groupDeleteAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
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

		group, err := apiClient.GetGroupById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if group == nil {
			httpHelper.NotFound(w, r)
			return
		}

		countOfUsers := group.MemberCount

		renderError := func(message string) {
			bind := map[string]interface{}{
				"group":        group,
				"countOfUsers": countOfUsers,
				"error":        message,
			}

			renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_delete.html", bind)
			if renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		groupIdentifier := r.FormValue("groupIdentifier")
		if len(groupIdentifier) == 0 {
			renderError("Group identifier is required.")
			return
		}

		if group.GroupIdentifier != groupIdentifier {
			renderError("Group identifier does not match the group being deleted.")
			return
		}

		// Delete the group via API. A refusal the administrator can resolve, 409
		// LAST_ADMINISTRATOR when the group gives the last one manage, is shown on this page
		// rather than as the 500 page (#402 decision 12).
		err = apiClient.DeleteGroup(r.Context(), jwtInfo.TokenResponse.AccessToken, group.Id)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/groups", baseURL), http.StatusFound)
	}
}
