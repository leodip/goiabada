package admingrouphandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// groupDeleteAPI is what the group delete page needs: the group it confirms, and the delete.
type groupDeleteAPI interface {
	DeleteGroup(ctx context.Context, accessToken string, groupId int64) error
	GetGroupById(ctx context.Context, accessToken string, groupId int64) (*api.GroupResponse, error)
}

func HandleAdminGroupDeleteGet(
	httpHelper handlers.HttpHelper,
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
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		group, err := apiClient.GetGroupById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
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

func HandleAdminGroupDeletePost(
	httpHelper handlers.HttpHelper,
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
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		group, err := apiClient.GetGroupById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
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

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_delete.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
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

		// Delete the group via API
		err = apiClient.DeleteGroup(r.Context(), jwtInfo.TokenResponse.AccessToken, group.Id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/groups", config.GetAdminConsole().BaseURL), http.StatusFound)
	}
}
