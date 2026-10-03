package adminuserhandlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// userGroupsAPI is what the user groups page needs: the groups to choose from, and the user's own
// set.
type userGroupsAPI interface {
	GetAllGroups(ctx context.Context, accessToken string) ([]api.GroupResponse, error)
	GetUserGroups(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, []api.GroupResponse, error)
	UpdateUserGroups(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserGroupsRequest) (*api.UserResponse, []api.GroupResponse, error)
}

func HandleGroupsGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient userGroupsAPI,
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

		// Get user and their groups
		user, userGroups, err := apiClient.GetUserGroups(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// Convert groups to map for template
		userGroupsMap := make(map[int64]string)
		for _, grp := range userGroups {
			userGroupsMap[grp.Id] = grp.GroupIdentifier
		}

		// Get all available groups
		allGroups, err := apiClient.GetAllGroups(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
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
			"userGroups":        userGroupsMap,
			"allGroups":         allGroups,
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_groups.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleGroupsPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient userGroupsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
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

		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		var data GroupsPostInput
		err = json.Unmarshal(body, &data)
		if err != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		// Create API request for updating user groups
		request := &api.UpdateUserGroupsRequest{
			GroupIds:         data.AssignedGroupsIds,
			ExpectedGroupIds: data.ExpectedGroupIds,
		}

		// Call API to update user groups (this handles all the business logic including audit logging)
		_, _, err = apiClient.UpdateUserGroups(r.Context(), jwtInfo.TokenResponse.AccessToken, id, request)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.JSONError(w, r, err)
			return
		}

		sess.SetFlash("savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.JSONError(w, r, err)
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
