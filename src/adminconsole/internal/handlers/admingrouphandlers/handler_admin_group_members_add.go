package admingrouphandlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// groupMembersAddAPI is what the add member page needs: the group, the annotated user search, and
// the add.
type groupMembersAddAPI interface {
	AddUserToGroup(ctx context.Context, accessToken string, groupId int64, userId int64) error
	GetGroupById(ctx context.Context, accessToken string, groupId int64) (*api.GroupResponse, error)
	SearchUsersWithGroupAnnotation(ctx context.Context, accessToken, query string, groupId int64, page, size int) ([]api.UserWithGroupMembershipResponse, int, error)
}

func HandleMembersAddGet(
	httpHelper HttpHelper,
	apiClient groupMembersAddAPI,
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

		bind := map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"description":     group.Description,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_members_add.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleMembersSearchGet(
	httpHelper HttpHelper,
	apiClient groupMembersAddAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		result := SearchResult{}

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

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		group, err := apiClient.GetGroupById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}
		if group == nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		query := strings.TrimSpace(r.URL.Query().Get("query"))
		if len(query) == 0 {
			httpHelper.EncodeJSON(w, r, result)
			return
		}

		users, _, err := apiClient.SearchUsersWithGroupAnnotation(r.Context(), jwtInfo.TokenResponse.AccessToken, query, group.Id, 1, 15)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		usersResult := make([]UserResult, 0)
		for _, user := range users {
			usersResult = append(usersResult, UserResult{
				Id:           user.Id,
				Subject:      user.Subject,
				Username:     user.Username,
				Email:        user.Email,
				GivenName:    user.GivenName,
				MiddleName:   user.MiddleName,
				FamilyName:   user.FamilyName,
				AddedToGroup: user.InGroup,
			})
		}

		result.Users = usersResult
		httpHelper.EncodeJSON(w, r, result)
	}
}

func HandleMembersAddPost(
	httpHelper HttpHelper,
	apiClient groupMembersAddAPI,
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

		userIdStr := r.URL.Query().Get("userId")
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

		err = apiClient.AddUserToGroup(r.Context(), jwtInfo.TokenResponse.AccessToken, id, userId)
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
