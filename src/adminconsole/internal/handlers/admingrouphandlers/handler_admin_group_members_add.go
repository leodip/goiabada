package admingrouphandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminGroupMembersAddGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("groupId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		group, _, err := apiClient.GetGroupById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if group == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		bind := map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"description":     group.Description,
			"csrfField":       csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_members_add.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminGroupMembersSearchGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		result := SearchResult{}

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("groupId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		group, _, err := apiClient.GetGroupById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			if apiErr, ok := err.(*apiclient.APIError); ok {
				httpHelper.JsonError(w, r, fmt.Errorf("%s", apiErr.Message))
			} else {
				httpHelper.JsonError(w, r, err)
			}
			return
		}
		if group == nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		query := strings.TrimSpace(r.URL.Query().Get("query"))
		if len(query) == 0 {
			httpHelper.EncodeJson(w, r, result)
			return
		}

		users, _, err := apiClient.SearchUsersWithGroupAnnotation(jwtInfo.TokenResponse.AccessToken, query, group.Id, 1, 15)
		if err != nil {
			if apiErr, ok := err.(*apiclient.APIError); ok {
				httpHelper.JsonError(w, r, fmt.Errorf("%s", apiErr.Message))
			} else {
				httpHelper.JsonError(w, r, err)
			}
			return
		}

		usersResult := make([]UserResult, 0)
		for _, user := range users {
			usersResult = append(usersResult, UserResult{
				Id:           user.Id,
				Subject:      user.Subject.String(),
				Username:     user.Username,
				Email:        user.Email,
				GivenName:    user.GivenName,
				MiddleName:   user.MiddleName,
				FamilyName:   user.FamilyName,
				AddedToGroup: user.InGroup,
			})
		}

		result.Users = usersResult
		httpHelper.EncodeJson(w, r, result)
	}
}

func HandleAdminGroupMembersAddPost(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("groupId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		userIdStr := r.URL.Query().Get("userId")
		if len(userIdStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		err = apiClient.AddUserToGroup(jwtInfo.TokenResponse.AccessToken, id, userId)
		if err != nil {
			if apiErr, ok := err.(*apiclient.APIError); ok {
				httpHelper.JsonError(w, r, fmt.Errorf("%s", apiErr.Message))
			} else {
				httpHelper.JsonError(w, r, err)
			}
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
