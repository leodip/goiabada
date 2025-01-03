package admingrouphandlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

func HandleAdminGroupMembersAddGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
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
		group, err := database.GetGroupById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
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
	database data.Database,
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
		group, err := database.GetGroupById(nil, id)
		if err != nil {
			httpHelper.JsonError(w, r, err)
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

		users, _, err := database.SearchUsersPaginated(nil, query, 1, 15)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		err = database.UsersLoadGroups(nil, users)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		usersResult := make([]UserResult, 0)
		for _, user := range users {

			userInGroup := false
			for _, userGroup := range user.Groups {
				if userGroup.Id == group.Id {
					userInGroup = true
					break
				}
			}

			usersResult = append(usersResult, UserResult{
				Id:           user.Id,
				Subject:      user.Subject.String(),
				Username:     user.Username,
				Email:        user.Email,
				GivenName:    user.GivenName,
				MiddleName:   user.MiddleName,
				FamilyName:   user.FamilyName,
				AddedToGroup: userInGroup,
			})
		}

		result.Users = usersResult
		httpHelper.EncodeJson(w, r, result)
	}
}

func HandleAdminGroupMembersAddPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
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
		group, err := database.GetGroupById(nil, id)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}
		if group == nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("group not found")))
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

		user, err := database.GetUserById(nil, userId)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		err = database.CreateUserGroup(nil, &models.UserGroup{
			UserId:  user.Id,
			GroupId: group.Id,
		})
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditUserAddedToGroup, map[string]interface{}{
			"userId":       user.Id,
			"groupId":      group.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJson(w, r, result)
	}
}
