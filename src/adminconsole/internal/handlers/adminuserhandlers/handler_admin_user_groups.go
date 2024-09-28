package adminuserhandlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

func HandleAdminUserGroupsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		user, err := database.GetUserById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		err = database.UserLoadGroups(nil, user)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		userGroups := make(map[int64]string)
		for _, grp := range user.Groups {
			userGroups[grp.Id] = grp.GroupIdentifier
		}

		allGroups, err := database.GetAllGroups(nil)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"user":              user,
			"userGroups":        userGroups,
			"allGroups":         allGroups,
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_groups.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserGroupsPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	type groupsPostInput struct {
		AssignedGroupsIds []int64 `json:"assignedGroupsIds"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}
		user, err := database.GetUserById(nil, id)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		var data groupsPostInput
		err = json.Unmarshal(body, &data)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		err = database.UserLoadGroups(nil, user)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		for _, groupId := range data.AssignedGroupsIds {

			found := false
			for _, grp := range user.Groups {
				if grp.Id == groupId {
					found = true
					break
				}
			}

			if !found {
				group, err := database.GetGroupById(nil, groupId)
				if err != nil {
					httpHelper.JsonError(w, r, err)
					return
				}
				if group == nil {
					httpHelper.JsonError(w, r, errors.WithStack(errors.New("group not found")))
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
			}
		}

		toDelete := []int64{}
		for _, grp := range user.Groups {
			found := false
			for _, grpId := range data.AssignedGroupsIds {
				if grp.Id == grpId {
					found = true
					break
				}
			}

			if !found {
				toDelete = append(toDelete, grp.Id)
			}
		}

		for _, grpId := range toDelete {

			group, err := database.GetGroupById(nil, grpId)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}

			userGroup, err := database.GetUserGroupByUserIdAndGroupId(nil, user.Id, group.Id)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}

			err = database.DeleteUserGroup(nil, userGroup.Id)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}

			auditLogger.Log(constants.AuditUserRemovedFromGroup, map[string]interface{}{
				"userId":       user.Id,
				"groupId":      group.Id,
				"loggedInUser": authHelper.GetLoggedInSubject(r),
			})
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.JsonError(w, r, err)
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
