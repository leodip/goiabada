package admingrouphandlers

import (
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/audit"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/data"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
)

func HandleAdminGroupMembersRemoveUserPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
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

		userIdStr := chi.URLParam(r, "userId")
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

		userGroup, err := database.GetUserGroupByUserIdAndGroupId(nil, user.Id, group.Id)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		if userGroup == nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("user not in group")))
			return
		}

		err = database.DeleteUserGroup(nil, userGroup.Id)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		audit.Log(constants.AuditUserRemovedFromGroup, map[string]interface{}{
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
