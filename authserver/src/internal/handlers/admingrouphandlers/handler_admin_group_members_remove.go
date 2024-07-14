package admingrouphandlers

import (
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/lib"
)

func HandleAdminGroupMembersRemoveUserPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("groupId is required")), http.StatusInternalServerError)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err, http.StatusInternalServerError)
			return
		}
		group, err := database.GetGroupById(nil, id)
		if err != nil {
			httpHelper.JsonError(w, r, err, http.StatusInternalServerError)
			return
		}
		if group == nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("group not found")), http.StatusInternalServerError)
			return
		}

		userIdStr := chi.URLParam(r, "userId")
		if len(userIdStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("userId is required")), http.StatusInternalServerError)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err, http.StatusInternalServerError)
			return
		}

		user, err := database.GetUserById(nil, userId)
		if err != nil {
			httpHelper.JsonError(w, r, err, http.StatusInternalServerError)
			return
		}

		if user == nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("user not found")), http.StatusInternalServerError)
			return
		}

		userGroup, err := database.GetUserGroupByUserIdAndGroupId(nil, user.Id, group.Id)
		if err != nil {
			httpHelper.JsonError(w, r, err, http.StatusInternalServerError)
			return
		}

		if userGroup == nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("user not in group")), http.StatusInternalServerError)
			return
		}

		err = database.DeleteUserGroup(nil, userGroup.Id)
		if err != nil {
			httpHelper.JsonError(w, r, err, http.StatusInternalServerError)
			return
		}

		lib.LogAudit(constants.AuditUserRemovedFromGroup, map[string]interface{}{
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
