package adminuserhandlers

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
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

func HandleAdminUserPermissionsGet(
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

		err = database.UserLoadPermissions(nil, user)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		userPermissions := make(map[int64]string)

		for _, permission := range user.Permissions {

			res, err := database.GetResourceById(nil, permission.ResourceId)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			userPermissions[permission.Id] = res.ResourceIdentifier + ":" + permission.PermissionIdentifier
		}

		resources, err := database.GetAllResources(nil)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sort.Slice(resources, func(i, j int) bool {
			return resources[i].ResourceIdentifier < resources[j].ResourceIdentifier
		})

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
			"userPermissions":   userPermissions,
			"resources":         resources,
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_permissions.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserPermissionsPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	type permissionsPostInput struct {
		AssignedPermissionsIds []int64 `json:"assignedPermissionsIds"`
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

		err = database.UserLoadPermissions(nil, user)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		var data permissionsPostInput
		err = json.Unmarshal(body, &data)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		for _, permissionId := range data.AssignedPermissionsIds {

			found := false
			for _, permission := range user.Permissions {
				if permission.Id == permissionId {
					found = true
					break
				}
			}

			if !found {
				permission, err := database.GetPermissionById(nil, permissionId)
				if err != nil {
					httpHelper.JsonError(w, r, err)
					return
				}
				if permission == nil {
					httpHelper.JsonError(w, r, errors.WithStack(errors.New("permission not found")))
					return
				}

				err = database.CreateUserPermission(nil, &models.UserPermission{
					UserId:       user.Id,
					PermissionId: permission.Id,
				})
				if err != nil {
					httpHelper.JsonError(w, r, err)
					return
				}

				auditLogger.Log(constants.AuditAddedUserPermission, map[string]interface{}{
					"userId":       user.Id,
					"permissionId": permission.Id,
					"loggedInUser": authHelper.GetLoggedInSubject(r),
				})
			}
		}

		toDelete := []int64{}
		for _, permission := range user.Permissions {
			found := false
			for _, permissionId := range data.AssignedPermissionsIds {
				if permission.Id == permissionId {
					found = true
					break
				}
			}

			if !found {
				toDelete = append(toDelete, permission.Id)
			}
		}

		for _, permissionId := range toDelete {

			userPermission, err := database.GetUserPermissionByUserIdAndPermissionId(nil, user.Id, permissionId)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}

			err = database.DeleteUserPermission(nil, userPermission.Id)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}

			auditLogger.Log(constants.AuditDeletedUserPermission, map[string]interface{}{
				"userId":       user.Id,
				"permissionId": permissionId,
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
