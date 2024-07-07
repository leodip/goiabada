package admingrouphandlers

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
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
)

func HandleAdminGroupPermissionsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
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

		err = database.GroupLoadPermissions(nil, group)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		groupPermissions := struct {
			GroupId         int64
			GroupIdentifier string
			Permissions     map[int64]string
		}{
			GroupId:         group.Id,
			GroupIdentifier: group.GroupIdentifier,
			Permissions:     make(map[int64]string),
		}

		for _, permission := range group.Permissions {

			res, err := database.GetResourceById(nil, permission.ResourceId)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			groupPermissions.Permissions[permission.Id] = res.ResourceIdentifier + ":" + permission.PermissionIdentifier
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
			err = sess.Save(r, w)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"group":             groupPermissions,
			"resources":         resources,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_permissions.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminGroupPermissionsPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {

	type permissionsPostInput struct {
		GroupId                int64   `json:"groupId"`
		AssignedPermissionsIds []int64 `json:"assignedPermissionsIds"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

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

		group, err := database.GetGroupById(nil, data.GroupId)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		if group == nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		err = database.GroupLoadPermissions(nil, group)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		for _, permissionId := range data.AssignedPermissionsIds {

			found := false
			for _, permission := range group.Permissions {
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

				err = database.CreateGroupPermission(nil, &models.GroupPermission{
					GroupId:      group.Id,
					PermissionId: permission.Id,
				})
				if err != nil {
					httpHelper.JsonError(w, r, err)
					return
				}

				lib.LogAudit(constants.AuditAddedGroupPermission, map[string]interface{}{
					"groupId":      group.Id,
					"permissionId": permission.Id,
					"loggedInUser": authHelper.GetLoggedInSubject(r),
				})
			}
		}

		toDelete := []int64{}
		for _, permission := range group.Permissions {
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

			groupPermission, err := database.GetGroupPermissionByGroupIdAndPermissionId(nil, group.Id, permissionId)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}

			err = database.DeleteGroupPermission(nil, groupPermission.Id)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}

			lib.LogAudit(constants.AuditDeletedGroupPermission, map[string]interface{}{
				"groupId":      group.Id,
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
		err = sess.Save(r, w)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		result := struct {
			Success bool
		}{
			Success: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
