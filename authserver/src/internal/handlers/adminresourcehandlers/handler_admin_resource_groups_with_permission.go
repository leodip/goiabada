package adminresourcehandlers

import (
	"encoding/json"
	"fmt"
	"net/http"
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
	"github.com/unknwon/paginater"
)

func HandleAdminResourceGroupsWithPermissionGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
) http.HandlerFunc {

	type groupInfo struct {
		Id              int64
		GroupIdentifier string
		Description     string
		HasPermission   bool
	}

	type pageResult struct {
		Page     int
		PageSize int
		Total    int
		Groups   []groupInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("resourceId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		resource, err := database.GetResourceById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if resource == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("resource not found")))
			return
		}

		permissions, err := database.GetPermissionsByResourceId(nil, resource.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.PermissionsLoadResources(nil, permissions)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		// filter out the userinfo permission if the resource is authserver
		filteredPermissions := []models.Permission{}
		for idx, permission := range permissions {
			if permission.Resource.ResourceIdentifier == constants.AuthServerResourceIdentifier {
				if permission.PermissionIdentifier != constants.UserinfoPermissionIdentifier {
					filteredPermissions = append(filteredPermissions, permissions[idx])
				}
			} else {
				filteredPermissions = append(filteredPermissions, permissions[idx])
			}
		}
		permissions = filteredPermissions

		selectedPermissionStr := r.URL.Query().Get("permission")
		if len(selectedPermissionStr) == 0 {
			if len(permissions) > 0 {
				selectedPermissionStr = strconv.FormatInt(permissions[0].Id, 10)
			} else {
				selectedPermissionStr = "0"
			}
		}

		var selectedPermission int64
		selectedPermission, err = strconv.ParseInt(selectedPermissionStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		selectedPermissionIdentifier := ""
		if selectedPermission > 0 {
			// check if permission belongs to resource
			var found bool
			for _, permission := range permissions {
				if permission.Id == selectedPermission {
					found = true
					selectedPermissionIdentifier = permission.PermissionIdentifier
					break
				}
			}

			if !found {
				httpHelper.InternalServerError(w, r, errors.WithStack(fmt.Errorf("permission %v does not belong to resource %v", selectedPermission, resource.Id)))
				return
			}
		}

		page := r.URL.Query().Get("page")
		if len(page) == 0 {
			page = "1"
		}
		pageInt, err := strconv.Atoi(page)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if pageInt < 1 {
			httpHelper.InternalServerError(w, r, errors.WithStack(fmt.Errorf("invalid page %d", pageInt)))
			return
		}

		const pageSize = 10
		groupsWithPermission, total, err := database.GetAllGroupsPaginated(nil, pageInt, pageSize)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.GroupsLoadPermissions(nil, groupsWithPermission)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		groupInfoArr := make([]groupInfo, len(groupsWithPermission))
		for i, group := range groupsWithPermission {
			groupInfo := groupInfo{
				Id:              group.Id,
				GroupIdentifier: group.GroupIdentifier,
				Description:     group.Description,
			}
			foundPermission := false
			for _, permission := range group.Permissions {
				if permission.Id == selectedPermission {
					foundPermission = true
					break
				}
			}
			groupInfo.HasPermission = foundPermission
			groupInfoArr[i] = groupInfo
		}

		pageResult := pageResult{
			Page:     pageInt,
			PageSize: pageSize,
			Total:    total,
			Groups:   groupInfoArr,
		}

		p := paginater.New(total, pageSize, pageInt, 5)

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
			"resourceId":                   resource.Id,
			"resourceIdentifier":           resource.ResourceIdentifier,
			"description":                  resource.Description,
			"isSystemLevelResource":        resource.IsSystemLevelResource(),
			"permissions":                  permissions,
			"selectedPermission":           selectedPermission,
			"selectedPermissionIdentifier": selectedPermissionIdentifier,
			"pageResult":                   pageResult,
			"paginator":                    p,
			"csrfField":                    csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_groups_with_permission.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminResourceGroupsWithPermissionAddPermissionPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("resourceId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		resource, err := database.GetResourceById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if resource == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("resource not found")))
			return
		}

		groupIdStr := chi.URLParam(r, "groupId")
		if len(groupIdStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("groupId is required")))
			return
		}

		groupId, err := strconv.ParseInt(groupIdStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		group, err := database.GetGroupById(nil, groupId)
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
			httpHelper.JsonError(w, r, err)
			return
		}

		permissionIdStr := chi.URLParam(r, "permissionId")
		if len(permissionIdStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("permissionId is required")))
			return
		}

		permissionId, err := strconv.ParseInt(permissionIdStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		permissions, err := database.GetPermissionsByResourceId(nil, resource.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.PermissionsLoadResources(nil, permissions)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		// filter out the userinfo permission if the resource is authserver
		filteredPermissions := []models.Permission{}
		for idx, permission := range permissions {
			if permission.Resource.ResourceIdentifier == constants.AuthServerResourceIdentifier {
				if permission.PermissionIdentifier != constants.UserinfoPermissionIdentifier {
					filteredPermissions = append(filteredPermissions, permissions[idx])
				}
			} else {
				filteredPermissions = append(filteredPermissions, permissions[idx])
			}
		}
		permissions = filteredPermissions

		found := false
		for _, permission := range permissions {
			if permission.Id == permissionId {
				found = true
				break
			}
		}

		if !found {
			httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("permission %v does not belong to resource %v", permissionId, resource.Id)))
			return
		}

		found = false
		for _, permission := range group.Permissions {
			if permission.Id == permissionId {
				found = true
				break
			}
		}

		if found {
			httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("group %v already has permission %v", group.Id, permissionId)))
			return
		}

		groupPermission := &models.GroupPermission{
			GroupId:      group.Id,
			PermissionId: permissionId,
		}

		err = database.CreateGroupPermission(nil, groupPermission)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditAddedGroupPermission, map[string]interface{}{
			"groupId":      group.Id,
			"permissionId": permissionId,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		result := struct {
			Success bool
		}{
			Success: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func HandleAdminResourceGroupsWithPermissionRemovePermissionPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("resourceId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		resource, err := database.GetResourceById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if resource == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("resource not found")))
			return
		}

		groupIdStr := chi.URLParam(r, "groupId")
		if len(groupIdStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("groupId is required")))
			return
		}

		groupId, err := strconv.ParseInt(groupIdStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		group, err := database.GetGroupById(nil, groupId)
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
			httpHelper.JsonError(w, r, err)
			return
		}

		permissionIdStr := chi.URLParam(r, "permissionId")
		if len(permissionIdStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("permissionId is required")))
			return
		}

		permissionId, err := strconv.ParseInt(permissionIdStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		permissions, err := database.GetPermissionsByResourceId(nil, resource.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.PermissionsLoadResources(nil, permissions)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		// filter out the userinfo permission if the resource is authserver
		filteredPermissions := []models.Permission{}
		for idx, permission := range permissions {
			if permission.Resource.ResourceIdentifier == constants.AuthServerResourceIdentifier {
				if permission.PermissionIdentifier != constants.UserinfoPermissionIdentifier {
					filteredPermissions = append(filteredPermissions, permissions[idx])
				}
			} else {
				filteredPermissions = append(filteredPermissions, permissions[idx])
			}
		}
		permissions = filteredPermissions

		found := false
		for _, permission := range permissions {
			if permission.Id == permissionId {
				found = true
				break
			}
		}

		if !found {
			httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("permission %v does not belong to resource %v", permissionId, resource.Id)))
			return
		}

		found = false
		for _, permission := range group.Permissions {
			if permission.Id == permissionId {
				found = true
				break
			}
		}

		if !found {
			httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("group %v does not have permission %v", group.Id, permissionId)))
			return
		}

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

		result := struct {
			Success bool
		}{
			Success: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
