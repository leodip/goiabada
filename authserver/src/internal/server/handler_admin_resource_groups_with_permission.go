package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/unknwon/paginater"
)

func (s *Server) handleAdminResourceGroupsWithPermissionGet() http.HandlerFunc {

	type groupInfo struct {
		Id              uint
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
			s.internalServerError(w, r, errors.New("resourceId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		resource, err := s.database.GetResourceById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if resource == nil {
			s.internalServerError(w, r, errors.New("resource not found"))
			return
		}

		permissions, err := s.database.GetPermissionsByResourceId(resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		// filter out the userinfo permission if the resource is authserver
		filteredPermissions := []entities.Permission{}
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
				selectedPermissionStr = strconv.FormatUint(uint64(permissions[0].Id), 10)
			} else {
				selectedPermissionStr = "0"
			}
		}

		var selectedPermission uint64
		selectedPermission, err = strconv.ParseUint(selectedPermissionStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		selectedPermissionIdentifier := ""
		if selectedPermission > 0 {
			// check if permission belongs to resource
			var found bool
			for _, permission := range permissions {
				if permission.Id == uint(selectedPermission) {
					found = true
					selectedPermissionIdentifier = permission.PermissionIdentifier
					break
				}
			}

			if !found {
				s.internalServerError(w, r, fmt.Errorf("permission %v does not belong to resource %v", selectedPermission, resource.Id))
				return
			}
		}

		page := r.URL.Query().Get("page")
		if len(page) == 0 {
			page = "1"
		}
		pageInt, err := strconv.Atoi(page)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if pageInt < 1 {
			s.internalServerError(w, r, fmt.Errorf("invalid page %d", pageInt))
			return
		}

		const pageSize = 10
		groupsWithPermission, total, err := s.database.GetAllGroupsPaginated(pageInt, pageSize)
		if err != nil {
			s.internalServerError(w, r, err)
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
				if permission.Id == uint(selectedPermission) {
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

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = sess.Save(r, w)
			if err != nil {
				s.internalServerError(w, r, err)
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

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_groups_with_permission.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminResourceGroupsWithPermissionAddPermissionPost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("resourceId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		resource, err := s.database.GetResourceById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if resource == nil {
			s.internalServerError(w, r, errors.New("resource not found"))
			return
		}

		groupIdStr := chi.URLParam(r, "groupId")
		if len(groupIdStr) == 0 {
			s.jsonError(w, r, errors.New("groupId is required"))
			return
		}

		groupId, err := strconv.ParseUint(groupIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		group, err := s.database.GetGroupById(uint(groupId))
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if group == nil {
			s.jsonError(w, r, errors.New("group not found"))
			return
		}

		permissionIdStr := chi.URLParam(r, "permissionId")
		if len(permissionIdStr) == 0 {
			s.jsonError(w, r, errors.New("permissionId is required"))
			return
		}

		permissionId, err := strconv.ParseUint(permissionIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		permissions, err := s.database.GetPermissionsByResourceId(resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		// filter out the userinfo permission if the resource is authserver
		filteredPermissions := []entities.Permission{}
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
			if permission.Id == uint(permissionId) {
				found = true
				break
			}
		}

		if !found {
			s.jsonError(w, r, fmt.Errorf("permission %v does not belong to resource %v", permissionId, resource.Id))
			return
		}

		found = false
		for _, permission := range group.Permissions {
			if permission.Id == uint(permissionId) {
				found = true
				break
			}
		}

		if found {
			s.jsonError(w, r, fmt.Errorf("group %v already has permission %v", group.Id, permissionId))
			return
		}

		err = s.database.AddGroupPermission(group.Id, uint(permissionId))
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditAddedGroupPermission, map[string]interface{}{
			"groupId":      group.Id,
			"permissionId": uint(permissionId),
			"loggedInUser": s.getLoggedInSubject(r),
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

func (s *Server) handleAdminResourceGroupsWithPermissionRemovePermissionPost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("resourceId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		resource, err := s.database.GetResourceById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if resource == nil {
			s.internalServerError(w, r, errors.New("resource not found"))
			return
		}

		groupIdStr := chi.URLParam(r, "groupId")
		if len(groupIdStr) == 0 {
			s.jsonError(w, r, errors.New("groupId is required"))
			return
		}

		groupId, err := strconv.ParseUint(groupIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		group, err := s.database.GetGroupById(uint(groupId))
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if group == nil {
			s.jsonError(w, r, errors.New("group not found"))
			return
		}

		permissionIdStr := chi.URLParam(r, "permissionId")
		if len(permissionIdStr) == 0 {
			s.jsonError(w, r, errors.New("permissionId is required"))
			return
		}

		permissionId, err := strconv.ParseUint(permissionIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		permissions, err := s.database.GetPermissionsByResourceId(resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		// filter out the userinfo permission if the resource is authserver
		filteredPermissions := []entities.Permission{}
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
			if permission.Id == uint(permissionId) {
				found = true
				break
			}
		}

		if !found {
			s.jsonError(w, r, fmt.Errorf("permission %v does not belong to resource %v", permissionId, resource.Id))
			return
		}

		found = false
		for _, permission := range group.Permissions {
			if permission.Id == uint(permissionId) {
				found = true
				break
			}
		}

		if !found {
			s.jsonError(w, r, fmt.Errorf("group %v does not have permission %v", group.Id, permissionId))
			return
		}

		err = s.database.DeleteGroupPermission(group.Id, uint(permissionId))
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditDeletedGroupPermission, map[string]interface{}{
			"groupId":      group.Id,
			"permissionId": uint(permissionId),
			"loggedInUser": s.getLoggedInSubject(r),
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
