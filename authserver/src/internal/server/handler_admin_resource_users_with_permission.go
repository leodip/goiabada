package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/unknwon/paginater"
)

func (s *Server) handleAdminResourceUsersWithPermissionGet() http.HandlerFunc {

	type pageResult struct {
		Page     int
		PageSize int
		Total    int
		Users    []entities.User
	}

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.WithStack(errors.New("resourceId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		resource, err := s.database.GetResourceById(nil, id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if resource == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("resource not found")))
			return
		}

		permissions, err := s.database.GetPermissionsByResourceId(nil, resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		err = s.database.PermissionsLoadResources(nil, permissions)
		if err != nil {
			s.jsonError(w, r, err)
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
				selectedPermissionStr = strconv.FormatInt(permissions[0].Id, 10)
			} else {
				selectedPermissionStr = "0"
			}
		}

		var selectedPermission int64
		selectedPermission, err = strconv.ParseInt(selectedPermissionStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
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
				s.internalServerError(w, r, errors.WithStack(fmt.Errorf("permission %v does not belong to resource %v", selectedPermission, resource.Id)))
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
			s.internalServerError(w, r, errors.WithStack(fmt.Errorf("invalid page %d", pageInt)))
			return
		}

		const pageSize = 10
		usersWithPermission, total, err := s.database.GetUsersByPermissionIdPaginated(nil, selectedPermission, pageInt, pageSize)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		pageResult := pageResult{
			Page:     pageInt,
			PageSize: pageSize,
			Total:    total,
			Users:    usersWithPermission,
		}

		p := paginater.New(total, pageSize, pageInt, 5)

		sess, err := s.sessionStore.Get(r, constants.SessionName)
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

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_users_with_permission.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminResourceUsersWithPermissionRemovePermissionPost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.WithStack(errors.New("resourceId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		resource, err := s.database.GetResourceById(nil, id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if resource == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("resource not found")))
			return
		}

		userIdStr := chi.URLParam(r, "userId")
		if len(userIdStr) == 0 {
			s.jsonError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		user, err := s.database.GetUserById(nil, userId)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if user == nil {
			s.jsonError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		err = s.database.UserLoadPermissions(nil, user)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		permissionIdStr := chi.URLParam(r, "permissionId")
		if len(userIdStr) == 0 {
			s.jsonError(w, r, errors.WithStack(errors.New("permissionId is required")))
			return
		}

		permissionId, err := strconv.ParseInt(permissionIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		permissions, err := s.database.GetPermissionsByResourceId(nil, resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		err = s.database.PermissionsLoadResources(nil, permissions)
		if err != nil {
			s.jsonError(w, r, err)
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
			if permission.Id == permissionId {
				found = true
				break
			}
		}

		if !found {
			s.jsonError(w, r, errors.WithStack(fmt.Errorf("permission %v does not belong to resource %v", permissionId, resource.Id)))
			return
		}

		found = false
		for _, permission := range user.Permissions {
			if permission.Id == permissionId {
				found = true
				break
			}
		}

		if !found {
			s.jsonError(w, r, errors.WithStack(fmt.Errorf("user %v does not have permission %v", user.Id, permissionId)))
			return
		}

		userPermission, err := s.database.GetUserPermissionByUserIdAndPermissionId(nil, user.Id, permissionId)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if userPermission == nil {
			s.jsonError(w, r, errors.WithStack(fmt.Errorf("user %v does not have permission %v", user.Id, permissionId)))
			return
		}

		err = s.database.DeleteUserPermission(nil, userPermission.Id)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditDeletedUserPermission, map[string]interface{}{
			"userId":       user.Id,
			"permissionId": permissionId,
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

func (s *Server) handleAdminResourceUsersWithPermissionAddGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.WithStack(errors.New("resourceId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		resource, err := s.database.GetResourceById(nil, id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if resource == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("resource not found")))
			return
		}

		permissions, err := s.database.GetPermissionsByResourceId(nil, resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		err = s.database.PermissionsLoadResources(nil, permissions)
		if err != nil {
			s.jsonError(w, r, err)
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

		selectedPermissionStr := chi.URLParam(r, "permissionId")
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
			s.internalServerError(w, r, err)
			return
		}

		// check if permission belongs to resource
		selectedPermissionIdentifier := ""
		var found bool
		for _, permission := range permissions {
			if permission.Id == selectedPermission {
				found = true
				selectedPermissionIdentifier = permission.PermissionIdentifier
				break
			}
		}

		if !found {
			s.internalServerError(w, r, errors.WithStack(fmt.Errorf("permission %v does not belong to resource %v", selectedPermission, resource.Id)))
			return
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

		bind := map[string]interface{}{
			"resourceId":                   resource.Id,
			"resourceIdentifier":           resource.ResourceIdentifier,
			"description":                  resource.Description,
			"isSystemLevelResource":        resource.IsSystemLevelResource(),
			"permissions":                  permissions,
			"selectedPermission":           selectedPermission,
			"selectedPermissionIdentifier": selectedPermissionIdentifier,
			"page":                         pageInt,
			"csrfField":                    csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_users_with_permission_add.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminResourceUsersWithPermissionSearchGet() http.HandlerFunc {

	type userResult struct {
		Id            int64
		Subject       string
		Username      string
		Email         string
		GivenName     string
		MiddleName    string
		FamilyName    string
		HasPermission bool
	}

	type searchResult struct {
		Users []userResult
	}

	return func(w http.ResponseWriter, r *http.Request) {
		result := searchResult{}

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.WithStack(errors.New("resourceId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		resource, err := s.database.GetResourceById(nil, id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if resource == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("resource not found")))
			return
		}

		permissions, err := s.database.GetPermissionsByResourceId(nil, resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		err = s.database.PermissionsLoadResources(nil, permissions)
		if err != nil {
			s.jsonError(w, r, err)
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

		selectedPermissionStr := chi.URLParam(r, "permissionId")
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
			s.internalServerError(w, r, err)
			return
		}

		// check if permission belongs to resource
		var found bool
		for _, permission := range permissions {
			if permission.Id == selectedPermission {
				found = true
				break
			}
		}

		if !found {
			s.internalServerError(w, r, errors.WithStack(fmt.Errorf("permission %v does not belong to resource %v", selectedPermission, resource.Id)))
			return
		}

		query := strings.TrimSpace(r.URL.Query().Get("query"))
		if len(query) == 0 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		users, _, err := s.database.SearchUsersPaginated(nil, query, 1, 15)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		err = s.database.UsersLoadPermissions(nil, users)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		usersResult := make([]userResult, 0)
		for _, user := range users {

			hasPermission := false
			for _, permission := range user.Permissions {
				if permission.Id == selectedPermission {
					hasPermission = true
					break
				}
			}

			usersResult = append(usersResult, userResult{
				Id:            user.Id,
				Subject:       user.Subject.String(),
				Username:      user.Username,
				Email:         user.Email,
				GivenName:     user.GivenName,
				MiddleName:    user.MiddleName,
				FamilyName:    user.FamilyName,
				HasPermission: hasPermission,
			})
		}

		result.Users = usersResult
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func (s *Server) handleAdminResourceUsersWithPermissionAddPermissionPost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.WithStack(errors.New("resourceId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		resource, err := s.database.GetResourceById(nil, id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if resource == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("resource not found")))
			return
		}

		userIdStr := chi.URLParam(r, "userId")
		if len(userIdStr) == 0 {
			s.jsonError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		user, err := s.database.GetUserById(nil, userId)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if user == nil {
			s.jsonError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		err = s.database.UserLoadPermissions(nil, user)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		permissionIdStr := chi.URLParam(r, "permissionId")
		if len(userIdStr) == 0 {
			s.jsonError(w, r, errors.WithStack(errors.New("permissionId is required")))
			return
		}

		permissionId, err := strconv.ParseInt(permissionIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		permissions, err := s.database.GetPermissionsByResourceId(nil, resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		err = s.database.PermissionsLoadResources(nil, permissions)
		if err != nil {
			s.jsonError(w, r, err)
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
			if permission.Id == permissionId {
				found = true
				break
			}
		}

		if !found {
			s.jsonError(w, r, errors.WithStack(fmt.Errorf("permission %v does not belong to resource %v", permissionId, resource.Id)))
			return
		}

		found = false
		for _, permission := range user.Permissions {
			if permission.Id == permissionId {
				found = true
				break
			}
		}

		if !found {
			err = s.database.CreateUserPermission(nil, &entities.UserPermission{
				UserId:       user.Id,
				PermissionId: permissionId,
			})
			if err != nil {
				s.jsonError(w, r, err)
				return
			}

			lib.LogAudit(constants.AuditAddedUserPermission, map[string]interface{}{
				"userId":       user.Id,
				"permissionId": permissionId,
				"loggedInUser": s.getLoggedInSubject(r),
			})
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
