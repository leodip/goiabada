package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/entities"
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

		permissions, err := s.database.GetResourcePermissions(resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

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
		usersWithPermission, total, err := s.database.GetUsersWithPermission(uint(selectedPermission), pageInt, pageSize)
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

		userIdStr := chi.URLParam(r, "userId")
		if len(userIdStr) == 0 {
			s.jsonError(w, r, errors.New("userId is required"))
			return
		}

		userId, err := strconv.ParseUint(userIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		user, err := s.database.GetUserById(uint(userId))
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if user == nil {
			s.jsonError(w, r, errors.New("user not found"))
			return
		}

		permissionIdStr := chi.URLParam(r, "permissionId")
		if len(userIdStr) == 0 {
			s.jsonError(w, r, errors.New("permissionId is required"))
			return
		}

		permissionId, err := strconv.ParseUint(permissionIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		permissions, err := s.database.GetResourcePermissions(resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

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
		for _, permission := range user.Permissions {
			if permission.Id == uint(permissionId) {
				found = true
				break
			}
		}

		if !found {
			s.jsonError(w, r, fmt.Errorf("user %v does not have permission %v", user.Id, permissionId))
			return
		}

		err = s.database.DeleteUserPermission(user.Id, uint(permissionId))
		if err != nil {
			s.jsonError(w, r, err)
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

func (s *Server) handleAdminResourceUsersWithPermissionAddGet() http.HandlerFunc {

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

		permissions, err := s.database.GetResourcePermissions(resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		selectedPermissionStr := chi.URLParam(r, "permissionId")
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

		// check if permission belongs to resource
		selectedPermissionIdentifier := ""
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
		Id            uint
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

		permissions, err := s.database.GetResourcePermissions(resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		selectedPermissionStr := chi.URLParam(r, "permissionId")
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

		// check if permission belongs to resource
		var found bool
		for _, permission := range permissions {
			if permission.Id == uint(selectedPermission) {
				found = true
				break
			}
		}

		if !found {
			s.internalServerError(w, r, fmt.Errorf("permission %v does not belong to resource %v", selectedPermission, resource.Id))
			return
		}

		query := strings.TrimSpace(r.URL.Query().Get("query"))
		if len(query) == 0 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		users, _, err := s.database.GetUsers(query, 1, 15)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		usersResult := make([]userResult, 0)
		for _, user := range users {

			hasPermission := false
			for _, permission := range user.Permissions {
				if permission.Id == uint(selectedPermission) {
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

		userIdStr := chi.URLParam(r, "userId")
		if len(userIdStr) == 0 {
			s.jsonError(w, r, errors.New("userId is required"))
			return
		}

		userId, err := strconv.ParseUint(userIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		user, err := s.database.GetUserById(uint(userId))
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if user == nil {
			s.jsonError(w, r, errors.New("user not found"))
			return
		}

		permissionIdStr := chi.URLParam(r, "permissionId")
		if len(userIdStr) == 0 {
			s.jsonError(w, r, errors.New("permissionId is required"))
			return
		}

		permissionId, err := strconv.ParseUint(permissionIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		permissions, err := s.database.GetResourcePermissions(resource.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

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
		for _, permission := range user.Permissions {
			if permission.Id == uint(permissionId) {
				found = true
				break
			}
		}

		if !found {
			err = s.database.AddUserPermission(user.Id, uint(permissionId))
			if err != nil {
				s.jsonError(w, r, err)
				return
			}
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
