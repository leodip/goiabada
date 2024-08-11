package adminresourcehandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/audit"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/data"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/models"
	"github.com/unknwon/paginater"
)

func HandleAdminResourceUsersWithPermissionGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
) http.HandlerFunc {

	type pageResult struct {
		Page     int
		PageSize int
		Total    int
		Users    []models.User
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
		usersWithPermission, total, err := database.GetUsersByPermissionIdPaginated(nil, selectedPermission, pageInt, pageSize)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		pageResult := pageResult{
			Page:     pageInt,
			PageSize: pageSize,
			Total:    total,
			Users:    usersWithPermission,
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

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_users_with_permission.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminResourceUsersWithPermissionRemovePermissionPost(
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

		err = database.UserLoadPermissions(nil, user)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		permissionIdStr := chi.URLParam(r, "permissionId")
		if len(userIdStr) == 0 {
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
		for _, permission := range user.Permissions {
			if permission.Id == permissionId {
				found = true
				break
			}
		}

		if !found {
			httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("user %v does not have permission %v", user.Id, permissionId)))
			return
		}

		userPermission, err := database.GetUserPermissionByUserIdAndPermissionId(nil, user.Id, permissionId)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		if userPermission == nil {
			httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("user %v does not have permission %v", user.Id, permissionId)))
			return
		}

		err = database.DeleteUserPermission(nil, userPermission.Id)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		audit.Log(constants.AuditDeletedUserPermission, map[string]interface{}{
			"userId":       user.Id,
			"permissionId": permissionId,
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

func HandleAdminResourceUsersWithPermissionAddGet(
	httpHelper handlers.HttpHelper,
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
			httpHelper.InternalServerError(w, r, err)
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
			httpHelper.InternalServerError(w, r, errors.WithStack(fmt.Errorf("permission %v does not belong to resource %v", selectedPermission, resource.Id)))
			return
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

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_users_with_permission_add.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminResourceUsersWithPermissionSearchGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {

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
			httpHelper.InternalServerError(w, r, err)
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
			httpHelper.InternalServerError(w, r, errors.WithStack(fmt.Errorf("permission %v does not belong to resource %v", selectedPermission, resource.Id)))
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

		err = database.UsersLoadPermissions(nil, users)
		if err != nil {
			httpHelper.JsonError(w, r, err)
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
		httpHelper.EncodeJson(w, r, result)
	}
}

func HandleAdminResourceUsersWithPermissionAddPermissionPost(
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

		err = database.UserLoadPermissions(nil, user)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		permissionIdStr := chi.URLParam(r, "permissionId")
		if len(userIdStr) == 0 {
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
		for _, permission := range user.Permissions {
			if permission.Id == permissionId {
				found = true
				break
			}
		}

		if !found {
			err = database.CreateUserPermission(nil, &models.UserPermission{
				UserId:       user.Id,
				PermissionId: permissionId,
			})
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}

			audit.Log(constants.AuditAddedUserPermission, map[string]interface{}{
				"userId":       user.Id,
				"permissionId": permissionId,
				"loggedInUser": authHelper.GetLoggedInSubject(r),
			})
		}

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJson(w, r, result)
	}
}
