package adminresourcehandlers

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/personname"
)

// resourceUsersWithPermissionAPI is what the users-with-permission page needs: the resource and
// its permissions, the users holding one, and each user's own set.
type resourceUsersWithPermissionAPI interface {
	GetPermissionsByResource(ctx context.Context, accessToken string, resourceID int64) ([]api.PermissionResponse, error)
	GetResourceByID(ctx context.Context, accessToken string, resourceID int64) (*api.ResourceResponse, error)
	GetUserPermissions(ctx context.Context, accessToken string, userID int64) (*api.UserResponse, []api.PermissionResponse, error)
	GetUsersByPermission(ctx context.Context, accessToken string, permissionID int64, page, size int) ([]api.UserResponse, int, error)
	SearchUsersWithPermissionAnnotation(ctx context.Context, accessToken string, permissionID int64, query string, page, size int) ([]api.UserWithPermissionResponse, int, error)
	UpdateUserPermissions(ctx context.Context, accessToken string, userID int64, request *api.UpdateUserPermissionsRequest) error
}

func HandleUsersWithPermissionGet(
	httpHelper HTTPHelper,
	apiClient resourceUsersWithPermissionAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		loaded, err := loadResourcePermissions(r, apiClient)
		if errors.Is(err, errNoSuchResource) {
			httpHelper.NotFound(w, r)
			return
		}
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		resource, permissions, accessToken := loaded.resource, loaded.permissions, loaded.accessToken
		selectedPermissionStr := r.URL.Query().Get("permission")
		if len(selectedPermissionStr) == 0 {
			if len(permissions) > 0 {
				selectedPermissionStr = strconv.FormatInt(permissions[0].ID, 10)
			} else {
				selectedPermissionStr = "0"
			}
		}
		selectedPermission, err := strconv.ParseInt(selectedPermissionStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		selectedPermissionIdentifier := ""
		if selectedPermission > 0 {
			// check if permission belongs to resource
			var found bool
			for _, permission := range permissions {
				if permission.ID == selectedPermission {
					found = true
					selectedPermissionIdentifier = permission.PermissionIdentifier
					break
				}
			}
			if !found {
				httpHelper.NotFound(w, r)
				return
			}
		}

		pageInt := pagination.ParsePage(r.URL.Query().Get("page"))

		const pageSize = 10
		var usersWithPermission []api.UserResponse
		var total int
		if selectedPermission > 0 {
			usersWithPermission, total, err = apiClient.GetUsersByPermission(r.Context(), accessToken, selectedPermission, pageInt, pageSize)
			if err != nil {
				render.HandleAPIError(httpHelper, w, r, err)
				return
			}

			// A page past the last one is only visible once the total has come
			// back. Ask again at the last page rather than render an empty list
			// under a bar that highlights a full one (#305).
			if clamped := pagination.ClampPage(total, pageSize, pageInt); clamped != pageInt {
				pageInt = clamped
				usersWithPermission, total, err = apiClient.GetUsersByPermission(r.Context(), accessToken, selectedPermission, pageInt, pageSize)
				if err != nil {
					render.HandleAPIError(httpHelper, w, r, err)
					return
				}
			}
		} else {
			// No permission is selected, so nothing is listed and the bar holds a
			// lone page 1. Any page number lands on it.
			pageInt = 1
		}

		pageResult := UsersWithPermissionPageResult{
			Page:     pageInt,
			PageSize: pageSize,
			Total:    total,
			Users:    usersWithPermission,
		}

		p := pagination.New(total, pageSize, pageInt, 5)

		bind := map[string]interface{}{
			"resourceId":                   resource.ID,
			"resourceIdentifier":           resource.ResourceIdentifier,
			"description":                  resource.Description,
			"isSystemLevelResource":        resource.IsSystemLevelResource,
			"permissions":                  permissions,
			"permissionChoices":            render.PermissionChoices(permissions),
			"selectedPermission":           selectedPermission,
			"selectedPermissionIdentifier": selectedPermissionIdentifier,
			"pageResult":                   pageResult,
			"paginator":                    p,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_users_with_permission.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleUsersWithPermissionRemovePermissionPost(
	httpHelper HTTPHelper,
	apiClient resourceUsersWithPermissionAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		loaded, err := loadResourcePermissions(r, apiClient)
		if errors.Is(err, errNoSuchResource) {
			render.JSONNotFound(httpHelper, w, r)
			return
		}
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}
		permissions, accessToken := loaded.permissions, loaded.accessToken

		userIDStr := r.PathValue("userId")
		if len(userIDStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}
		userID, err := strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		user, currentPerms, err := apiClient.GetUserPermissions(r.Context(), accessToken, userID)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}
		if user == nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		permissionIDStr := r.PathValue("permissionId")
		if len(permissionIDStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}
		permissionID, err := strconv.ParseInt(permissionIDStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}
		found := false
		for _, permission := range permissions {
			if permission.ID == permissionID {
				found = true
				break
			}
		}
		if !found {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		found = false
		for _, permission := range currentPerms {
			if permission.ID == permissionID {
				found = true
				break
			}
		}
		if !found {
			render.JSONConflict(httpHelper, w, r)
			return
		}

		// Build reduced set and update via API
		newIDs := make([]int64, 0, len(currentPerms))
		for _, p := range currentPerms {
			if p.ID != permissionID {
				newIDs = append(newIDs, p.ID)
			}
		}
		apiReq := &api.UpdateUserPermissionsRequest{PermissionIDs: newIDs, ExpectedPermissionIDs: permissionIDsOf(currentPerms)}
		if err := apiClient.UpdateUserPermissions(r.Context(), accessToken, user.ID, apiReq); err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		result := struct{ Success bool }{Success: true}
		httpHelper.EncodeJSON(w, r, result)
	}
}

func HandleUsersWithPermissionAddGet(
	httpHelper HTTPHelper,
	apiClient resourceUsersWithPermissionAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		loaded, err := loadResourcePermissions(r, apiClient)
		if errors.Is(err, errNoSuchResource) {
			httpHelper.NotFound(w, r)
			return
		}
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		resource, permissions := loaded.resource, loaded.permissions
		selectedPermissionStr := r.PathValue("permissionId")
		if len(selectedPermissionStr) == 0 {
			if len(permissions) > 0 {
				selectedPermissionStr = strconv.FormatInt(permissions[0].ID, 10)
			} else {
				selectedPermissionStr = "0"
			}
		}
		selectedPermission, err := strconv.ParseInt(selectedPermissionStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		// check if permission belongs to resource
		selectedPermissionIdentifier := ""
		var found bool
		for _, permission := range permissions {
			if permission.ID == selectedPermission {
				found = true
				selectedPermissionIdentifier = permission.PermissionIdentifier
				break
			}
		}
		if !found {
			httpHelper.NotFound(w, r)
			return
		}

		// Only carried forward, into the link back to the list; the same parse as
		// the list's, so an unparseable page does not answer 500 on one page and
		// render on the other (#305).
		pageInt := pagination.ParsePage(r.URL.Query().Get("page"))

		bind := map[string]interface{}{
			"resourceId":                   resource.ID,
			"resourceIdentifier":           resource.ResourceIdentifier,
			"description":                  resource.Description,
			"isSystemLevelResource":        resource.IsSystemLevelResource,
			"permissions":                  permissions,
			"permissionChoices":            render.PermissionChoices(permissions),
			"selectedPermission":           selectedPermission,
			"selectedPermissionIdentifier": selectedPermissionIdentifier,
			"page":                         pageInt,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_users_with_permission_add.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleUsersWithPermissionSearchGet(
	httpHelper HTTPHelper,
	apiClient resourceUsersWithPermissionAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := SearchResult{}

		loaded, err := loadResourcePermissions(r, apiClient)
		if errors.Is(err, errNoSuchResource) {
			render.JSONNotFound(httpHelper, w, r)
			return
		}
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}
		permissions, accessToken := loaded.permissions, loaded.accessToken
		selectedPermissionStr := r.PathValue("permissionId")
		if len(selectedPermissionStr) == 0 {
			if len(permissions) > 0 {
				selectedPermissionStr = strconv.FormatInt(permissions[0].ID, 10)
			} else {
				selectedPermissionStr = "0"
			}
		}
		selectedPermission, err := strconv.ParseInt(selectedPermissionStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}
		// check if permission belongs to resource
		var found bool
		for _, permission := range permissions {
			if permission.ID == selectedPermission {
				found = true
				break
			}
		}
		if !found {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		query := strings.TrimSpace(r.URL.Query().Get("query"))
		if len(query) == 0 {
			httpHelper.EncodeJSON(w, r, result)
			return
		}

		annotatedUsers, _, err := apiClient.SearchUsersWithPermissionAnnotation(r.Context(), accessToken, selectedPermission, query, 1, 15)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}
		usersResult := make([]UserResult, 0, len(annotatedUsers))
		for _, u := range annotatedUsers {
			usersResult = append(usersResult, UserResult{
				ID:            u.ID,
				Subject:       u.Subject,
				Username:      u.Username,
				Email:         u.Email,
				GivenName:     u.GivenName,
				MiddleName:    u.MiddleName,
				FamilyName:    u.FamilyName,
				FullName:      personname.FullName(u.GivenName, u.MiddleName, u.FamilyName),
				HasPermission: u.HasPermission,
			})
		}
		result.Users = usersResult
		httpHelper.EncodeJSON(w, r, result)
	}
}

func HandleUsersWithPermissionAddPermissionPost(
	httpHelper HTTPHelper,
	apiClient resourceUsersWithPermissionAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		loaded, err := loadResourcePermissions(r, apiClient)
		if errors.Is(err, errNoSuchResource) {
			render.JSONNotFound(httpHelper, w, r)
			return
		}
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}
		permissions, accessToken := loaded.permissions, loaded.accessToken

		userIDStr := r.PathValue("userId")
		if len(userIDStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}
		userID, err := strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		user, currentPerms, err := apiClient.GetUserPermissions(r.Context(), accessToken, userID)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}
		if user == nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		permissionIDStr := r.PathValue("permissionId")
		if len(permissionIDStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}
		permissionID, err := strconv.ParseInt(permissionIDStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		found := false
		for _, permission := range permissions {
			if permission.ID == permissionID {
				found = true
				break
			}
		}
		if !found {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		for _, permission := range currentPerms {
			if permission.ID == permissionID {
				render.JSONConflict(httpHelper, w, r)
				return
			}
		}

		newIDs := make([]int64, 0, len(currentPerms)+1)
		for _, p := range currentPerms {
			newIDs = append(newIDs, p.ID)
		}
		newIDs = append(newIDs, permissionID)
		apiReq := &api.UpdateUserPermissionsRequest{PermissionIDs: newIDs, ExpectedPermissionIDs: permissionIDsOf(currentPerms)}
		if err := apiClient.UpdateUserPermissions(r.Context(), accessToken, user.ID, apiReq); err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		result := struct{ Success bool }{Success: true}
		httpHelper.EncodeJSON(w, r, result)
	}
}
