package adminresourcehandlers

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// resourceGroupsWithPermissionAPI is what the groups-with-permission page needs: the resource and
// its permissions, the groups to choose from, and each group's own set.
type resourceGroupsWithPermissionAPI interface {
	GetAllGroups(ctx context.Context, accessToken string) ([]api.GroupResponse, error)
	GetGroupPermissions(ctx context.Context, accessToken string, groupId int64) (*api.GroupResponse, []api.PermissionResponse, error)
	GetPermissionsByResource(ctx context.Context, accessToken string, resourceId int64) ([]api.PermissionResponse, error)
	GetResourceById(ctx context.Context, accessToken string, resourceId int64) (*api.ResourceResponse, error)
	SearchGroupsWithPermissionAnnotation(ctx context.Context, accessToken string, permissionId int64, page, size int) ([]api.GroupWithPermissionResponse, int, error)
	UpdateGroupPermissions(ctx context.Context, accessToken string, groupId int64, request *api.UpdateGroupPermissionsRequest) error
}

func HandleGroupsWithPermissionGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient resourceGroupsWithPermissionAPI,
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
				selectedPermissionStr = strconv.FormatInt(permissions[0].Id, 10)
			} else {
				selectedPermissionStr = "0"
			}
		}

		var selectedPermission int64
		selectedPermission, err = strconv.ParseInt(selectedPermissionStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
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
				httpHelper.NotFound(w, r)
				return
			}
		}

		pageInt := pagination.ParsePage(r.URL.Query().Get("page"))

		const pageSize = 10
		var (
			total        int
			groupInfoArr []GroupInfo
		)
		if selectedPermission == 0 {
			// No permissions in resource; paginate groups client-side and mark all as false
			allGroups, getGroupsErr := apiClient.GetAllGroups(r.Context(), accessToken)
			if getGroupsErr != nil {
				render.HandleAPIError(httpHelper, w, r, getGroupsErr)
				return
			}
			total = len(allGroups)

			// This is the one page in the admin console that slices the list itself
			// rather than asking the API for a page of it, so the clamp is
			// arithmetic here and not a second call.
			//
			// It is also what keeps the slice below in range. pageInt comes from
			// "?page=" and used to be checked only for being at least 1, so
			// "?page=9223372036854775807" wrapped the product negative and panicked
			// the request on allGroups[start:end] before anything rendered (#305).
			// A clamped page cannot: it is at most the page count, so start is at
			// most total. The two guards after it are kept as the bound on the
			// slice expression itself, so a future edit to the clamp cannot turn
			// back into a panic.
			pageInt = pagination.ClampPage(total, pageSize, pageInt)

			start := (pageInt - 1) * pageSize
			if start > total {
				start = total
			}
			end := start + pageSize
			if end > total {
				end = total
			}
			pageGroups := allGroups[start:end]
			groupInfoArr = make([]GroupInfo, len(pageGroups))
			for i, g := range pageGroups {
				groupInfoArr[i] = GroupInfo{Id: g.Id, GroupIdentifier: g.GroupIdentifier, Description: g.Description, HasPermission: false}
			}
		} else {
			annotatedGroups, total2, searchErr := apiClient.SearchGroupsWithPermissionAnnotation(r.Context(), accessToken, selectedPermission, pageInt, pageSize)
			if searchErr != nil {
				render.HandleAPIError(httpHelper, w, r, searchErr)
				return
			}
			total = total2

			// A page past the last one is only visible once the total has come
			// back. Ask again at the last page rather than render an empty list
			// under a bar that highlights a full one (#305).
			if clamped := pagination.ClampPage(total, pageSize, pageInt); clamped != pageInt {
				pageInt = clamped
				annotatedGroups, total2, searchErr = apiClient.SearchGroupsWithPermissionAnnotation(r.Context(), accessToken, selectedPermission, pageInt, pageSize)
				if searchErr != nil {
					render.HandleAPIError(httpHelper, w, r, searchErr)
					return
				}
				total = total2
			}

			groupInfoArr = make([]GroupInfo, len(annotatedGroups))
			for i, grp := range annotatedGroups {
				groupInfoArr[i] = GroupInfo{
					Id:              grp.Id,
					GroupIdentifier: grp.GroupIdentifier,
					Description:     grp.Description,
					HasPermission:   grp.HasPermission,
				}
			}
		}

		pageResult := GroupsWithPermissionPageResult{Page: pageInt, PageSize: pageSize, Total: total, Groups: groupInfoArr}
		p := pagination.New(total, pageSize, pageInt, 5)

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		_, savedSuccessfully := sess.TakeFlash("savedSuccessfully")
		if savedSuccessfully {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"resourceId":                   resource.Id,
			"resourceIdentifier":           resource.ResourceIdentifier,
			"description":                  resource.Description,
			"isSystemLevelResource":        resource.IsSystemLevelResource,
			"permissions":                  permissions,
			"selectedPermission":           selectedPermission,
			"selectedPermissionIdentifier": selectedPermissionIdentifier,
			"pageResult":                   pageResult,
			"paginator":                    p,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_groups_with_permission.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleGroupsWithPermissionAddPermissionPost(
	httpHelper HttpHelper,
	apiClient resourceGroupsWithPermissionAPI,
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

		groupIdStr := chi.URLParam(r, "groupId")
		if len(groupIdStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		groupId, err := strconv.ParseInt(groupIdStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		group, currentPerms, err := apiClient.GetGroupPermissions(r.Context(), accessToken, groupId)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}
		if group == nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		permissionIdStr := chi.URLParam(r, "permissionId")
		if len(permissionIdStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		permissionId, err := strconv.ParseInt(permissionIdStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		found := false
		for _, permission := range permissions {
			if permission.Id == permissionId {
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
			if permission.Id == permissionId {
				found = true
				break
			}
		}

		if found {
			render.JSONConflict(httpHelper, w, r)
			return
		}
		// Build the new set and update via API
		newIds := make([]int64, 0, len(currentPerms)+1)
		for _, p := range currentPerms {
			newIds = append(newIds, p.Id)
		}
		newIds = append(newIds, permissionId)

		req := &api.UpdateGroupPermissionsRequest{PermissionIds: newIds, ExpectedPermissionIds: permissionIdsOf(currentPerms)}
		if err := apiClient.UpdateGroupPermissions(r.Context(), accessToken, group.Id, req); err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJSON(w, r, result)
	}
}

func HandleGroupsWithPermissionRemovePermissionPost(
	httpHelper HttpHelper,
	apiClient resourceGroupsWithPermissionAPI,
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

		groupIdStr := chi.URLParam(r, "groupId")
		if len(groupIdStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		groupId, err := strconv.ParseInt(groupIdStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		group, currentPerms, err := apiClient.GetGroupPermissions(r.Context(), accessToken, groupId)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}
		if group == nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		permissionIdStr := chi.URLParam(r, "permissionId")
		if len(permissionIdStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		permissionId, err := strconv.ParseInt(permissionIdStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		found := false
		for _, permission := range permissions {
			if permission.Id == permissionId {
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
			if permission.Id == permissionId {
				found = true
				break
			}
		}

		if !found {
			render.JSONConflict(httpHelper, w, r)
			return
		}
		// Build reduced set and update via API
		newIds := make([]int64, 0, len(currentPerms))
		for _, p := range currentPerms {
			if p.Id != permissionId {
				newIds = append(newIds, p.Id)
			}
		}
		req := &api.UpdateGroupPermissionsRequest{PermissionIds: newIds, ExpectedPermissionIds: permissionIdsOf(currentPerms)}
		if err := apiClient.UpdateGroupPermissions(r.Context(), accessToken, group.Id, req); err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJSON(w, r, result)
	}
}

// no extra types
