package adminresourcehandlers

import (
	"context"
	"net/http"
	"slices"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	"github.com/leodip/goiabada/core/api"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
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

func HandleAdminResourceGroupsWithPermissionGet(
	httpHelper handlers.HttpHelper,
	httpSession sessionstore.Store,
	apiClient resourceGroupsWithPermissionAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}
		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}
		accessToken := jwtInfo.TokenResponse.AccessToken

		resource, err := apiClient.GetResourceById(r.Context(), accessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if resource == nil {
			httpHelper.NotFound(w, r)
			return
		}

		permissions, err := apiClient.GetPermissionsByResource(r.Context(), accessToken, resource.Id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// filter out the userinfo permission if the resource is authserver
		if resource.ResourceIdentifier == coreconstants.AuthServerResourceIdentifier {
			permissions = slices.DeleteFunc(permissions, func(p api.PermissionResponse) bool {
				return p.PermissionIdentifier == coreconstants.UserinfoPermissionIdentifier
			})
		}

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
				handlers.HandleAPIError(httpHelper, w, r, getGroupsErr)
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
				handlers.HandleAPIError(httpHelper, w, r, searchErr)
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
					handlers.HandleAPIError(httpHelper, w, r, searchErr)
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

		sess, err := httpSession.Get(r, coreconstants.AdminConsoleSessionName)
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

func HandleAdminResourceGroupsWithPermissionAddPermissionPost(
	httpHelper handlers.HttpHelper,
	apiClient resourceGroupsWithPermissionAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}
		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}
		accessToken := jwtInfo.TokenResponse.AccessToken

		resource, err := apiClient.GetResourceById(r.Context(), accessToken, id)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}
		if resource == nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		groupIdStr := chi.URLParam(r, "groupId")
		if len(groupIdStr) == 0 {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		groupId, err := strconv.ParseInt(groupIdStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		group, currentPerms, err := apiClient.GetGroupPermissions(r.Context(), accessToken, groupId)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}
		if group == nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		permissionIdStr := chi.URLParam(r, "permissionId")
		if len(permissionIdStr) == 0 {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		permissionId, err := strconv.ParseInt(permissionIdStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		permissions, err := apiClient.GetPermissionsByResource(r.Context(), accessToken, resource.Id)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		// filter out the userinfo permission if the resource is authserver
		if resource.ResourceIdentifier == coreconstants.AuthServerResourceIdentifier {
			permissions = slices.DeleteFunc(permissions, func(p api.PermissionResponse) bool {
				return p.PermissionIdentifier == coreconstants.UserinfoPermissionIdentifier
			})
		}

		found := false
		for _, permission := range permissions {
			if permission.Id == permissionId {
				found = true
				break
			}
		}

		if !found {
			httpHelper.JsonError(w, r, errs.Errorf("permission %v does not belong to resource %v", permissionId, resource.Id))
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
			httpHelper.JsonError(w, r, errs.Errorf("group %v already has permission %v", group.Id, permissionId))
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
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
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

func HandleAdminResourceGroupsWithPermissionRemovePermissionPost(
	httpHelper handlers.HttpHelper,
	apiClient resourceGroupsWithPermissionAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}
		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}
		accessToken := jwtInfo.TokenResponse.AccessToken

		resource, err := apiClient.GetResourceById(r.Context(), accessToken, id)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}
		if resource == nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		groupIdStr := chi.URLParam(r, "groupId")
		if len(groupIdStr) == 0 {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		groupId, err := strconv.ParseInt(groupIdStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		group, currentPerms, err := apiClient.GetGroupPermissions(r.Context(), accessToken, groupId)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}
		if group == nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		permissionIdStr := chi.URLParam(r, "permissionId")
		if len(permissionIdStr) == 0 {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		permissionId, err := strconv.ParseInt(permissionIdStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		permissions, err := apiClient.GetPermissionsByResource(r.Context(), accessToken, resource.Id)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		// filter out the userinfo permission if the resource is authserver
		filteredPermissions := []api.PermissionResponse{}
		for idx, permission := range permissions {
			if permission.Resource.ResourceIdentifier == coreconstants.AuthServerResourceIdentifier {
				if permission.PermissionIdentifier != coreconstants.UserinfoPermissionIdentifier {
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
			httpHelper.JsonError(w, r, errs.Errorf("permission %v does not belong to resource %v", permissionId, resource.Id))
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
			httpHelper.JsonError(w, r, errs.Errorf("group %v does not have permission %v", group.Id, permissionId))
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
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
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

// no extra types
