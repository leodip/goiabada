package adminresourcehandlers

import (
    "fmt"
    "net/http"
    "slices"
    "strconv"

    "github.com/pkg/errors"

    "github.com/go-chi/chi/v5"
    "github.com/gorilla/csrf"
    "github.com/gorilla/sessions"
    "github.com/leodip/goiabada/adminconsole/internal/apiclient"
    "github.com/leodip/goiabada/adminconsole/internal/handlers"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/models"
    "github.com/leodip/goiabada/core/oauth"
    "github.com/unknwon/paginater"
)

func HandleAdminResourceGroupsWithPermissionGet(
    httpHelper handlers.HttpHelper,
    httpSession sessions.Store,
    apiClient apiclient.ApiClient,
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
        // Get JWT info from context to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }
        accessToken := jwtInfo.TokenResponse.AccessToken

        resource, err := apiClient.GetResourceById(accessToken, id)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }
        if resource == nil {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("resource not found")))
            return
        }

        permissions, err := apiClient.GetPermissionsByResource(accessToken, resource.Id)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }

        // filter out the userinfo permission if the resource is authserver
        if resource.ResourceIdentifier == constants.AuthServerResourceIdentifier {
            permissions = slices.DeleteFunc(permissions, func(p models.Permission) bool {
                return p.PermissionIdentifier == constants.UserinfoPermissionIdentifier
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
        var (
            total int
            groupInfoArr []GroupInfo
        )
        if selectedPermission == 0 {
            // No permissions in resource; paginate groups client-side and mark all as false
            allGroups, err := apiClient.GetAllGroups(accessToken)
            if err != nil {
                httpHelper.InternalServerError(w, r, err)
                return
            }
            total = len(allGroups)
            start := (pageInt-1)*pageSize
            if start > total { start = total }
            end := start + pageSize
            if end > total { end = total }
            pageGroups := allGroups[start:end]
            groupInfoArr = make([]GroupInfo, len(pageGroups))
            for i, g := range pageGroups {
                groupInfoArr[i] = GroupInfo{ Id: g.Id, GroupIdentifier: g.GroupIdentifier, Description: g.Description, HasPermission: false }
            }
        } else {
            annotatedGroups, total2, err := apiClient.SearchGroupsWithPermissionAnnotation(accessToken, selectedPermission, pageInt, pageSize)
            if err != nil {
                httpHelper.InternalServerError(w, r, err)
                return
            }
            total = total2
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

        pageResult := GroupsWithPermissionPageResult{ Page: pageInt, PageSize: pageSize, Total: total, Groups: groupInfoArr }
        p := paginater.New(total, pageSize, pageInt, 5)

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
    apiClient apiclient.ApiClient,
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
        // Get JWT info from context to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.JsonError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }
        accessToken := jwtInfo.TokenResponse.AccessToken

        resource, err := apiClient.GetResourceById(accessToken, id)
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

        group, currentPerms, err := apiClient.GetGroupPermissions(accessToken, groupId)
        if err != nil {
            httpHelper.JsonError(w, r, err)
            return
        }
        if group == nil {
            httpHelper.JsonError(w, r, errors.WithStack(errors.New("group not found")))
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

        permissions, err := apiClient.GetPermissionsByResource(accessToken, resource.Id)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }

        // filter out the userinfo permission if the resource is authserver
        if resource.ResourceIdentifier == constants.AuthServerResourceIdentifier {
            permissions = slices.DeleteFunc(permissions, func(p models.Permission) bool {
                return p.PermissionIdentifier == constants.UserinfoPermissionIdentifier
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
			httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("permission %v does not belong to resource %v", permissionId, resource.Id)))
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
            httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("group %v already has permission %v", group.Id, permissionId)))
            return
        }
        // Build the new set and update via API
        newIds := make([]int64, 0, len(currentPerms)+1)
        for _, p := range currentPerms { newIds = append(newIds, p.Id) }
        newIds = append(newIds, permissionId)

        req := &api.UpdateGroupPermissionsRequest{PermissionIds: newIds}
        if err := apiClient.UpdateGroupPermissions(accessToken, group.Id, req); err != nil {
            // Provide clean error to UI if API returned structured error
            if apiErr, ok := err.(*apiclient.APIError); ok {
                httpHelper.JsonError(w, r, fmt.Errorf("%s", apiErr.Message))
                return
            }
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

func HandleAdminResourceGroupsWithPermissionRemovePermissionPost(
    httpHelper handlers.HttpHelper,
    apiClient apiclient.ApiClient,
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
        // Get JWT info from context to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.JsonError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }
        accessToken := jwtInfo.TokenResponse.AccessToken

        resource, err := apiClient.GetResourceById(accessToken, id)
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

        group, currentPerms, err := apiClient.GetGroupPermissions(accessToken, groupId)
        if err != nil {
            httpHelper.JsonError(w, r, err)
            return
        }
        if group == nil {
            httpHelper.JsonError(w, r, errors.WithStack(errors.New("group not found")))
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

        permissions, err := apiClient.GetPermissionsByResource(accessToken, resource.Id)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
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
        for _, permission := range currentPerms {
            if permission.Id == permissionId {
                found = true
                break
            }
        }

        if !found {
            httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("group %v does not have permission %v", group.Id, permissionId)))
            return
        }
        // Build reduced set and update via API
        newIds := make([]int64, 0, len(currentPerms))
        for _, p := range currentPerms {
            if p.Id != permissionId {
                newIds = append(newIds, p.Id)
            }
        }
        req := &api.UpdateGroupPermissionsRequest{PermissionIds: newIds}
        if err := apiClient.UpdateGroupPermissions(accessToken, group.Id, req); err != nil {
            if apiErr, ok := err.(*apiclient.APIError); ok {
                httpHelper.JsonError(w, r, fmt.Errorf("%s", apiErr.Message))
                return
            }
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

// no extra types
