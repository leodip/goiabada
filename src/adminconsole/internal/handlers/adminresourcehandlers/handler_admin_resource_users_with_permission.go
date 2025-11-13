package adminresourcehandlers

import (
    "fmt"
    "net/http"
    "slices"
    "strconv"
    "strings"

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

func HandleAdminResourceUsersWithPermissionGet(
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

        // Access token
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
        selectedPermission, err := strconv.ParseInt(selectedPermissionStr, 10, 64)
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
        var usersWithPermission []models.User
        var total int
        if selectedPermission > 0 {
            usersWithPermission, total, err = apiClient.GetUsersByPermission(accessToken, selectedPermission, pageInt, pageSize)
            if err != nil {
                httpHelper.InternalServerError(w, r, err)
                return
            }
        }

        pageResult := UsersWithPermissionPageResult{
            Page:     pageInt,
            PageSize: pageSize,
            Total:    total,
            Users:    usersWithPermission,
        }

        p := paginater.New(total, pageSize, pageInt, 5)

        sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
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

        err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_users_with_permission.html", bind)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }
    }
}

func HandleAdminResourceUsersWithPermissionRemovePermissionPost(
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

        user, currentPerms, err := apiClient.GetUserPermissions(accessToken, userId)
        if err != nil {
            httpHelper.JsonError(w, r, err)
            return
        }
        if user == nil {
            httpHelper.JsonError(w, r, errors.WithStack(errors.New("user not found")))
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
        if !found {
            httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("user %v does not have permission %v", user.Id, permissionId)))
            return
        }

        // Build reduced set and update via API
        newIds := make([]int64, 0, len(currentPerms))
        for _, p := range currentPerms {
            if p.Id != permissionId {
                newIds = append(newIds, p.Id)
            }
        }
        apiReq := &api.UpdateUserPermissionsRequest{PermissionIds: newIds}
        if err := apiClient.UpdateUserPermissions(accessToken, user.Id, apiReq); err != nil {
            httpHelper.JsonError(w, r, err)
            return
        }

        result := struct{ Success bool }{Success: true}
        httpHelper.EncodeJson(w, r, result)
    }
}

func HandleAdminResourceUsersWithPermissionAddGet(
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

        selectedPermissionStr := chi.URLParam(r, "permissionId")
        if len(selectedPermissionStr) == 0 {
            if len(permissions) > 0 {
                selectedPermissionStr = strconv.FormatInt(permissions[0].Id, 10)
            } else {
                selectedPermissionStr = "0"
            }
        }
        selectedPermission, err := strconv.ParseInt(selectedPermissionStr, 10, 64)
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
    apiClient apiclient.ApiClient,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        result := SearchResult{}

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

        selectedPermissionStr := chi.URLParam(r, "permissionId")
        if len(selectedPermissionStr) == 0 {
            if len(permissions) > 0 {
                selectedPermissionStr = strconv.FormatInt(permissions[0].Id, 10)
            } else {
                selectedPermissionStr = "0"
            }
        }
        selectedPermission, err := strconv.ParseInt(selectedPermissionStr, 10, 64)
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

        annotatedUsers, _, err := apiClient.SearchUsersWithPermissionAnnotation(accessToken, selectedPermission, query, 1, 15)
        if err != nil {
            httpHelper.JsonError(w, r, err)
            return
        }
        usersResult := make([]UserResult, 0, len(annotatedUsers))
        for _, u := range annotatedUsers {
            usersResult = append(usersResult, UserResult{
                Id:            u.Id,
                Subject:       u.Subject.String(),
                Username:      u.Username,
                Email:         u.Email,
                GivenName:     u.GivenName,
                MiddleName:    u.MiddleName,
                FamilyName:    u.FamilyName,
                HasPermission: u.HasPermission,
            })
        }
        result.Users = usersResult
        httpHelper.EncodeJson(w, r, result)
    }
}

func HandleAdminResourceUsersWithPermissionAddPermissionPost(
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

        user, currentPerms, err := apiClient.GetUserPermissions(accessToken, userId)
        if err != nil {
            httpHelper.JsonError(w, r, err)
            return
        }
        if user == nil {
            httpHelper.JsonError(w, r, errors.WithStack(errors.New("user not found")))
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
            // build filtered list similar to groups handler to be safe
            filtered := []models.Permission{}
            for _, p := range permissions {
                if p.Resource.ResourceIdentifier == constants.AuthServerResourceIdentifier {
                    if p.PermissionIdentifier != constants.UserinfoPermissionIdentifier {
                        filtered = append(filtered, p)
                    }
                } else {
                    filtered = append(filtered, p)
                }
            }
            permissions = filtered
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

        for _, permission := range currentPerms {
            if permission.Id == permissionId {
                httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("user %v already has permission %v", user.Id, permissionId)))
                return
            }
        }

        newIds := make([]int64, 0, len(currentPerms)+1)
        for _, p := range currentPerms { newIds = append(newIds, p.Id) }
        newIds = append(newIds, permissionId)
        apiReq := &api.UpdateUserPermissionsRequest{PermissionIds: newIds}
        if err := apiClient.UpdateUserPermissions(accessToken, user.Id, apiReq); err != nil {
            httpHelper.JsonError(w, r, err)
            return
        }

        result := struct{ Success bool }{Success: true}
        httpHelper.EncodeJson(w, r, result)
    }
}

