package adminresourcehandlers

import (
    "fmt"
    "net/http"
    "strconv"

    "github.com/pkg/errors"

    "github.com/go-chi/chi/v5"
    "github.com/gorilla/csrf"
    "github.com/leodip/goiabada/adminconsole/internal/apiclient"
    "github.com/leodip/goiabada/adminconsole/internal/handlers"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/oauth"
)

func HandleAdminResourceDeleteGet(
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
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }

        resource, err := apiClient.GetResourceById(jwtInfo.TokenResponse.AccessToken, id)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }

        permissions, err := apiClient.GetPermissionsByResource(jwtInfo.TokenResponse.AccessToken, resource.Id)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }

		bind := map[string]interface{}{
			"resource":    resource,
			"permissions": permissions,
			"csrfField":   csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_delete.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminResourceDeletePost(
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
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }

        resource, err := apiClient.GetResourceById(jwtInfo.TokenResponse.AccessToken, id)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }

        permissions, err := apiClient.GetPermissionsByResource(jwtInfo.TokenResponse.AccessToken, resource.Id)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }

		renderError := func(message string) {
			bind := map[string]interface{}{
				"resource":    resource,
				"permissions": permissions,
				"error":       message,
				"csrfField":   csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_delete.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		resourceIdentifier := r.FormValue("resourceIdentifier")
		if len(resourceIdentifier) == 0 {
			renderError("Resource identifier is required.")
			return
		}

		if resource.ResourceIdentifier != resourceIdentifier {
			renderError("Resource identifier does not match the resource being deleted.")
			return
		}

        // Call API to delete the resource
        err = apiClient.DeleteResource(jwtInfo.TokenResponse.AccessToken, resource.Id)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }

		http.Redirect(w, r, fmt.Sprintf("%v/admin/resources", config.GetAdminConsole().BaseURL), http.StatusFound)
	}
}
