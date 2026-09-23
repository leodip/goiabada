package adminresourcehandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// resourceDeleteAPI is what the resource delete page needs: the resource, the permissions it
// warns about, and the delete.
type resourceDeleteAPI interface {
	DeleteResource(ctx context.Context, accessToken string, resourceId int64) error
	GetPermissionsByResource(ctx context.Context, accessToken string, resourceId int64) ([]api.PermissionResponse, error)
	GetResourceById(ctx context.Context, accessToken string, resourceId int64) (*api.ResourceResponse, error)
}

func HandleAdminResourceDeleteGet(
	httpHelper handlers.HttpHelper,
	apiClient resourceDeleteAPI,
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

		resource, err := apiClient.GetResourceById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		permissions, err := apiClient.GetPermissionsByResource(r.Context(), jwtInfo.TokenResponse.AccessToken, resource.Id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"resource":              resource,
			"permissions":           permissions,
			"isSystemLevelResource": resource.IsSystemLevelResource,
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
	apiClient resourceDeleteAPI,
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

		resource, err := apiClient.GetResourceById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		permissions, err := apiClient.GetPermissionsByResource(r.Context(), jwtInfo.TokenResponse.AccessToken, resource.Id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"resource":              resource,
				"permissions":           permissions,
				"isSystemLevelResource": resource.IsSystemLevelResource,
				"error":                 message,
			}

			renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_delete.html", bind)
			if renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		// System-level resource protection: block deletion
		if resource.IsSystemLevelResource {
			renderError("System-level resources cannot be deleted.")
			return
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
		err = apiClient.DeleteResource(r.Context(), jwtInfo.TokenResponse.AccessToken, resource.Id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/resources", config.GetAdminConsole().BaseURL), http.StatusFound)
	}
}
