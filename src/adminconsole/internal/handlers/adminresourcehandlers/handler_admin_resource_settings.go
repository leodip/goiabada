package adminresourcehandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/handlerhelpers"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// resourceSettingsAPI is what the resource settings page needs: the resource, and the write.
type resourceSettingsAPI interface {
	GetResourceById(ctx context.Context, accessToken string, resourceId int64) (*api.ResourceResponse, error)
	UpdateResource(ctx context.Context, accessToken string, resourceId int64, request *api.UpdateResourceRequest) (*api.ResourceResponse, error)
}

func HandleAdminResourceSettingsGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient resourceSettingsAPI,
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
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		resource, err := apiClient.GetResourceById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlerhelpers.HandleAPIError(httpHelper, w, r, err)
			return
		}

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
			"resourceId":            resource.Id,
			"resourceIdentifier":    resource.ResourceIdentifier,
			"description":           resource.Description,
			"isSystemLevelResource": resource.IsSystemLevelResource,
			"savedSuccessfully":     savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_settings.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminResourceSettingsPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient resourceSettingsAPI,
	baseURL string,
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
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Get resource to determine if it's system-level
		resource, err := apiClient.GetResourceById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlerhelpers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		isSystemLevelResource := resource.IsSystemLevelResource

		resourceIdentifier := r.FormValue("resourceIdentifier")
		description := r.FormValue("description")

		renderError := func(message string) {
			bind := map[string]interface{}{
				"resourceId":            id,
				"resourceIdentifier":    resourceIdentifier,
				"description":           description,
				"isSystemLevelResource": isSystemLevelResource,
				"error":                 message,
			}

			renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_settings.html", bind)
			if renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		// Build API request
		req := &api.UpdateResourceRequest{
			ResourceIdentifier: strings.TrimSpace(resourceIdentifier),
			Description:        strings.TrimSpace(description),
		}

		// Call API
		_, err = apiClient.UpdateResource(r.Context(), jwtInfo.TokenResponse.AccessToken, id, req)
		if err != nil {
			handlerhelpers.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.SetFlash("savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/resources/%v/settings", baseURL, id), http.StatusFound)
	}
}
