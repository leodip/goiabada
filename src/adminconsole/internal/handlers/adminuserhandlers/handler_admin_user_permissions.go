package adminuserhandlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// userPermissionsAPI is what the user permissions page needs: the resources to choose from, and
// the user's own set.
type userPermissionsAPI interface {
	GetAllResources(ctx context.Context, accessToken string) ([]api.ResourceResponse, error)
	GetUserPermissions(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, []api.PermissionResponse, error)
	UpdateUserPermissions(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserPermissionsRequest) error
}

func HandlePermissionsGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient userPermissionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}
		accessToken := jwtInfo.TokenResponse.AccessToken

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get user permissions via API
		user, userPermissions, err := apiClient.GetUserPermissions(r.Context(), accessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Create permission display map for template
		permissionDisplayMap := make(map[int64]string)
		for _, permission := range userPermissions {
			permissionDisplayMap[permission.Id] = permission.Resource.ResourceIdentifier + ":" + permission.PermissionIdentifier
		}

		// Get all resources via API
		resources, err := apiClient.GetAllResources(r.Context(), accessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// Resources are already sorted in the API response

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
			"user":              user,
			"userPermissions":   permissionDisplayMap,
			"resources":         resources,
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_permissions.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandlePermissionsPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient userPermissionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
			return
		}
		accessToken := jwtInfo.TokenResponse.AccessToken

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		var data PermissionsPostInput
		err = json.Unmarshal(body, &data)
		if err != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		// Convert to API request format
		request := &api.UpdateUserPermissionsRequest{
			PermissionIds:         data.AssignedPermissionsIds,
			ExpectedPermissionIds: data.ExpectedPermissionIds,
		}

		// Update user permissions via API (includes validation and audit logging)
		err = apiClient.UpdateUserPermissions(r.Context(), accessToken, id, request)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.JSONError(w, r, err)
			return
		}

		sess.SetFlash("savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.JSONError(w, r, err)
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
