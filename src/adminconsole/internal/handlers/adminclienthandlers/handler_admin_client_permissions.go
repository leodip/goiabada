package adminclienthandlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// clientPermissionsAPI is what the client permissions page needs: the resources to choose from,
// and the client's own set.
type clientPermissionsAPI interface {
	GetAllResources(ctx context.Context, accessToken string) ([]api.ResourceResponse, error)
	GetClientPermissions(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, []api.PermissionResponse, error)
	UpdateClientPermissions(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientPermissionsRequest) error
}

func HandleAdminClientPermissionsGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientPermissionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
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

		clientResp, perms, err := apiClient.GetClientPermissions(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			httpHelper.NotFound(w, r)
			return
		}

		adminClientPermissions := struct {
			ClientId                 int64
			ClientIdentifier         string
			ClientCredentialsEnabled bool
			Permissions              map[int64]string
			IsSystemLevelClient      bool
		}{
			ClientId:                 clientResp.Id,
			ClientIdentifier:         clientResp.ClientIdentifier,
			ClientCredentialsEnabled: clientResp.ClientCredentialsEnabled,
			Permissions:              make(map[int64]string),
			IsSystemLevelClient:      clientResp.IsSystemLevelClient,
		}
		for _, permission := range perms {
			adminClientPermissions.Permissions[permission.Id] = permission.Resource.ResourceIdentifier + ":" + permission.PermissionIdentifier
		}

		resources, err := apiClient.GetAllResources(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		sort.Slice(resources, func(i, j int) bool {
			return resources[i].ResourceIdentifier < resources[j].ResourceIdentifier
		})

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
			"client":            adminClientPermissions,
			"resources":         resources,
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_permissions.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminClientPermissionsPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientPermissionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

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

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Call Auth Server API to update client permissions
		req := &api.UpdateClientPermissionsRequest{
			PermissionIds:         data.AssignedPermissionsIds,
			ExpectedPermissionIds: data.ExpectedPermissionIds,
		}
		if updateClientPermissionsErr := apiClient.UpdateClientPermissions(r.Context(), jwtInfo.TokenResponse.AccessToken, data.ClientId, req); updateClientPermissionsErr != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, updateClientPermissionsErr)
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
