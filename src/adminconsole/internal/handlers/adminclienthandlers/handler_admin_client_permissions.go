package adminclienthandlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
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
	httpHelper handlers.HttpHelper,
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
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		clientResp, perms, err := apiClient.GetClientPermissions(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
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
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		sort.Slice(resources, func(i, j int) bool {
			return resources[i].ResourceIdentifier < resources[j].ResourceIdentifier
		})

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
	httpHelper handlers.HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientPermissionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		body, err := io.ReadAll(r.Body)
		if err != nil {
			handlers.JsonBadRequestBody(httpHelper, w, r)
			return
		}

		var data PermissionsPostInput
		err = json.Unmarshal(body, &data)
		if err != nil {
			handlers.JsonBadRequestBody(httpHelper, w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Call Auth Server API to update client permissions
		req := &api.UpdateClientPermissionsRequest{PermissionIds: data.AssignedPermissionsIds}
		if err := apiClient.UpdateClientPermissions(r.Context(), jwtInfo.TokenResponse.AccessToken, data.ClientId, req); err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		sess, err := httpSession.Get(r, coreconstants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		sess.SetFlash("savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
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
