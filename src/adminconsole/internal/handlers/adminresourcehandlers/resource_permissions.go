package adminresourcehandlers

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// errNoSuchResource is what loadResourcePermissions hands back when the URL names no resource: a
// resourceId that is absent or does not parse, or one the API answered with no row. Each caller
// answers it with the 404 of the writer family its route answers with.
var errNoSuchResource = errors.New("the URL names no resource")

// resourceAndPermissionsReader is the two reads every users-with-permission and
// groups-with-permission handler starts from.
type resourceAndPermissionsReader interface {
	GetResourceById(ctx context.Context, accessToken string, resourceId int64) (*api.ResourceResponse, error)
	GetPermissionsByResource(ctx context.Context, accessToken string, resourceId int64) ([]api.PermissionResponse, error)
}

// resourcePermissions is what those handlers read before anything of their own: the resource the
// URL names, the permissions it holds, and the access token the rest of the handler reads with.
type resourcePermissions struct {
	resource    *api.ResourceResponse
	permissions []api.PermissionResponse
	accessToken string
}

// loadResourcePermissions is the preamble the eight handlers in the users-with-permission and
// groups-with-permission files used to repeat (#440). It writes no response: it hands back
// errNoSuchResource, reqctx.ErrNoJwtInfo or the API's error, and each caller answers it through
// its own writers, so a JSON handler's every branch is still visibly JSON.
func loadResourcePermissions(r *http.Request, apiClient resourceAndPermissionsReader) (resourcePermissions, error) {
	resourceId, err := strconv.ParseInt(chi.URLParam(r, "resourceId"), 10, 64)
	if err != nil {
		return resourcePermissions{}, errNoSuchResource
	}

	jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
	if !ok {
		return resourcePermissions{}, reqctx.ErrNoJwtInfo
	}
	accessToken := jwtInfo.TokenResponse.AccessToken

	resource, err := apiClient.GetResourceById(r.Context(), accessToken, resourceId)
	if err != nil {
		return resourcePermissions{}, err
	}
	if resource == nil {
		return resourcePermissions{}, errNoSuchResource
	}

	permissions, err := apiClient.GetPermissionsByResource(r.Context(), accessToken, resource.Id)
	if err != nil {
		return resourcePermissions{}, err
	}

	return resourcePermissions{resource: resource, permissions: permissions, accessToken: accessToken}, nil
}
