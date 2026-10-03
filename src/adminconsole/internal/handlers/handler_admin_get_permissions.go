package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// permissionsAPI is what the permissions lookup needs: the one read it answers with.
type permissionsAPI interface {
	GetPermissionsByResource(ctx context.Context, accessToken string, resourceId int64) ([]api.PermissionResponse, error)
}

func HandleAdminGetPermissionsGet(
	httpHelper HttpHelper,
	apiClient permissionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
			return
		}
		accessToken := jwtInfo.TokenResponse.AccessToken

		result := GetPermissionsResult{
			Permissions: []api.PermissionResponse{}, // Initialize with empty slice to avoid null
		}

		resourceIdStr := r.URL.Query().Get("resourceId")
		resourceId, err := strconv.ParseInt(resourceIdStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		// Get permissions via API client
		permissions, err := apiClient.GetPermissionsByResource(r.Context(), accessToken, resourceId)
		if err != nil {
			// The resource id goes into the message rather than into a record of its own. This
			// was the console's one caller-side error log, and it ran before the classifier: an
			// upstream 500 was written twice, and a 400, 404 or 409 that the classifier forwards
			// silently on purpose was still announced at ERROR. errors.As sees the
			// *apiclient.APIError through this wrap, so the forwarding is unaffected (#279).
			render.HandleAPIErrorJSON(httpHelper, w, r,
				errs.Wrapf(err, "unable to get the permissions of resource %d", resourceId))
			return
		}

		// Ensure permissions is never nil
		if permissions == nil {
			permissions = []api.PermissionResponse{}
		}

		result.Permissions = permissions
		httpHelper.EncodeJSON(w, r, result)
	}
}
