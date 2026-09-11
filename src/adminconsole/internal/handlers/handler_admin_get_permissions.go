package handlers

import (
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminGetPermissionsGet(
	httpHelper HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}
		accessToken := jwtInfo.TokenResponse.AccessToken

		result := GetPermissionsResult{
			Permissions: []models.Permission{}, // Initialize with empty slice to avoid null
		}

		resourceIdStr := r.URL.Query().Get("resourceId")
		resourceId, err := strconv.ParseInt(resourceIdStr, 10, 64)
		if err != nil {
			JsonNotFound(httpHelper, w, r)
			return
		}

		// Get permissions via API client
		permissions, err := apiClient.GetPermissionsByResource(accessToken, resourceId)
		if err != nil {
			// The resource id goes into the message rather than into a record of its own. This
			// was the console's one caller-side error log, and it ran before the classifier: an
			// upstream 500 was written twice, and a 400, 404 or 409 that the classifier forwards
			// silently on purpose was still announced at ERROR. errors.As sees the
			// *apiclient.APIError through this wrap, so the forwarding is unaffected (#279).
			HandleAPIErrorJson(httpHelper, w, r,
				errs.Wrapf(err, "unable to get the permissions of resource %d", resourceId))
			return
		}

		// Ensure permissions is never nil
		if permissions == nil {
			permissions = []models.Permission{}
		}

		result.Permissions = permissions
		httpHelper.EncodeJson(w, r, result)
	}
}
