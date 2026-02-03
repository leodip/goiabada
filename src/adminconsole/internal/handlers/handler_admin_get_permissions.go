package handlers

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/constants"
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
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}
		accessToken := jwtInfo.TokenResponse.AccessToken

		result := GetPermissionsResult{
			Permissions: []models.Permission{}, // Initialize with empty slice to avoid null
		}

		resourceIdStr := r.URL.Query().Get("resourceId")
		resourceId, err := strconv.ParseInt(resourceIdStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		// Get permissions via API client
		permissions, err := apiClient.GetPermissionsByResource(accessToken, resourceId)
		if err != nil {
			slog.Error("Admin Console: Error getting permissions from API", "error", err, "resourceId", resourceId)
			httpHelper.JsonError(w, r, err)
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
