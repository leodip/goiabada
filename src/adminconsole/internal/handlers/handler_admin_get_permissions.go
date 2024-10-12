package handlers

import (
	"net/http"
	"slices"
	"strconv"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

func HandleAdminGetPermissionsGet(
	httpHelper HttpHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		result := GetPermissionsResult{}

		resourceIdStr := r.URL.Query().Get("resourceId")
		resourceId, err := strconv.ParseInt(resourceIdStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		permissions, err := database.GetPermissionsByResourceId(nil, resourceId)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		err = database.PermissionsLoadResources(nil, permissions)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		// Filter out the userinfo permission if the resource is authserver
		if len(permissions) > 0 &&
			permissions[0].Resource.ResourceIdentifier == constants.AuthServerResourceIdentifier {
			permissions = slices.DeleteFunc(permissions, func(p models.Permission) bool {
				return p.PermissionIdentifier == constants.UserinfoPermissionIdentifier
			})
		}

		result.Permissions = permissions
		httpHelper.EncodeJson(w, r, result)
	}
}
