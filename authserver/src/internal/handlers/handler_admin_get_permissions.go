package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/models"
)

func HandleAdminGetPermissionsGet(
	httpHelper HttpHelper,
	database data.Database,
) http.HandlerFunc {

	type getPermissionsResult struct {
		Permissions []models.Permission
	}

	return func(w http.ResponseWriter, r *http.Request) {
		result := getPermissionsResult{}

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

		// filter out the userinfo permission if the resource is authserver
		filteredPermissions := []models.Permission{}
		for idx, permission := range permissions {
			if permission.Resource.ResourceIdentifier == constants.AuthServerResourceIdentifier {
				if permission.PermissionIdentifier != constants.UserinfoPermissionIdentifier {
					filteredPermissions = append(filteredPermissions, permissions[idx])
				}
			} else {
				filteredPermissions = append(filteredPermissions, permissions[idx])
			}
		}
		permissions = filteredPermissions

		result.Permissions = permissions
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
