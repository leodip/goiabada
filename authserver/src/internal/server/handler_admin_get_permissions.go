package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/entities"
)

func (s *Server) handleAdminGetPermissionsGet() http.HandlerFunc {

	type getPermissionsResult struct {
		Permissions []entities.Permission
	}

	return func(w http.ResponseWriter, r *http.Request) {
		result := getPermissionsResult{}

		resourceIdStr := r.URL.Query().Get("resourceId")
		resourceId, err := strconv.ParseUint(resourceIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		permissions, err := s.database.GetPermissionsByResourceId(uint(resourceId))
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		// filter out the userinfo permission if the resource is authserver
		filteredPermissions := []entities.Permission{}
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
