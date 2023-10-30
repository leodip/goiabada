package server

import (
	"encoding/json"
	"net/http"
	"strconv"

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
			s.internalServerError(w, r, err)
			return
		}

		permissions, err := s.database.GetResourcePermissions(uint(resourceId))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		result.Permissions = permissions
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
