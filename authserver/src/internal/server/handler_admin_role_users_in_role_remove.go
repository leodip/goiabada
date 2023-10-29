package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

func (s *Server) handleAdminRoleUsersInRoleRemoveUserPost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "roleId")
		if len(idStr) == 0 {
			s.jsonError(w, r, errors.New("roleId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		role, err := s.database.GetRoleById(uint(id))
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if role == nil {
			s.jsonError(w, r, errors.New("role not found"))
			return
		}

		userIdStr := chi.URLParam(r, "userId")
		if len(userIdStr) == 0 {
			s.jsonError(w, r, errors.New("userId is required"))
			return
		}

		userId, err := strconv.ParseUint(userIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		user, err := s.database.GetUserById(uint(userId))
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if user == nil {
			s.jsonError(w, r, errors.New("user not found"))
			return
		}

		err = s.database.RemoveUserFromRole(user, role)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		result := struct {
			Success bool
		}{
			Success: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
