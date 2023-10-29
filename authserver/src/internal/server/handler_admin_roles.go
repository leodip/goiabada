package server

import (
	"net/http"
)

func (s *Server) handleAdminRolesGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		roles, err := s.database.GetAllRoles()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"roles": roles,
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_roles.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}
