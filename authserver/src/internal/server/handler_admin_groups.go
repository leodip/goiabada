package server

import (
	"net/http"
)

func (s *Server) handleAdminGroupsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		groups, err := s.database.GetAllGroups(nil)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"groups": groups,
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}
