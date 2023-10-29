package server

import (
	"net/http"
)

func (s *Server) handleAdminResourcesGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		resources, err := s.database.GetAllResources()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"resources": resources,
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}
