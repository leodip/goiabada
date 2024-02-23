package server

import (
	"net/http"
)

func (s *Server) handleAdminClientsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		clients, err := s.database.GetAllClients(nil)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"clients": clients,
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}
