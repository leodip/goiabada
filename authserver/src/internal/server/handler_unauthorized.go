package server

import (
	"net/http"
)

func (s *Server) handleUnauthorizedGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{
			"_httpStatus": http.StatusUnauthorized,
		}

		err := s.renderTemplate(w, r, "/layouts/no_menu_layout.html", "/unauthorized.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}
