package server

import (
	"net/http"
)

func (s *Server) handleUnauthorizedGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{}

		err := s.renderTemplate(w, r, "/layouts/error_layout.html", "/unauthorized.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}
