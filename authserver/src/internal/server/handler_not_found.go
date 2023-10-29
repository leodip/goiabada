package server

import (
	"net/http"
)

func (s *Server) handleNotFoundGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{
			"_httpStatus": http.StatusNotFound,
		}

		err := s.renderTemplate(w, r, "/layouts/error_layout.html", "/not_found.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}
