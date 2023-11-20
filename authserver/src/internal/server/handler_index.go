package server

import "net/http"

func (s *Server) handleIndexGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{
			"_httpStatus": http.StatusNotFound,
		}

		err := s.renderTemplate(w, r, "/layouts/no_menu_layout.html", "/index.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}
