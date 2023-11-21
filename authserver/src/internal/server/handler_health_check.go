package server

import "net/http"

func (s *Server) handleHealthCheckGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("healthy"))
	}
}
