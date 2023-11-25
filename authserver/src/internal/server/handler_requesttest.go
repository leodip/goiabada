package server

import (
	"encoding/json"
	"net"
	"net/http"
)

func (s *Server) handleRequestTestGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{
			"RemoteAddr": r.RemoteAddr,
			"RequestURI": r.RequestURI,
		}

		ipWithoutPort, _, _ := net.SplitHostPort(r.RemoteAddr)
		if len(ipWithoutPort) == 0 {
			ipWithoutPort = r.RemoteAddr
		}
		data["ipWithoutPort"] = ipWithoutPort

		// add all request headers to data
		for name, values := range r.Header {
			// Loop over all values for the name.
			for _, value := range values {
				data[name] = value
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		json.NewEncoder(w).Encode(data)
	}
}
