package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/web"
)

func HandleOpenAPIGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(web.OpenAPISpec())
	}
}
