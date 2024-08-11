package server

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/cors"
	"github.com/leodip/goiabada/adminconsole/internal/data"
)

func MiddlewareCors(database data.Database) func(next http.Handler) http.Handler {
	return cors.Handler(cors.Options{
		AllowOriginFunc: func(r *http.Request, origin string) bool {
			if r.URL.Path == "/.well-known/openid-configuration" || r.URL.Path == "/certs" {
				// always allow the discovery URL
				return true
			} else if r.URL.Path == "/auth/token" || r.URL.Path == "/auth/logout" || r.URL.Path == "/userinfo" {
				// allow when the web origin of the request matches a web origin in the database
				webOrigins, err := database.GetAllWebOrigins(nil)
				if err != nil {
					slog.Error(fmt.Sprintf("%+v", err))
					return false
				}
				for _, or := range webOrigins {
					if or.Origin == origin {
						return true
					}
				}
			}
			return false
		},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
	})
}
