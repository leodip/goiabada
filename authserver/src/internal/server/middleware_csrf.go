package server

import (
	"net/http"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func MiddlewareSkipCsrf() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			skip := false
			if strings.HasPrefix(r.URL.Path, "/static") ||
				strings.HasPrefix(r.URL.Path, "/userinfo") ||
				strings.HasPrefix(r.URL.Path, "/auth/token") ||
				strings.HasPrefix(r.URL.Path, "/auth/callback") {
				skip = true
			}
			if skip {
				r = csrf.UnsafeSkipCheck(r)
			}
			next.ServeHTTP(w, r.WithContext(r.Context()))
		}
		return http.HandlerFunc(fn)
	}
}

func MiddlewareCsrf(settings *entities.Settings) func(next http.Handler) http.Handler {
	return csrf.Protect(settings.SessionAuthenticationKey, csrf.Secure(lib.IsHttpsEnabled()))
}
