package httpmw

import (
	"net/http"
	"strings"
)

// StripTrailingSlash strips one trailing slash from the request's path before routing, so a route
// answers its path with one slash after it as it answers its path. A second slash stays, and that
// path matches nothing. "/" is left alone.
//
// It rewrites r.URL.Path, and r.URL.RawPath when the path carried an escape, so everything beneath
// it reads the stripped path off the request: the router, the body-limit and CSRF lookups, and the
// handlers. chi's StripSlashes, which it replaces, wrote the stripped path only to chi's routing
// context and left r.URL as it arrived (#462). The request logger above it has already rendered
// the target, so its record keeps the path the client sent.
//
// The request is edited in place rather than copied, so a middleware above it that reads the
// request after the handler has run reads the one that was routed.
func StripTrailingSlash(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if path := r.URL.Path; len(path) > 1 && strings.HasSuffix(path, "/") {
			r.URL.Path = path[:len(path)-1]
			r.URL.RawPath = strings.TrimSuffix(r.URL.RawPath, "/")
		}
		next.ServeHTTP(w, r)
	})
}
