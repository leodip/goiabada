package middleware

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/reqctx"
)

// BrandSafeMode draws every page the server answers in safe mode while the operator's switch,
// GOIABADA_AUTHSERVER_BRAND_SAFE_MODE, is on: each request carries it (reqctx.WithBrandSafeMode), so a
// page links its brand's safe stylesheets, and the public settings say so and publish the safe links
// as the brand's own (#816 decision 3). Off, it hands the request on untouched.
//
// It is mounted at the root, ahead of everything that can draw a page, so a fault's page and the
// not-found page are drawn safe too. It is mounted whether or not the switch is on, so the chain has
// one shape either way.
func BrandSafeMode(enabled bool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if !enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(reqctx.WithBrandSafeMode(r.Context())))
		})
	}
}
