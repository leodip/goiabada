package middleware

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/cors"
	"github.com/leodip/goiabada/core/data"
)

func MiddlewareCors(database data.Database) func(next http.Handler) http.Handler {
	return cors.Handler(cors.Options{
		AllowOriginFunc: func(r *http.Request, origin string) bool {
			switch r.URL.Path {
			case "/.well-known/openid-configuration", "/certs":
				// always allow the discovery URL
				return true
			case "/auth/token", "/auth/logout", "/userinfo":
				// Allow when any client has registered this origin. An index lookup, on the
				// UNIQUE (origin, client_id) migration 000034 adds, rather than the whole-table
				// scan this used to perform on every CORS-checked request with no cache (#250).
				//
				// Server-wide rather than per-client on purpose, and the schema's client_id is a
				// label recording which app an origin was registered for. Per the Fetch Standard
				// section 4.8 a CORS-preflight fetch is "a new request" carrying neither the
				// original header list nor its body, so a preflight for GET /userinfo arrives
				// with no Authorization header and one for POST /auth/token with no form body:
				// no client identity is available at preflight time and per-client enforcement
				// is not implementable here. The admin console and the docs say so rather than
				// implying a scoping the server cannot honour.
				exists, err := database.WebOriginExists(nil, origin)
				if err != nil {
					// Fail closed: an unreadable list is not an empty one, and answering true
					// here would let script on any origin read a token response.
					slog.Error(fmt.Sprintf("%+v", err))
					return false
				}
				return exists
			}
			return false
		},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowedMethods: []string{"GET", "POST", "DELETE", "OPTIONS"},
		// Ten minutes. cors@v1.2.2 emits Access-Control-Max-Age only when maxAge > 0, so with
		// no value set every browser fell back to its own short default and re-preflighted
		// constantly, each one paying for the lookup above.
		//
		// Safe because a cached preflight only lets the browser skip the OPTIONS. The actual
		// request still runs AllowOriginFunc, which now answers false, so no
		// Access-Control-Allow-Origin comes back and script still cannot read the response. A
		// removed origin therefore bites immediately and the cached approval buys nothing (#250).
		MaxAge: 600,
	})
}
