package middleware

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// corsDatabase is what the CORS origin check needs: whether any client registered this origin.
type corsDatabase interface {
	WebOriginExists(ctx context.Context, tx *sql.Tx, origin string) (bool, error)
}

// corsAllowedMethods are the methods a cross-origin request may use. HEAD beside GET, because an
// actual request is answered only for a listed method, and the discovery document and JWKS answer
// HEAD as they answer GET (RFC 9110 section 9.3.2): left out, a cross-origin HEAD got their
// content's headers but no Access-Control-Allow-Origin. HEAD is a CORS-safelisted method (Fetch
// Standard section 2.2.1), so it never needs a preflight; the endpoints below that check an origin
// refuse it with 405 whatever this says. OPTIONS is allowed whatever the list says.
var corsAllowedMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodDelete, http.MethodOptions}

// corsAllowedHeaders are the request headers a preflight may ask for, in canonical form. Origin is
// among them because some browsers always ask for it.
var corsAllowedHeaders = []string{"Accept", "Authorization", "Content-Type", "X-Csrf-Token", "Origin"}

// corsMaxAge is how long, in seconds, a browser may cache a granted preflight: ten minutes. With
// none, every browser fell back to its own short default and re-preflighted constantly, each one
// paying for the origin lookup.
//
// Safe because a cached preflight only lets the browser skip the OPTIONS. The actual request still
// runs the origin check, which now answers false, so no Access-Control-Allow-Origin comes back and
// script still cannot read the response. A removed origin therefore bites immediately and the
// cached approval buys nothing (#250).
const corsMaxAge = 600

// CORS answers the cross-origin requests this server serves to a browser, as go-chi/cors v1.2.2
// answered them before this became the server's own (#462, #280).
//
// A preflight, an OPTIONS carrying Origin, even an empty one, and a non-empty
// Access-Control-Request-Method, is answered 200 here and never reaches a route. It always varies
// on the three request fields it reads, and grants only when the origin, the method and every
// requested header are allowed: then it names the origin, the one method asked for, the headers
// asked for, and corsMaxAge. Every other request goes on to its route, varying on Origin, and names
// its origin only when the request carries one that is allowed and its method is listed. Vary is
// always added to, never set, and before the route runs, so a Vary of the route's own stays beside
// it, and no answer carries Access-Control-Allow-Credentials.
func CORS(database corsDatabase) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, hasOrigin := r.Header["Origin"]
			if r.Method == http.MethodOptions && hasOrigin && r.Header.Get("Access-Control-Request-Method") != "" {
				answerPreflight(w, r, database)
				w.WriteHeader(http.StatusOK)
				return
			}

			w.Header().Add("Vary", "Origin")
			if hasOrigin {
				origin := r.Header.Get("Origin")
				// The origin first and the method after, as the library did, so a request by a
				// method outside the list still costs its lookup.
				if corsOriginAllowed(r, database, origin) && corsMethodAllowed(r.Method) {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// answerPreflight writes a preflight's header fields: the three Vary values always, and the grant
// when origin, method and headers are allowed, decided in that order.
func answerPreflight(w http.ResponseWriter, r *http.Request, database corsDatabase) {
	header := w.Header()
	header.Add("Vary", "Origin")
	header.Add("Vary", "Access-Control-Request-Method")
	header.Add("Vary", "Access-Control-Request-Headers")

	origin := r.Header.Get("Origin")
	if !corsOriginAllowed(r, database, origin) {
		return
	}
	method := r.Header.Get("Access-Control-Request-Method")
	if !corsMethodAllowed(method) {
		return
	}
	requested := corsRequestedHeaders(r.Header.Get("Access-Control-Request-Headers"))
	for _, name := range requested {
		if !slices.Contains(corsAllowedHeaders, name) {
			return
		}
	}

	header.Set("Access-Control-Allow-Origin", origin)
	// The method asked for is enough, since the list of methods could be unbounded, and so are the
	// headers asked for.
	header.Set("Access-Control-Allow-Methods", strings.ToUpper(method))
	if len(requested) > 0 {
		header.Set("Access-Control-Allow-Headers", strings.Join(requested, ", "))
	}
	header.Set("Access-Control-Max-Age", strconv.Itoa(corsMaxAge))
}

// corsMethodAllowed says whether a cross-origin request may use method, in any case.
func corsMethodAllowed(method string) bool {
	return slices.Contains(corsAllowedMethods, strings.ToUpper(method))
}

// corsRequestedHeaders splits an Access-Control-Request-Headers value on commas, spaces and tabs
// into canonical header names, in the order asked: RFC 9110 section 5.6.1 lets a list put optional
// whitespace, SP or HTAB, around each comma. A name that is not a valid token stays as sent, so it
// matches nothing allowed and the preflight is refused.
func corsRequestedHeaders(value string) []string {
	var names []string
	for _, name := range strings.FieldsFunc(value, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' }) {
		names = append(names, http.CanonicalHeaderKey(name))
	}
	return names
}

// corsOriginAllowed is the origin decision: which paths any origin may read, which a registered one
// may, and none elsewhere.
func corsOriginAllowed(r *http.Request, database corsDatabase, origin string) bool {
	// The trailing-slash strip runs below this middleware, so the slashed form of a covered path
	// routes but would not receive the same CORS decision without normalizing here (#335).
	switch strings.TrimSuffix(r.URL.Path, "/") {
	case "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server", "/certs":
		// Always allow both discovery addresses and the JWKS: they are public, and a client
		// running in a browser, an MCP client among them, reads them cross-origin (#576).
		return true
	case "/auth/token", "/auth/revoke", "/auth/logout", "/userinfo":
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
		exists, err := database.WebOriginExists(r.Context(), nil, origin)
		if err != nil {
			// Fail closed: an unreadable list is not an empty one, and answering true
			// here would let script on any origin read a token response.
			slog.ErrorContext(r.Context(), "unable to load the cors configuration", "error", err)
			return false
		}
		return exists
	}
	return false
}
