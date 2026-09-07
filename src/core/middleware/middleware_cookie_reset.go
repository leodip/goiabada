package middleware

import (
	"net/http"

	"github.com/leodip/goiabada/core/sessionstore"
)

// cookieNamer is implemented by a session store that knows what a previous implementation
// left behind in the browser, and what attributes a deletion has to carry to land.
//
// It is asserted rather than required because this middleware takes the sessionstore.Store
// interface, which says nothing about cookies: both modules now pass a ServerSideStore, but
// the parameter admits any store and the mock in this package's own tests is one. A store
// that does not implement this simply has no leftovers to declare, and the sweep does
// nothing (#266).
type cookieNamer interface {
	StaleCookieNames(logicalName string) []string
	DeletionCookie(name string) *http.Cookie
}

// MiddlewareCookieReset deletes whatever an earlier session store left in this browser,
// and takes the session once so the rest of the chain gets it for free.
//
// The first half is not housekeeping. The chunked cookie store split a session across up
// to fifty numbered cookies, and the only code that ever deleted them belonged to that
// store, so once a binary stops constructing it nothing names them again and they ride
// along in every request until their own expiry, which is a year on the admin console. A
// user would then see no improvement at all from the session moving to the server, which
// is the entire point of the change. This is the response-capable layer, so the deletion
// happens here, on first contact with a browser still carrying them (#266).
//
// The Get is kept although nothing here reads its result, and it is not a leftover: it is
// the first Get on the request, so it is what installs the per-request session cache that
// every later middleware and handler is answered from. Removing it would not change any
// answer, only the number of backend loads a request costs, which on the admin console is
// a number of HTTP round trips to the auth server (#269).
//
// It no longer acts on the error. An undecodable cookie is answered by the store with a
// fresh session and a nil error, deliberately, so the branch that cleared the cookie and
// redirected was reachable from nothing but a test that manufactured the old codec's error
// type through a mock. That type left with securecookie, and a store's only errors now are
// storage failures, which the middlewares downstream answer as 500 with the cause logged
// rather than by signing the visitor out (decision 11, #270).
func MiddlewareCookieReset(sessionStore sessionstore.Store, sessionName string) func(next http.Handler) http.Handler {
	namer, _ := sessionStore.(cookieNamer)

	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			deleteStaleCookies(w, r, namer, sessionName)

			_, _ = sessionStore.Get(r, sessionName)

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

// deleteStaleCookies emits one deletion per leftover cookie the request actually carries.
//
// Only the ones present, so an ordinary request writes no Set-Cookie at all: the browser
// drops them on the first response and never sends them again, which is what makes this
// first-contact rather than per-request. The store decides which names are safe to name,
// and on a plain http deployment that deliberately excludes the bare session name, since
// there the bare name IS the live cookie.
func deleteStaleCookies(w http.ResponseWriter, r *http.Request, namer cookieNamer, sessionName string) {
	if namer == nil {
		return
	}

	for _, name := range namer.StaleCookieNames(sessionName) {
		if _, err := r.Cookie(name); err != nil {
			continue
		}
		http.SetCookie(w, namer.DeletionCookie(name))
	}
}
