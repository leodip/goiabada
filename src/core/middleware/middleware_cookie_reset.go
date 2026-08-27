package middleware

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// cookieNamer is implemented by a session store that knows what its cookies are
// physically called, what a previous implementation left behind in the browser, and what
// attributes a deletion has to carry to land.
//
// It is asserted rather than required because this middleware takes the sessions.Store
// interface, which says nothing about cookies: both modules now pass a ServerSideStore, but
// the parameter admits any store and the mock in this package's own tests is one. A store
// that does not implement this gets the behaviour the middleware had before there was one to
// implement, which is the fallback below (#266).
type cookieNamer interface {
	CookieName(logicalName string) string
	StaleCookieNames(logicalName string) []string
	DeletionCookie(name string) *http.Cookie
}

// MiddlewareCookieReset clears the session cookie and redirects when it cannot be decoded,
// and deletes whatever an earlier session store left in this browser.
//
// The second half is not housekeeping. The chunked cookie store split a session across up
// to fifty numbered cookies, and the only code that ever deleted them belonged to that
// store, so once a binary stops constructing it nothing names them again and they ride
// along in every request until their own expiry, which is a year on the admin console. A
// user would then see no improvement at all from the session moving to the server, which
// is the entire point of the change. This is the response-capable layer, so the deletion
// happens here, on first contact with a browser still carrying them (#266).
func MiddlewareCookieReset(sessionStore sessions.Store, sessionName string) func(next http.Handler) http.Handler {
	namer, _ := sessionStore.(cookieNamer)

	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			deleteStaleCookies(w, r, namer, sessionName)

			_, err := sessionStore.Get(r, sessionName)
			if err != nil {
				multiErr, ok := err.(securecookie.MultiError)
				if ok && multiErr.IsDecode() {
					http.SetCookie(w, deletionCookie(namer, physicalName(namer, sessionName)))
					http.Redirect(w, r, r.RequestURI, http.StatusFound)
					return
				}
			}
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

// physicalName is what the browser calls the session cookie, which is not always what the
// application calls it: decision 11 gives it a __Host- prefix on https. A deletion naming
// the logical name there names a cookie the browser does not have.
func physicalName(namer cookieNamer, sessionName string) string {
	if namer == nil {
		return sessionName
	}
	return namer.CookieName(sessionName)
}

// deletionCookie is the store's own deletion when there is a store that can build one, and
// otherwise the shape this middleware used before there was: a past expiry, a negative
// Max-Age and the root path. The fallback carries no Secure attribute, which is correct
// for the unprefixed name it is deleting and would not be for a prefixed one, and that is
// exactly why a store that prefixes has to answer for its own cookies.
func deletionCookie(namer cookieNamer, name string) *http.Cookie {
	if namer != nil {
		return namer.DeletionCookie(name)
	}
	return &http.Cookie{
		Name:    name,
		Expires: time.Now().AddDate(0, 0, -1),
		MaxAge:  -1,
		Path:    "/",
	}
}
