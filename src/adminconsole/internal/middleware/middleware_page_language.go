package middleware

import (
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/sessionstore"
)

// sessionReader is the part of the session store PageLanguage reads through: the request's own
// session, which the store loads once per request and SessionHandler has already loaded (#269).
type sessionReader interface {
	Get(r *http.Request, name string) (*sessionstore.Session, error)
}

// PageLanguage draws a signed-in user's pages in their page language: the console's copy of it,
// which the sign-in reads from the Account API and the profile page keeps current
// (sessionkeys.PageLanguage). It is the console's half of #631 decision 7, mounted in each
// authenticated chain right after SessionHandler, which says whether anyone is signed in.
//
// A chosen language wins over everything the locale middleware resolved, ?ui_locales and the
// browser's Accept-Language (decision 4). Automatic, or a tag the console has no catalog for, leaves
// that resolution standing, which is what the auth server's pages do too; the ID token's locale
// claim, Language and region, steers no console page (decision 2). i18n.WithPageLanguage decides
// both.
//
// Nothing is applied to a request with no signed-in user, though its session may still hold a copy,
// as one signed out by SessionHandler does: the copy is the signed-in user's. A session that cannot
// be read is SessionHandler's to answer, and it has, since the store answers this request's Get
// from the same load, so it is not answered twice here.
func PageLanguage(sessions sessionReader, sessionName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, signedIn := reqctx.JwtInfoFrom(r.Context()); signedIn {
				if sess, err := sessions.Get(r, sessionName); err == nil {
					if pageLanguage, _ := sess.Values[sessionkeys.PageLanguage].(string); pageLanguage != "" {
						r = r.WithContext(i18n.WithPageLanguage(r.Context(), pageLanguage))
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
