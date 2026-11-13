package middleware

import (
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
)

// SafeMode puts on the request whether it is in safe mode, which draws its page from the brand's safe
// stylesheets and makes every authorization request it sends ask for safe mode (#816 decision 2). It
// is mounted in each chain right after SessionHandler, which says whether anyone is signed in, and
// before RequiresScope, whose sign-in must carry it.
//
// A signed-in console session is in safe mode while its session holds sessionkeys.SafeMode, which the
// callback writes for a sign-in that asked for it. goiabada_safe_mode=true on a console URL turns it
// on for a signed-in session at once, saved for every later page, and for a browser not signed in
// draws that request in safe mode, so the sign-in it starts asks for it and the callback keeps it.
// Nothing is written for a browser not signed in: the console writes no session row before a
// sign-in (#620).
//
// It lasts until the session is signed out. A session whose tokens are gone, by the sign-out or by
// SessionHandler, is not in safe mode whatever it still holds, and the next sign-in writes the value
// afresh.
func SafeMode(sessions sessionstore.Store, sessionName string, errorRenderer ServerErrorRenderer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A console URL takes the authorization request's parameter, read as the auth server
			// reads it: only true turns it on, and any other value is absent (#816 decision 3).
			asked := r.URL.Query().Get(oauthclient.SafeModeParameter) == "true"
			on := asked
			if _, signedIn := reqctx.JwtInfoFrom(r.Context()); signedIn {
				sess, err := sessions.Get(r, sessionName)
				if err != nil {
					errorRenderer.InternalServerError(w, r, errs.Wrap(err, "unable to get the session"))
					return
				}
				kept, _ := sess.Values[sessionkeys.SafeMode].(bool)
				if asked && !kept {
					sess.Values[sessionkeys.SafeMode] = true
					if err := sessions.Save(r, w, sess); err != nil {
						errorRenderer.InternalServerError(w, r, errs.Wrap(err, "unable to save the session"))
						return
					}
				}
				on = asked || kept
			}
			next.ServeHTTP(w, r.WithContext(reqctx.WithSafeMode(r.Context(), on)))
		})
	}
}
