package handlers

import (
	"log/slog"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/constants"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
)

// flashSessionEnded is the one-time notice HandleSessionEndedGet leaves for HandleIndexGet.
const flashSessionEnded = "sessionEnded"

// HandleSessionEndedGet signs the administrator out after the admin API refused the console's
// access token, and sends the browser home, where the notice says why (#427 decision 17).
//
// Only the token values go, the same two JwtSessionHandler clears when it signs a session out, so
// the session survives to carry the notice. The home page is the destination because it does not
// require a sign-in: sending the browser to a page that does would start a sign-in the auth server
// may refuse again, and nothing here could then stop the loop.
//
// A GET that changes state, the same exposure /auth/logout already has: a cross-site link can sign
// an administrator out, and nothing more.
func HandleSessionEndedGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := httpSession.Get(r, coreconstants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, errs.Wrap(err, "unable to read the session"))
			return
		}

		delete(sess.Values, constants.SessionKeyJwt)
		delete(sess.Values, constants.SessionKeyJwtExpiresAt)
		sess.SetFlash(flashSessionEnded, "true")
		if err = httpSession.Save(r, w, sess); err != nil {
			httpHelper.InternalServerError(w, r, errs.Wrap(err, "unable to save the session"))
			return
		}

		// Warn: a refusal met and handled. The admin API's own record says which of its checks
		// refused the token; this one says the console signed the administrator out for it.
		slog.WarnContext(r.Context(), "the admin api refused the access token, signing the session out")
		http.Redirect(w, r, "/", http.StatusFound)
	}
}
