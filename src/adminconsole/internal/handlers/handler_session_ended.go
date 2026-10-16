package handlers

import (
	"log/slog"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/sessionstore"
)

// flashSessionEnded is the one-time notice HandleSessionEndedGet leaves for HandleIndexGet.
const flashSessionEnded = "sessionEnded"

// HandleSessionEndedGet signs the administrator out after the admin API refused the console's
// access token, and sends the browser home, where the notice says why (#427 decision 17).
//
// Only the token values go, the same two middleware.SessionHandler clears when it signs a session out, so
// the session survives to carry the notice. The home page is the destination because it does not
// require a sign-in: sending the browser to a page that does would start a sign-in the auth server
// may refuse again, and nothing here could then stop the loop.
//
// The route stays a GET because both of its callers navigate rather than submit: the API-error
// helpers answer an admin API 401 with a 302 here, and the page scripts follow with
// window.location, and neither can arrive as a POST. A GET that changes state is the exposure
// #411 closed on /auth/logout, so the state change here is guarded instead: a navigation the
// browser itself reports as beginning on another site is refused, which is the same evidence the
// origin check reads first on the unsafe methods beside it (httpmw.CSRF). A browser predating
// fetch metadata sends no Sec-Fetch-Site at all and is allowed through, the posture those POSTs
// keep; and a top-level navigation is the only cross-site shape that carries this console's Lax
// session cookie to a GET anyway (#408).
func HandleSessionEndedGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		if crossSiteNavigation(r) {
			// The same status and sentence httpmw.CSRF answers a cross-site POST with, from the
			// same catalog entry, so one refusal vocabulary covers both halves of #411. The
			// session is left exactly as the navigation found it: alive, tokens and all.
			http.Error(w, i18n.T(r.Context(), "error.csrf_refused"), http.StatusForbidden)
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, errs.Wrap(err, "unable to read the session"))
			return
		}

		delete(sess.Values, sessionkeys.JWT)
		delete(sess.Values, sessionkeys.JWTExpiresAt)
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

// crossSiteNavigation reports whether the browser itself says this request began on another
// site, which is the first thing net/http.CrossOriginProtection reads on the unsafe methods it
// guards. A GET has no such guard, so the one GET here that changes state asks the same
// question.
//
// "same-site" is refused beside "cross-site", mirroring the origin check's decision for a
// sibling subdomain; "none" is the address bar, and an absent header is a browser predating
// fetch metadata (2023), which sends nothing a legitimate navigation would not also send (#411).
func crossSiteNavigation(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "cross-site", "same-site":
		return true
	}
	return false
}
