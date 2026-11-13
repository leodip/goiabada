package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

func HandleIndexGet(
	authHelper AuthHelper,
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	authServerBaseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{}

		// The notice HandleSessionEndedGet left. TakeFlash edits only the session in memory, and
		// the store reads the saved record again on the next request, so the session is saved
		// here or the notice would show on every visit.
		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		_, sessionEnded := sess.TakeFlash(r.URL.Path, flashSessionEnded)
		if sessionEnded {
			if err = httpSession.Save(r, w, sess); err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind["AuthServerBaseUrl"] = authServerBaseURL

		isAuthenticated := false
		loggedInUser := ""
		logoutLink := ""

		// The index is the one page mounted outside RequiresScope, so an absent token set is the
		// anonymous visitor rather than a fault.
		jwtInfo, signedIn := reqctx.JwtInfoFrom(r.Context())
		if signedIn {
			isAuthenticated = authHelper.IsAuthenticated(jwtInfo)
			if isAuthenticated {
				loggedInUser = jwtInfo.IdToken.StringClaim("email")
				logoutLink = "/auth/logout"
			}
		}

		// Your account and Administration start a sign-in for a browser not signed in. Its safe mode
		// lasts only this request, since nothing is stored before a sign-in (#620), so the links
		// carry it on, and the sign-in they start asks for it (#816 decision 2). A signed-in
		// session keeps it itself.
		accountLink, adminLink := "/account/profile", "/admin/clients"
		if !signedIn && reqctx.SafeModeFrom(r.Context()) {
			accountLink += "?" + oauthclient.SafeModeParameter + "=true"
			adminLink += "?" + oauthclient.SafeModeParameter + "=true"
		}
		bind["AccountLink"] = accountLink
		bind["AdminLink"] = adminLink

		bind["IsAuthenticated"] = isAuthenticated
		bind["LoggedInUser"] = loggedInUser
		bind["LogoutLink"] = logoutLink

		// The notice HandleSessionEndedGet sends in the query when the session's row was gone.
		// Anyone can link to it, so a signed-in visitor, whom it would tell their sign-in had
		// ended, is not shown it.
		if !isAuthenticated && r.URL.Query().Has(sessionEndedQuery) {
			sessionEnded = true
		}
		bind["SessionEnded"] = sessionEnded

		err = httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/index.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
