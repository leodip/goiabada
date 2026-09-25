package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/sessionstore"
)

func HandleIndexGet(
	authHelper AuthHelper,
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{}

		// The notice HandleSessionEndedGet left. TakeFlash edits only the session in memory, and
		// the store reads the saved record again on the next request, so the session is saved
		// here or the notice would show on every visit.
		sess, err := httpSession.Get(r, coreconstants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		_, sessionEnded := sess.TakeFlash(flashSessionEnded)
		if sessionEnded {
			if err = httpSession.Save(r, w, sess); err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}
		bind["SessionEnded"] = sessionEnded

		bind["AuthServerBaseUrl"] = config.GetAuthServer().BaseURL

		isAuthenticated := false
		loggedInUser := ""
		logoutLink := ""

		var jwtInfo oauthclient.JwtInfo
		var ok bool
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo, ok = r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
			if ok {
				isAuthenticated = authHelper.IsAuthenticated(jwtInfo)
				if isAuthenticated {
					loggedInUser = jwtInfo.IdToken.GetStringClaim("email")
					logoutLink = "/auth/logout"
				}
			}
		}

		bind["IsAuthenticated"] = isAuthenticated
		bind["LoggedInUser"] = loggedInUser
		bind["LogoutLink"] = logoutLink

		err = httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/index.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
