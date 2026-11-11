package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// indexSessionStore is what HandleIndexGet needs of the session store: the session, whose flash
// may hold the session-ended notice, and the sealed cookie that holds it when the session's row
// was gone (see HandleSessionEndedGet).
type indexSessionStore interface {
	Get(r *http.Request, name string) (*sessionstore.Session, error)
	Save(r *http.Request, w http.ResponseWriter, s *sessionstore.Session) error
	CookieName(logicalName string) string
	OpenCookieValues(name, value string) (map[string]string, error)
	DeletionCookie(name string) *http.Cookie
}

func HandleIndexGet(
	authHelper AuthHelper,
	httpHelper HttpHelper,
	httpSession indexSessionStore,
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
		// The notice's own cookie is taken on sight, opened or not, so it shows once; one that
		// does not open, from a key rotated away or a cookie not this console's, says nothing.
		noticeName := httpSession.CookieName(sessionEndedNoticeCookie)
		if notice, cookieErr := r.Cookie(noticeName); cookieErr == nil {
			http.SetCookie(w, httpSession.DeletionCookie(noticeName))
			if values, openErr := httpSession.OpenCookieValues(sessionEndedNoticeCookie, notice.Value); openErr == nil && values[flashSessionEnded] == "true" {
				sessionEnded = true
			}
		}
		bind["SessionEnded"] = sessionEnded

		bind["AuthServerBaseUrl"] = authServerBaseURL

		isAuthenticated := false
		loggedInUser := ""
		logoutLink := ""

		// The index is the one page mounted outside RequiresScope, so an absent token set is the
		// anonymous visitor rather than a fault.
		if jwtInfo, ok := reqctx.JwtInfoFrom(r.Context()); ok {
			isAuthenticated = authHelper.IsAuthenticated(jwtInfo)
			if isAuthenticated {
				loggedInUser = jwtInfo.IdToken.StringClaim("email")
				logoutLink = "/auth/logout"
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
