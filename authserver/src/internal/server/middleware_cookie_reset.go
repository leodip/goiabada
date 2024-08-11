package server

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/authserver/internal/constants"
)

func MiddlewareCookieReset(sessionStore sessions.Store) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			_, err := sessionStore.Get(r, constants.SessionName)
			if err != nil {
				multiErr, ok := err.(securecookie.MultiError)
				if ok && multiErr.IsDecode() {
					cookie := http.Cookie{
						Name:    constants.SessionName,
						Expires: time.Now().AddDate(0, 0, -1),
						MaxAge:  -1,
						Path:    "/",
					}
					http.SetCookie(w, &cookie)
					http.Redirect(w, r, r.RequestURI, http.StatusFound)
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}
