package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/data"
)

func MiddlewareSessionIdentifier(sessionStore sessions.Store, database data.Database) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			requestId := middleware.GetReqID(ctx)

			errorMsg := fmt.Sprintf("fatal failure in session middleware. For additional information, refer to the server logs. Request Id: %v", requestId)

			sess, err := sessionStore.Get(r, constants.SessionName)
			if err != nil {
				slog.Error(fmt.Sprintf("unable to get the session store: %+v", err), "request-id", requestId)
				http.Error(w, errorMsg, http.StatusInternalServerError)
				return
			}

			if sess.Values[constants.SessionKeySessionIdentifier] != nil {
				sessionIdentifier := sess.Values[constants.SessionKeySessionIdentifier].(string)

				userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
				if err != nil {
					slog.Error(fmt.Sprintf("unable to get the user session: %+v", err), "request-id", requestId)
					http.Error(w, errorMsg, http.StatusInternalServerError)
					return
				}
				if userSession == nil {
					// session has been deleted, will clear the session state
					sess.Values = make(map[interface{}]interface{})
					err = sessionStore.Save(r, w, sess)
					if err != nil {
						slog.Error(fmt.Sprintf("unable to save the session: %+v", err), "request-id", requestId)
						http.Error(w, errorMsg, http.StatusInternalServerError)
						return
					}
				} else {
					ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, sessionIdentifier)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}
