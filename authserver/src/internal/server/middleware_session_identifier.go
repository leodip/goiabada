package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/data"
)

func MiddlewareSessionIdentifier(sessionStore sessions.Store, database *data.Database) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			requestId := middleware.GetReqID(ctx)

			errorMsg := fmt.Sprintf("fatal failure in session middleware. For additional information, refer to the server logs. Request Id: %v", requestId)

			sess, err := sessionStore.Get(r, common.SessionName)
			if err != nil {
				slog.Error(fmt.Sprintf("unable to get the session store: %v", err.Error()), "request-id", requestId)
				http.Error(w, errorMsg, http.StatusInternalServerError)
				return
			}

			if sess.Values[common.SessionKeySessionIdentifier] != nil {
				sessionIdentifier := sess.Values[common.SessionKeySessionIdentifier].(string)

				userSession, err := database.GetUserSessionBySessionIdentifier(sessionIdentifier)
				if err != nil {
					slog.Error(fmt.Sprintf("unable to get the user session: %v", err.Error()), "request-id", requestId)
					http.Error(w, errorMsg, http.StatusInternalServerError)
					return
				}
				if userSession == nil {
					// session has been deleted, will clear the session state
					sess.Values = make(map[interface{}]interface{})
					err = sess.Save(r, w)
					if err != nil {
						slog.Error(fmt.Sprintf("unable to save the session: %v", err.Error()), "request-id", requestId)
						http.Error(w, errorMsg, http.StatusInternalServerError)
						return
					}
				} else {
					ctx = context.WithValue(ctx, common.ContextKeySessionIdentifier, sessionIdentifier)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}
