package middleware

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/sessionstore"
)

// sessionIdentifierDatabase is what the session identifier middleware needs: the session a cookie
// names.
type sessionIdentifierDatabase interface {
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error)
}

func MiddlewareSessionIdentifier(sessionStore sessionstore.Store, database sessionIdentifierDatabase) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			requestId := middleware.GetReqID(ctx)

			errorMsg := fmt.Sprintf("fatal failure in session middleware. For additional information, refer to the server logs. Request Id: %v", requestId)

			sess, err := sessionStore.Get(r, constants.AuthServerSessionName)
			if err != nil {
				slog.ErrorContext(ctx, "unable to get the session store", "error", err)
				http.Error(w, errorMsg, http.StatusInternalServerError)
				return
			}

			if sess.Values[constants.SessionKeySessionIdentifier] != nil {
				sessionIdentifier := sess.Values[constants.SessionKeySessionIdentifier].(string)

				userSession, err := database.GetUserSessionBySessionIdentifier(r.Context(), nil, sessionIdentifier)
				if err != nil {
					slog.ErrorContext(ctx, "unable to get the user session", "error", err)
					http.Error(w, errorMsg, http.StatusInternalServerError)
					return
				}
				if userSession == nil {
					// session has been deleted from DB, clear only the session identifier
					// but preserve other session data (like AuthContext for ongoing auth flows)
					slog.WarnContext(ctx, "session not found in the database, clearing the session identifier")
					delete(sess.Values, constants.SessionKeySessionIdentifier)
					err = sessionStore.Save(r, w, sess)
					if err != nil {
						slog.ErrorContext(ctx, "unable to save the session", "error", err)
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
