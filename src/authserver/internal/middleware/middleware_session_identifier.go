package middleware

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"

	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
)

// sessionIdentifierDatabase is what the session identifier middleware needs: the session a cookie
// names.
type sessionIdentifierDatabase interface {
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error)
}

// SessionIdentifier puts on the request's context the session identifier the session
// cookie names, when that session still exists. A failure to read the session or its row is
// answered through faults, in the format of the branch it is mounted on; on a page route it is
// text/plain (#435).
func SessionIdentifier(sessionStore sessionstore.Store, database sessionIdentifierDatabase, faults ServerFaults) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			requestId := chimiddleware.GetReqID(ctx)

			errorMsg := fmt.Sprintf("fatal failure in session middleware. For additional information, refer to the server logs. Request Id: %v", requestId)

			sess, err := sessionStore.Get(r, sessionkeys.AuthServerSessionName)
			if err != nil {
				if faults.answered(w, r, errs.Wrap(err, "unable to get the session store")) {
					return
				}
				slog.ErrorContext(ctx, "unable to get the session store", "error", err)
				http.Error(w, errorMsg, http.StatusInternalServerError)
				return
			}

			if sess.Values[sessionkeys.SessionIdentifier] != nil {
				sessionIdentifier := sess.Values[sessionkeys.SessionIdentifier].(string)

				userSession, err := database.GetUserSessionBySessionIdentifier(r.Context(), nil, sessionIdentifier)
				if err != nil {
					if faults.answered(w, r, errs.Wrap(err, "unable to get the user session")) {
						return
					}
					slog.ErrorContext(ctx, "unable to get the user session", "error", err)
					http.Error(w, errorMsg, http.StatusInternalServerError)
					return
				}
				if userSession == nil {
					// session has been deleted from DB, clear only the session identifier
					// but preserve other session data (like AuthContext for ongoing auth flows)
					slog.WarnContext(ctx, "session not found in the database, clearing the session identifier")
					delete(sess.Values, sessionkeys.SessionIdentifier)
					err = sessionStore.Save(r, w, sess)
					if err != nil {
						if faults.answered(w, r, errs.Wrap(err, "unable to save the session")) {
							return
						}
						slog.ErrorContext(ctx, "unable to save the session", "error", err)
						http.Error(w, errorMsg, http.StatusInternalServerError)
						return
					}
				} else {
					ctx = reqctx.WithSessionIdentifier(ctx, sessionIdentifier)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}
