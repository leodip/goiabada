package middleware

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
)

// sessionIdentifierDatabase is what the session identifier middleware needs: the session a cookie
// names.
type sessionIdentifierDatabase interface {
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
}

// sessionIdentifierStore is what the session identifier middleware calls on the browser session
// store: the request's session, and the conditional write its removal of a dangling pointer is made
// with, which only sessionstore.ConditionalStore has (#579).
type sessionIdentifierStore interface {
	Get(r *http.Request, name string) (*sessionstore.Session, error)
	ChangeAndSave(r *http.Request, w http.ResponseWriter, session *sessionstore.Session,
		change func(values map[string]any) error) error
}

// errPointerNotStored is the refusal removeDanglingPointer's change answers when the browser session
// no longer holds the pointer it was asked to remove, so nothing is written.
var errPointerNotStored = errors.New("the browser session no longer holds the session pointer")

// SessionIdentifier puts on the request's context the session identifier the session
// cookie names, when that session still exists. A failure to read the session or its row is
// answered through faults, in the format of the branch it is mounted on; on a page route it is
// text/plain (#435).
func SessionIdentifier(sessionStore sessionIdentifierStore, database sessionIdentifierDatabase, faults ServerFaults) func(next http.Handler) http.Handler {
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
					err = removeDanglingPointer(sessionStore, w, r, sess, sessionIdentifier)
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

// removeDanglingPointer removes the pointer to a user session that no longer exists from the browser
// session, and writes only that removal: onto the session as it is stored now, on condition nothing
// wrote it in between, through ChangeAndSave (#579). The copy the request read when it began would put
// back whatever another request of this browser wrote since, such as a ceremony another tab started.
//
// It removes that pointer and no other, so a pointer to a newer user session written meanwhile is
// kept, and it writes nothing when the session no longer holds the pointer, or is gone, since the
// pointer is then already removed. Either way the request's own session no longer holds it.
func removeDanglingPointer(sessionStore sessionIdentifierStore, w http.ResponseWriter, r *http.Request,
	sess *sessionstore.Session, sessionIdentifier string) error {

	err := sessionStore.ChangeAndSave(r, w, sess, func(values map[string]any) error {
		if values[sessionkeys.SessionIdentifier] != sessionIdentifier {
			return errPointerNotStored
		}
		delete(values, sessionkeys.SessionIdentifier)
		return nil
	})
	if errors.Is(err, errPointerNotStored) || errors.Is(err, sessionstore.ErrNotFound) {
		delete(sess.Values, sessionkeys.SessionIdentifier)
		return nil
	}
	return err
}
