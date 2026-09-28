package middleware

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
)

// settingsDatabase is what the settings middleware needs: the settings row it puts on every
// request's context.
type settingsDatabase interface {
	GetSettingsById(ctx context.Context, tx *sql.Tx, settingsId int64) (*models.Settings, error)
}

func MiddlewareSettings(database settingsDatabase) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			settings, err := database.GetSettingsById(r.Context(), nil, 1)
			if err != nil {
				// Plain text, because this runs before any helper that could render a page:
				// the settings it is fetching are what the error page's layout reads. The
				// sentence is unchanged; the log line is decision 9's shape, with the stack
				// riding inside the error attribute rather than formatted into the message
				// (#279).
				requestId := middleware.GetReqID(r.Context())
				// No request_id attribute: the installed handler takes it off the context this
				// call passes it (#320 decision 2). requestId is still read for the body below,
				// which is what gives whoever hit this something to quote to an operator.
				slog.ErrorContext(r.Context(), "unable to load the settings", "error", err)
				http.Error(w, fmt.Sprintf("fatal failure in GetSettings() middleware. For additional information, refer to the server logs. Request Id: %v", requestId), http.StatusInternalServerError)
				return
			}
			next.ServeHTTP(w, r.WithContext(reqctx.WithSettings(ctx, settings)))
		}
		return http.HandlerFunc(fn)
	}
}

// AuditSwitches answers audit.Log's two switches. It sits beside MiddlewareSettings because it
// reads what that middleware wrote: on every route of the application branch the settings are
// already on the context, and taking them from there is what spares each audited request a second
// settings read (#212 item 2, #328 decision 5). The root registrations, the rate limiter's tiers
// and the background workers audit with no settings on their context, and those read the row.
type AuditSwitches struct {
	database settingsDatabase
}

func NewAuditSwitches(database settingsDatabase) *AuditSwitches {
	return &AuditSwitches{database: database}
}

func (a *AuditSwitches) AuditSwitches(ctx context.Context) (audit.Switches, error) {
	settings, ok := reqctx.SettingsFrom(ctx)
	if !ok {
		var err error
		settings, err = a.database.GetSettingsById(ctx, nil, 1)
		if err != nil {
			return audit.Switches{}, errs.Wrap(err, "unable to read the settings row")
		}
		if settings == nil {
			return audit.Switches{}, errs.New("the settings row does not exist")
		}
	}
	return audit.Switches{
		Console:  settings.AuditLogsInConsoleEnabled,
		Database: settings.AuditLogsInDatabaseEnabled,
	}, nil
}
