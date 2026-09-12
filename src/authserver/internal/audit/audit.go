package audit

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/leodip/goiabada/core/auditlog"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

type AuditLogger struct {
	database data.Database
}

func NewAuditLogger(database data.Database) *AuditLogger {
	return &AuditLogger{
		database: database,
	}
}

// Log records one audit event on whichever of the two targets the settings row enables.
//
// ctx is the request's, and every record written below carries it, which is the whole of #328:
// the installed handler reads chi's request id off it, so an operator holding a request id from a
// user's report finds the audit events that request raised beside the request's own log line.
// Nothing here names request_id, and that is deliberate — core/logging owns the injection, so the
// 126 call sites pass a context and nothing else.
//
// It never fails a request. Every failure path below logs and returns, as it did before, and the
// two reads ctx brought cannot fail, only be absent: a context with no settings on it falls back
// to the row read, and a context with no request id yields the empty string.
func (al *AuditLogger) Log(ctx context.Context, auditEvent string, details map[string]interface{}) {
	if al.database == nil {
		return
	}

	// Settings: taken off the request context when the settings middleware put them there, which
	// is every route on the app branch, and read from the row when it did not (#212 item 2, folded
	// in as decision 5). The five root registrations that audit, the rate limiter's three tiers and
	// a Background context in a test all take the fallback, so the read is not gone, only skipped
	// where the same row is already in hand. A type assertion cannot fail in a way worth reporting:
	// absent means read it.
	settings, ok := ctx.Value(constants.ContextKeySettings).(*models.Settings)
	// The nil check is not defensive: the assertion succeeds on a typed nil pointer, and reaching
	// the field reads below with one would panic in the audit path of every event.
	if !ok || settings == nil {
		var err error
		settings, err = al.database.GetSettingsById(nil, 1)
		if err != nil {
			slog.ErrorContext(ctx, "unable to read the settings row for audit logging", "error", err, "event", auditEvent)
			return
		}
	}

	// Console logging
	if settings.AuditLogsInConsoleEnabled {
		auditlog.LogToConsole(ctx, auditEvent, details)
	}

	// Database persistence
	if settings.AuditLogsInDatabaseEnabled {
		// Marshal details to JSON
		detailsJSON, err := json.Marshal(details)
		if err != nil {
			slog.ErrorContext(ctx, "unable to marshal the audit event details for the database", "error", err, "event", auditEvent)
			return
		}

		auditLog := &models.AuditLog{
			AuditEvent: auditEvent,
			Details:    string(detailsJSON),
			// CreatedAt set by CreateAuditLog
		}

		err = al.database.CreateAuditLog(nil, auditLog)
		if err != nil {
			slog.ErrorContext(ctx, "unable to persist the audit log to the database", "error", err, "event", auditEvent)
			// Non-blocking: do not return error to caller
		}
	}
}
