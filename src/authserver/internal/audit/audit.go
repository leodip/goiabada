package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/logging"
)

// auditDatabase is what the audit logger writes: the record.
type auditDatabase interface {
	CreateAuditLog(ctx context.Context, tx *sql.Tx, auditLog *record.AuditLog) error
}

// Switches are the two settings that say where Log records an event.
type Switches struct {
	Console  bool
	Database bool
}

// switchesSource answers the two switches for the request ctx belongs to. The production one,
// middleware.AuditSwitches, answers from the settings the settings middleware put on the context
// and reads the row only when there are none, so an audited request costs no second settings read
// (#212 item 2) and this package reads nothing off a context itself (#433).
type switchesSource interface {
	AuditSwitches(ctx context.Context) (Switches, error)
}

// auditWriteTimeout bounds the switches read and the audit insert once Log has detached them from
// the caller's cancellation. Ten seconds, matching every other bounded wait on a dependency in
// this repository's request path rather than introducing a value nobody chose against the others.
const auditWriteTimeout = 10 * time.Second

type Logger struct {
	database auditDatabase
	switches switchesSource
}

func NewLogger(database auditDatabase, switches switchesSource) *Logger {
	return &Logger{
		database: database,
		switches: switches,
	}
}

// Log records one audit event on whichever of the two targets the switches enable.
//
// ctx is the request's, and every record written below carries it, which is the whole of #328:
// the installed handler reads chi's request id off it, so an operator holding a request id from a
// user's report finds the audit events that request raised beside the request's own log line.
// Nothing here names request_id, and that is deliberate — core/logging owns the injection, so the
// 126 call sites pass a context and nothing else.
//
// It never fails a request. Every failure path below logs and returns, as it did before, and a
// context with no request id yields the empty string.
func (al *Logger) Log(ctx context.Context, auditEvent string, details map[string]interface{}) {
	if al.database == nil || al.switches == nil {
		return
	}

	// The caller's VALUES, deliberately not the caller's cancellation. Every one of the 126 call
	// sites logs its event after the outcome it records is already durable -- the token was
	// issued, the password was changed, the user was deleted -- so the request going away is not
	// a reason to stop recording that it happened. Before #386 the two calls below took no
	// context at all and always ran; net/http cancels a request's context the moment the client
	// disconnects, so passing it straight through would have made "hang up" a way to keep an
	// event out of the audit trail, which is the opposite of what the trail is for.
	//
	// WithoutCancel and not context.Background(): the switches and the request id are read off
	// this context a few lines down, and a fresh root would lose both, costing every audit row
	// written under a cancelled request its request_id and forcing a settings read the middleware
	// had already done.
	//
	// The deadline is what the request's cancellation used to supply by accident, and it is not
	// optional once the cancellation is gone: an unbounded detached context is how a database
	// that has stopped answering holds a handler's goroutine for ever. 10 seconds, which is the
	// one value the repository uses for a bounded wait on a dependency in the request path
	// (#386 decision 6, and final review round 1 finding 9).
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()

	switches, err := al.switches.AuditSwitches(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "unable to read the audit switches", "error", err, "event", auditEvent)
		return
	}

	// Console logging
	if switches.Console {
		LogToConsole(ctx, auditEvent, details)
	}

	// Database persistence
	if switches.Database {
		// Marshal details to JSON
		detailsJSON, err := json.Marshal(details)
		if err != nil {
			slog.ErrorContext(ctx, "unable to marshal the audit event details for the database", "error", err, "event", auditEvent)
			return
		}

		auditLog := &record.AuditLog{
			AuditEvent: auditEvent,
			Details:    string(detailsJSON),
			// Through FieldForLog, and not chi's raw string, so the row carries exactly what
			// core/logging puts on the record: the id is client-chosen (an inbound X-Request-Id
			// is adopted verbatim), so this is where it is escaped to printable ASCII and clipped
			// with a counted marker. Storing the raw value instead would make the admin page and
			// the log disagree on precisely the ids an attacker chose, which is the case the
			// correlation has to survive (#328). An empty context yields "", which is what a row
			// written off a request carries.
			RequestId: logging.FieldForLog(chimiddleware.GetReqID(ctx)),
			// CreatedAt set by CreateAuditLog
		}

		err = al.database.CreateAuditLog(ctx, nil, auditLog)
		if err != nil {
			slog.ErrorContext(ctx, "unable to persist the audit log to the database", "error", err, "event", auditEvent)
			// Non-blocking: do not return error to caller
		}
	}
}
