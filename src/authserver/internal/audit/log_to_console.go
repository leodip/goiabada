package audit

import (
	"context"
	"log/slog"
)

// LogToConsole writes one audit event to the application log: the console half of audit logging,
// the one record every audit event writes to the application log whichever site raised it (#320).
//
// details is passed as an attribute value rather than marshalled into the
// message, which is the whole point of the function. Under JSON the collector
// gets an object it can query inside; under text it gets Go's map rendering.
// The shape it replaced put a JSON document where the message goes, so a
// collector consuming the log as JSON had to parse `msg` a second time to reach
// the field it was querying on, and a person reading the text log got one
// unbroken line with no key=value in it at all (#320 decision 7).
//
// One narrowing came with that, and it is here rather than buried: the shape this
// replaced marshalled the envelope itself and logged an error when that failed,
// whereas a details value slog's JSON encoder cannot render makes the handler
// return an error the slog.Logger discards, so the record is dropped in silence.
// Nothing reaches here with such a value today (every site sends strings, numbers,
// bools and slices of them), and the database half of AuditLogger still marshals
// and still reports the failure, so an unrenderable value is caught there.
//
// It takes a context so the installed handler can append request_id, which ties
// an event to the request that raised it: an operator holding a request id from a
// user's report finds this record beside the request's own log line, where before
// the two could not be joined at all (#328). The identifying details the event
// carries are about the subject, not about the request.
//
// It is a function of this package rather than of its own because there is one caller left,
// AuditLogger.Log in audit.go. It was a core package while a backfill in the data layer wrote this
// record from the other side of the module boundary; #351 deleted that backfill, and #359 folded
// what was left of the package in here. It stays exported and separate from Log because the record
// it writes is one of the two halves Log chooses between, and the settings row decides which.
func LogToConsole(ctx context.Context, event string, details map[string]any) {
	slog.InfoContext(ctx, "audit event", "event", event, "details", details)
}
