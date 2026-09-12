// Package auditlog owns the console half of audit logging: the one record every
// audit event writes to the application log, whichever site raised it (#320).
package auditlog

import (
	"context"
	"log/slog"
)

// LogToConsole writes one audit event to the application log.
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
// Two sites call this, and that is the second reason it exists. The authserver's
// AuditLogger and the email-collision backfill in core/data/commondb both write
// this record, and they cannot share code any higher up because core cannot
// import the authserver module. Before this they were two hand-copied envelope
// structs, so a change to one silently produced two shapes on one log stream.
// The backfill passes context.Background(), because it runs at startup inside a
// Database method with no request in existence, and a Background context adds
// nothing to the record: its record carries no request_id, which is the truth
// about it rather than a gap.
func LogToConsole(ctx context.Context, event string, details map[string]any) {
	slog.InfoContext(ctx, "audit event", "event", event, "details", details)
}
