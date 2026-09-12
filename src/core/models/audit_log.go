package models

import "time"

type AuditLog struct {
	Id         int64     `db:"id" fieldtag:"pk"`
	CreatedAt  time.Time `db:"created_at" fieldtag:"dont-update"`
	AuditEvent string    `db:"audit_event"`
	Details    string    `db:"details"` // JSON-serialized

	// RequestId ties this row to the application log: it is the request id rendered exactly as
	// core/logging renders the request_id attribute, so the value shown on the admin page is the
	// value an operator greps the log for, byte for byte, clipping and escaping included (#328).
	//
	// The empty string means the row was not written on a request: every row written before the
	// column existed, and the startup backfill's row, which has no request to name.
	RequestId string `db:"request_id"`
}
