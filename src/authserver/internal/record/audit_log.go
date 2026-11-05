package record

import (
	"database/sql"
	"time"
)

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

	// UserId is the user the event is about, copied from the details' user_id when the event is
	// written. It is no foreign key: an audit row outlives the user it names. NULL when the details
	// name no user, and on every row written before the column existed.
	UserId sql.NullInt64 `db:"user_id"`

	// LoggedInUserId is the user whose access token made the request that raised the event: the
	// administrator on the admin API, the user themselves on the account API. NULL on a request
	// made without a user's token (a browser sign-in, a client credentials token), off a request,
	// and on every row written before the column existed. No foreign key, as UserId.
	LoggedInUserId sql.NullInt64 `db:"logged_in_user_id"`
}

// AuditLogFilter narrows a page of audit logs. Each filter is an exact match and applies only when
// it is set; its zero value sets none, and the filters set combine with AND.
type AuditLogFilter struct {
	// AuditEvent lists the rows of that event only.
	AuditEvent string
	// RequestId lists the rows written on that request only, compared byte for byte, so an id
	// differing by a trailing space or a fold names another request (#328).
	RequestId string
	// UserId lists the rows about that user or made by them: those whose user_id or whose
	// logged_in_user_id is that id, each row once. Zero sets no filter.
	UserId int64
}
