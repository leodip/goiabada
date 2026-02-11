package models

import "time"

type AuditLog struct {
	Id         int64     `db:"id" fieldtag:"pk"`
	CreatedAt  time.Time `db:"created_at" fieldtag:"dont-update"`
	AuditEvent string    `db:"audit_event"`
	Details    string    `db:"details"` // JSON-serialized
}
