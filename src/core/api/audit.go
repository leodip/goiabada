package api

import (
	"time"
)

type AuditLogResponse struct {
	Id int64 `json:"id"`
	// CreatedAt is the instant, not a string the producer formatted: every consumer wants a
	// time, and the one that renders it has to localize it rather than reproduce whatever
	// layout the server picked. A value rather than a pointer because audit_logs.created_at is
	// NOT NULL on every engine and the schema declares createdAt required and not nullable, so
	// a pointer would publish a null that cannot occur. time.Time marshals to RFC3339, which is
	// what the hand-rolled format produced, so the wire is unchanged but for the sub-second
	// precision that format truncated (#373).
	CreatedAt  time.Time `json:"createdAt"`
	AuditEvent string    `json:"auditEvent"`
	Details    string    `json:"details"`
	// RequestId is the request's id as the application log carries it, empty when the entry
	// was not written on a request (#328).
	RequestId string `json:"requestId"`
}

type GetAuditLogsResponse struct {
	AuditLogs []AuditLogResponse `json:"auditLogs"`
	Total     int                `json:"total"`
	Page      int                `json:"page"`
	Size      int                `json:"size"`
}

// GetAuditEventTypesResponse is the catalog of every audit event name this server can write,
// which is what the auditEvent filter on GET /api/v1/admin/audit-logs accepts. It is a fixed
// list rather than the distinct values present in the table: a filter offering only what has
// already happened cannot express "show me the ones that have not".
//
// It is its own route rather than a field on GetAuditLogsResponse because that response is
// paginated and filtered, so the catalog would ride on every page of every query (#351).
type GetAuditEventTypesResponse struct {
	AuditEventTypes []string `json:"auditEventTypes"`
}
