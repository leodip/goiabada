package audit

import (
	"encoding/json"
	"log/slog"
)

type AuditEvent struct {
	AuditEvent string                 `json:"audit_event"`
	Details    map[string]interface{} `json:"details"`
}

type AuditLogger struct {
	auditLogsInConsole bool
}

func NewAuditLogger(auditLogsInConsole bool) *AuditLogger {
	return &AuditLogger{
		auditLogsInConsole: auditLogsInConsole,
	}
}

func (al *AuditLogger) Log(auditEvent string, details map[string]interface{}) {
	if !al.auditLogsInConsole {
		return
	}

	evt := AuditEvent{
		AuditEvent: auditEvent,
		Details:    details,
	}

	eventJSON, err := json.Marshal(evt)
	if err != nil {
		slog.Error("failed to marshal audit event", "error", err, "event", auditEvent)
		return
	}

	slog.Info(string(eventJSON))
}
