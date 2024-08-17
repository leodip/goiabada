package audit

import (
	"encoding/json"
	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/config"
)

type AuditEvent struct {
	AuditEvent string                 `json:"audit_event"`
	Details    map[string]interface{} `json:"details"`
}

type AuditLogger struct {
}

func NewAuditLogger() *AuditLogger {
	return &AuditLogger{}
}

func (al *AuditLogger) Log(auditEvent string, details map[string]interface{}) {
	if !config.AuditLogsInConsole {
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
