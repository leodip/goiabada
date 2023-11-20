package lib

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

type AuditEvent struct {
	Event   string                 `json:"event"`
	Details map[string]interface{} `json:"details"`
}

func LogAudit(event string, details map[string]interface{}) {
	auditEvent := AuditEvent{
		Event:   event,
		Details: details,
	}

	detailsJson, err := json.Marshal(auditEvent.Details)
	if err != nil {
		slog.Error(fmt.Sprintf("failed to marshal audit details: %v", err))
		slog.Info(fmt.Sprintf("audit: %v; (unable to marshal details)", auditEvent.Event))
		return
	}
	slog.Info(fmt.Sprintf("audit: %v; details: %v", auditEvent.Event, string(detailsJson)))
}
