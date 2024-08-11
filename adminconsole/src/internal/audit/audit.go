package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/leodip/goiabada/adminconsole/internal/config"
)

type AuditEvent struct {
	Event   string                 `json:"event"`
	Details map[string]interface{} `json:"details"`
}

func Log(event string, details map[string]interface{}) {
	auditEvent := AuditEvent{
		Event:   event,
		Details: details,
	}

	detailsJson, err := json.Marshal(auditEvent.Details)
	if err != nil {
		slog.Error(fmt.Sprintf("failed to marshal audit details: %+v", err))
		slog.Info(fmt.Sprintf("audit: %v; (unable to marshal details)", auditEvent.Event))
		return
	}

	consoleLogEnabled := config.AuditLogsInConsole
	if consoleLogEnabled {
		slog.Info(fmt.Sprintf("audit: %v; details: %v", auditEvent.Event, string(detailsJson)))
	}
}
