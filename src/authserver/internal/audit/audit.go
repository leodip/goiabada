package audit

import (
	"encoding/json"
	"log/slog"

	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

type AuditEvent struct {
	AuditEvent string                 `json:"audit_event"`
	Details    map[string]interface{} `json:"details"`
}

type AuditLogger struct {
	database data.Database
}

func NewAuditLogger(database data.Database) *AuditLogger {
	return &AuditLogger{
		database: database,
	}
}

func (al *AuditLogger) Log(auditEvent string, details map[string]interface{}) {
	// Read settings to check which logging targets are enabled
	var settings *models.Settings
	if al.database != nil {
		var err error
		settings, err = al.database.GetSettingsById(nil, 1)
		if err != nil {
			slog.Error("failed to read settings for audit logging", "error", err, "event", auditEvent)
			return
		}
	} else {
		return
	}

	// Console logging
	if settings.AuditLogsInConsoleEnabled {
		evt := AuditEvent{
			AuditEvent: auditEvent,
			Details:    details,
		}

		eventJSON, err := json.Marshal(evt)
		if err != nil {
			slog.Error("failed to marshal audit event", "error", err, "event", auditEvent)
		} else {
			slog.Info(string(eventJSON))
		}
	}

	// Database persistence
	if settings.AuditLogsInDatabaseEnabled {
		// Marshal details to JSON
		detailsJSON, err := json.Marshal(details)
		if err != nil {
			slog.Error("failed to marshal audit event details for DB", "error", err, "event", auditEvent)
			return
		}

		auditLog := &models.AuditLog{
			AuditEvent: auditEvent,
			Details:    string(detailsJSON),
			// CreatedAt set by CreateAuditLog
		}

		err = al.database.CreateAuditLog(nil, auditLog)
		if err != nil {
			slog.Error("failed to persist audit log to database", "error", err, "event", auditEvent)
			// Non-blocking: do not return error to caller
		}
	}
}
