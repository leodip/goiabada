package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// HandleSettingsAuditLogsGet - GET /api/v1/admin/settings/audit-logs
func HandleSettingsAuditLogsGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		resp := api.SettingsAuditLogsResponse{
			AuditLogsInConsoleEnabled:  settings.AuditLogsInConsoleEnabled,
			AuditLogsInDatabaseEnabled: settings.AuditLogsInDatabaseEnabled,
			AuditLogRetentionDays:      settings.AuditLogRetentionDays,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}

// settingsAuditLogsDatabase is what the audit log settings endpoint needs: the settings write.
type settingsAuditLogsDatabase interface {
	UpdateSettings(ctx context.Context, tx *sql.Tx, settings *record.Settings) error
}

// HandleSettingsAuditLogsPut - PUT /api/v1/admin/settings/audit-logs
func HandleSettingsAuditLogsPut(
	database settingsAuditLogsDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentSettings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		var req api.UpdateSettingsAuditLogsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Validation
		if req.AuditLogRetentionDays < 0 {
			writeJSONError(w, "Audit log retention days cannot be negative. Use 0 for infinite retention.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		const maxRetentionDays = 3650 // 10 years
		if req.AuditLogRetentionDays > maxRetentionDays {
			writeJSONError(w, "Audit log retention days cannot exceed 3650 days (10 years).", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Reserved to authserver:manage, refused before the change is recorded or made.
		if !settingsCeilingAllows(w, r, auditLogger) {
			return
		}

		// Saved from a copy, so the settings on the request's context stay the ones it started
		// with. The change is then recorded under those, the audit logger's switches, so switching
		// logging off is recorded too, and a save the database refuses records nothing.
		updated := *currentSettings
		updated.AuditLogsInConsoleEnabled = req.AuditLogsInConsoleEnabled
		updated.AuditLogsInDatabaseEnabled = req.AuditLogsInDatabaseEnabled
		updated.AuditLogRetentionDays = req.AuditLogRetentionDays

		if err := database.UpdateSettings(r.Context(), nil, &updated); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		auditLogger.Log(r.Context(), audit.EventUpdatedAuditLogsSettings, map[string]interface{}{
			"logged_in_user":                 callerSubject(r),
			"audit_logs_in_console_enabled":  updated.AuditLogsInConsoleEnabled,
			"audit_logs_in_database_enabled": updated.AuditLogsInDatabaseEnabled,
			"audit_log_retention_days":       updated.AuditLogRetentionDays,
		})

		resp := api.SettingsAuditLogsResponse{
			AuditLogsInConsoleEnabled:  updated.AuditLogsInConsoleEnabled,
			AuditLogsInDatabaseEnabled: updated.AuditLogsInDatabaseEnabled,
			AuditLogRetentionDays:      updated.AuditLogRetentionDays,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}
