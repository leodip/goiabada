package apihandlers

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
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

// settingsAuditLogsDatabase is what the audit log settings endpoint needs: the settings save.
type settingsAuditLogsDatabase interface {
	settingsSaveDatabase
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
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsAuditLogsRetentionDaysNegative, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		const maxRetentionDays = 3650 // 10 years
		if req.AuditLogRetentionDays > maxRetentionDays {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsAuditLogsRetentionDaysTooLarge, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Reserved to authserver:manage, refused before the change is recorded or made.
		if !settingsCeilingAllows(w, r, auditLogger) {
			return
		}

		// Saved onto the row as stored when the save runs (#407), so the settings on the request's
		// context stay the ones it started with. The change is then recorded under those, the audit
		// logger's switches, so switching logging off is recorded too, and a save the database
		// refuses records nothing.
		updated, err := saveSettingsSection(r.Context(), database, currentSettings.Id, func(stored *record.Settings) {
			stored.AuditLogsInConsoleEnabled = req.AuditLogsInConsoleEnabled
			stored.AuditLogsInDatabaseEnabled = req.AuditLogsInDatabaseEnabled
			stored.AuditLogRetentionDays = req.AuditLogRetentionDays
		})
		if err != nil {
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
