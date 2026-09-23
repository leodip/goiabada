package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// HandleAPISettingsAuditLogsGet - GET /api/v1/admin/settings/audit-logs
func HandleAPISettingsAuditLogsGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if settings == nil {
			writeInternalServerError(w, r, errs.New("settings are missing from the request context"))
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
	UpdateSettings(ctx context.Context, tx *sql.Tx, settings *models.Settings) error
}

// HandleAPISettingsAuditLogsPut - PUT /api/v1/admin/settings/audit-logs
func HandleAPISettingsAuditLogsPut(
	database settingsAuditLogsDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentSettings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if currentSettings == nil {
			writeInternalServerError(w, r, errs.New("settings are missing from the request context"))
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

		// Audit log before saving, so the logger reads the old settings
		// and always records the change (even when disabling logging)
		auditLogger.Log(r.Context(), audit.AuditUpdatedAuditLogsSettings, map[string]interface{}{
			"loggedInUser":               callerSubject(r),
			"auditLogsInConsoleEnabled":  req.AuditLogsInConsoleEnabled,
			"auditLogsInDatabaseEnabled": req.AuditLogsInDatabaseEnabled,
			"auditLogRetentionDays":      req.AuditLogRetentionDays,
		})

		// Apply updates
		currentSettings.AuditLogsInConsoleEnabled = req.AuditLogsInConsoleEnabled
		currentSettings.AuditLogsInDatabaseEnabled = req.AuditLogsInDatabaseEnabled
		currentSettings.AuditLogRetentionDays = req.AuditLogRetentionDays

		if err := database.UpdateSettings(r.Context(), nil, currentSettings); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		resp := api.SettingsAuditLogsResponse{
			AuditLogsInConsoleEnabled:  currentSettings.AuditLogsInConsoleEnabled,
			AuditLogsInDatabaseEnabled: currentSettings.AuditLogsInDatabaseEnabled,
			AuditLogRetentionDays:      currentSettings.AuditLogRetentionDays,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}
