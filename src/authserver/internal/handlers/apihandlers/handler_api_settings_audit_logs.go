package apihandlers

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

// HandleAPISettingsAuditLogsGet - GET /api/v1/admin/settings/audit-logs
func HandleAPISettingsAuditLogsGet(
	httpHelper handlers.HttpHelper,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if settings == nil {
			writeJSONError(w, "Failed to load settings", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		resp := api.SettingsAuditLogsResponse{
			AuditLogsInConsoleEnabled:  settings.AuditLogsInConsoleEnabled,
			AuditLogsInDatabaseEnabled: settings.AuditLogsInDatabaseEnabled,
			AuditLogRetentionDays:      settings.AuditLogRetentionDays,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, resp)
	}
}

// HandleAPISettingsAuditLogsPut - PUT /api/v1/admin/settings/audit-logs
func HandleAPISettingsAuditLogsPut(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentSettings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if currentSettings == nil {
			writeJSONError(w, "Failed to load settings", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		var req api.UpdateSettingsAuditLogsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
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
		auditLogger.Log(constants.AuditUpdatedAuditLogsSettings, map[string]interface{}{
			"loggedInUser":               authHelper.GetLoggedInSubject(r),
			"auditLogsInConsoleEnabled":  req.AuditLogsInConsoleEnabled,
			"auditLogsInDatabaseEnabled": req.AuditLogsInDatabaseEnabled,
			"auditLogRetentionDays":      req.AuditLogRetentionDays,
		})

		// Apply updates
		currentSettings.AuditLogsInConsoleEnabled = req.AuditLogsInConsoleEnabled
		currentSettings.AuditLogsInDatabaseEnabled = req.AuditLogsInDatabaseEnabled
		currentSettings.AuditLogRetentionDays = req.AuditLogRetentionDays

		if err := database.UpdateSettings(nil, currentSettings); err != nil {
			writeJSONError(w, "Failed to update settings", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		resp := api.SettingsAuditLogsResponse{
			AuditLogsInConsoleEnabled:  currentSettings.AuditLogsInConsoleEnabled,
			AuditLogsInDatabaseEnabled: currentSettings.AuditLogsInDatabaseEnabled,
			AuditLogRetentionDays:      currentSettings.AuditLogRetentionDays,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, resp)
	}
}
