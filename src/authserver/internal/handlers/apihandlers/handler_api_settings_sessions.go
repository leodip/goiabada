package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// HandleSettingsSessionsGet - GET /api/v1/admin/settings/sessions
func HandleSettingsSessionsGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		resp := api.SettingsSessionsResponse{
			UserSessionIdleTimeoutInSeconds: settings.UserSessionIdleTimeoutInSeconds,
			UserSessionMaxLifetimeInSeconds: settings.UserSessionMaxLifetimeInSeconds,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}

// settingsSessionsDatabase is what the session settings endpoint needs: the settings write.
type settingsSessionsDatabase interface {
	UpdateSettings(ctx context.Context, tx *sql.Tx, settings *record.Settings) error
}

// HandleSettingsSessionsPut - PUT /api/v1/admin/settings/sessions
func HandleSettingsSessionsPut(
	database settingsSessionsDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentSettings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		var req api.UpdateSettingsSessionsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Validation
		if req.UserSessionIdleTimeoutInSeconds <= 0 {
			writeJSONError(w, "User session - idle timeout in seconds must be greater than zero.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if req.UserSessionMaxLifetimeInSeconds <= 0 {
			writeJSONError(w, "User session - max lifetime in seconds must be greater than zero.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		const maxValue = 160000000
		if req.UserSessionIdleTimeoutInSeconds > maxValue {
			writeJSONError(w, fmt.Sprintf("User session - idle timeout in seconds cannot be greater than %v.", maxValue), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if req.UserSessionMaxLifetimeInSeconds > maxValue {
			writeJSONError(w, fmt.Sprintf("User session - max lifetime in seconds cannot be greater than %v.", maxValue), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if req.UserSessionIdleTimeoutInSeconds > req.UserSessionMaxLifetimeInSeconds {
			writeJSONError(w, "User session - the idle timeout cannot be greater than the max lifetime.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Apply updates
		currentSettings.UserSessionIdleTimeoutInSeconds = req.UserSessionIdleTimeoutInSeconds
		currentSettings.UserSessionMaxLifetimeInSeconds = req.UserSessionMaxLifetimeInSeconds

		if err := database.UpdateSettings(r.Context(), nil, currentSettings); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), audit.EventUpdatedSessionsSettings, map[string]interface{}{
			"loggedInUser": callerSubject(r),
		})

		resp := api.SettingsSessionsResponse{
			UserSessionIdleTimeoutInSeconds: currentSettings.UserSessionIdleTimeoutInSeconds,
			UserSessionMaxLifetimeInSeconds: currentSettings.UserSessionMaxLifetimeInSeconds,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}
