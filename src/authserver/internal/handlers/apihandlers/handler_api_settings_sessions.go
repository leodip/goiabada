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
	"github.com/leodip/goiabada/core/i18n"
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
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsSessionsIdleTimeoutNotPositive, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if req.UserSessionMaxLifetimeInSeconds <= 0 {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsSessionsMaxLifetimeNotPositive, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		const maxValue = 160000000
		if req.UserSessionIdleTimeoutInSeconds > maxValue {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsSessionsIdleTimeoutTooLarge, map[string]any{"max": maxValue}), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if req.UserSessionMaxLifetimeInSeconds > maxValue {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsSessionsMaxLifetimeTooLarge, map[string]any{"max": maxValue}), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if req.UserSessionIdleTimeoutInSeconds > req.UserSessionMaxLifetimeInSeconds {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsSessionsIdleTimeoutAboveMaxLifetime, nil), "VALIDATION_ERROR", http.StatusBadRequest)
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
			"logged_in_user": callerSubject(r),
		})

		resp := api.SettingsSessionsResponse{
			UserSessionIdleTimeoutInSeconds: currentSettings.UserSessionIdleTimeoutInSeconds,
			UserSessionMaxLifetimeInSeconds: currentSettings.UserSessionMaxLifetimeInSeconds,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}
