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
			MaxUserSessionsPerUser:          settings.MaxUserSessionsPerUser,
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
		// The cap is required: a PUT replaces the whole resource, and an absent or null value read
		// as 0 would turn the cap off for a caller that does not know the field (#564 decision 6).
		if req.MaxUserSessionsPerUser == nil {
			writeJSONError(w, "User session - max sessions per user is required.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		const maxSessionsPerUser = 1000
		if *req.MaxUserSessionsPerUser < 0 || *req.MaxUserSessionsPerUser > maxSessionsPerUser {
			writeJSONError(w, fmt.Sprintf("User session - max sessions per user must be between 0 and %v.", maxSessionsPerUser), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		oldVals := sessionsSettingsAuditValues(currentSettings)

		// Apply updates
		currentSettings.UserSessionIdleTimeoutInSeconds = req.UserSessionIdleTimeoutInSeconds
		currentSettings.UserSessionMaxLifetimeInSeconds = req.UserSessionMaxLifetimeInSeconds
		currentSettings.MaxUserSessionsPerUser = *req.MaxUserSessionsPerUser

		if err := database.UpdateSettings(r.Context(), nil, currentSettings); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Audit with old/new values: lowering the cap ends sessions at every user's next sign-in,
		// so the event says what changed and not only who saved (#564 decision 10).
		auditLogger.Log(r.Context(), audit.EventUpdatedSessionsSettings, map[string]interface{}{
			"logged_in_user": callerSubject(r),
			"old":            oldVals,
			"new":            sessionsSettingsAuditValues(currentSettings),
		})

		resp := api.SettingsSessionsResponse{
			UserSessionIdleTimeoutInSeconds: currentSettings.UserSessionIdleTimeoutInSeconds,
			UserSessionMaxLifetimeInSeconds: currentSettings.UserSessionMaxLifetimeInSeconds,
			MaxUserSessionsPerUser:          currentSettings.MaxUserSessionsPerUser,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}

// sessionsSettingsAuditValues is the three session settings as updated_sessions_settings records
// them under old and new.
func sessionsSettingsAuditValues(settings *record.Settings) map[string]interface{} {
	return map[string]interface{}{
		"user_session_idle_timeout_in_seconds": settings.UserSessionIdleTimeoutInSeconds,
		"user_session_max_lifetime_in_seconds": settings.UserSessionMaxLifetimeInSeconds,
		"max_user_sessions_per_user":           settings.MaxUserSessionsPerUser,
	}
}
