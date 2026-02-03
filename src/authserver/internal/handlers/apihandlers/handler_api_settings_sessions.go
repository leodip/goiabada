package apihandlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

// HandleAPISettingsSessionsGet - GET /api/v1/admin/settings/sessions
func HandleAPISettingsSessionsGet(
	httpHelper handlers.HttpHelper,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if settings == nil {
			writeJSONError(w, "Failed to load settings", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		resp := api.SettingsSessionsResponse{
			UserSessionIdleTimeoutInSeconds: settings.UserSessionIdleTimeoutInSeconds,
			UserSessionMaxLifetimeInSeconds: settings.UserSessionMaxLifetimeInSeconds,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, resp)
	}
}

// HandleAPISettingsSessionsPut - PUT /api/v1/admin/settings/sessions
func HandleAPISettingsSessionsPut(
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

		var req api.UpdateSettingsSessionsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
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

		if err := database.UpdateSettings(nil, currentSettings); err != nil {
			writeJSONError(w, "Failed to update settings", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Audit log
		auditLogger.Log(constants.AuditUpdatedSessionsSettings, map[string]interface{}{
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		resp := api.SettingsSessionsResponse{
			UserSessionIdleTimeoutInSeconds: currentSettings.UserSessionIdleTimeoutInSeconds,
			UserSessionMaxLifetimeInSeconds: currentSettings.UserSessionMaxLifetimeInSeconds,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, resp)
	}
}
