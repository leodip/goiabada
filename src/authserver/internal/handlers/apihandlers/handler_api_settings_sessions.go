package apihandlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/models"
)

// HandleAPISettingsSessionsGet - GET /api/v1/admin/settings/sessions
func HandleAPISettingsSessionsGet(
	httpHelper handlers.HttpHelper,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if settings == nil {
			writeInternalServerError(w, r, errs.New("settings are missing from the request context"))
			return
		}

		resp := api.SettingsSessionsResponse{
			UserSessionIdleTimeoutInSeconds: settings.UserSessionIdleTimeoutInSeconds,
			UserSessionMaxLifetimeInSeconds: settings.UserSessionMaxLifetimeInSeconds,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}

// HandleAPISettingsSessionsPut - PUT /api/v1/admin/settings/sessions
func HandleAPISettingsSessionsPut(
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentSettings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if currentSettings == nil {
			writeInternalServerError(w, r, errs.New("settings are missing from the request context"))
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

		if err := database.UpdateSettings(nil, currentSettings); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), constants.AuditUpdatedSessionsSettings, map[string]interface{}{
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		resp := api.SettingsSessionsResponse{
			UserSessionIdleTimeoutInSeconds: currentSettings.UserSessionIdleTimeoutInSeconds,
			UserSessionMaxLifetimeInSeconds: currentSettings.UserSessionMaxLifetimeInSeconds,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}
