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

// HandleAPISettingsTokensGet - GET /api/v1/admin/settings/tokens
func HandleAPISettingsTokensGet(
	httpHelper handlers.HttpHelper,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if settings == nil {
			writeInternalServerError(w, r, errs.New("settings are missing from the request context"))
			return
		}

		resp := api.SettingsTokensResponse{
			TokenExpirationInSeconds:                settings.TokenExpirationInSeconds,
			RefreshTokenOfflineIdleTimeoutInSeconds: settings.RefreshTokenOfflineIdleTimeoutInSeconds,
			RefreshTokenOfflineMaxLifetimeInSeconds: settings.RefreshTokenOfflineMaxLifetimeInSeconds,
			IncludeOpenIDConnectClaimsInAccessToken: settings.IncludeOpenIDConnectClaimsInAccessToken,
			IncludeOpenIDConnectClaimsInIdToken:     settings.IncludeOpenIDConnectClaimsInIdToken,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}

// HandleAPISettingsTokensPut - PUT /api/v1/admin/settings/tokens
func HandleAPISettingsTokensPut(
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

		var req api.UpdateSettingsTokensRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		// Preserve existing behavior: values must be > 0 and <= max, and idle <= max lifetime
		const maxValue = 160000000
		if req.TokenExpirationInSeconds <= 0 {
			writeJSONError(w, "Token expiration in seconds must be greater than zero.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if req.TokenExpirationInSeconds > maxValue {
			writeJSONError(w, fmt.Sprintf("Token expiration in seconds cannot be greater than %v.", maxValue), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if req.RefreshTokenOfflineIdleTimeoutInSeconds <= 0 {
			writeJSONError(w, "Refresh token offline - idle timeout in seconds must be greater than zero.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if req.RefreshTokenOfflineIdleTimeoutInSeconds > maxValue {
			writeJSONError(w, fmt.Sprintf("Refresh token offline - idle timeout in seconds cannot be greater than %v.", maxValue), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if req.RefreshTokenOfflineMaxLifetimeInSeconds <= 0 {
			writeJSONError(w, "Refresh token offline - max lifetime in seconds must be greater than zero.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if req.RefreshTokenOfflineMaxLifetimeInSeconds > maxValue {
			writeJSONError(w, fmt.Sprintf("Refresh token offline - max lifetime in seconds cannot be greater than %v.", maxValue), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if req.RefreshTokenOfflineIdleTimeoutInSeconds > req.RefreshTokenOfflineMaxLifetimeInSeconds {
			writeJSONError(w, "Refresh token offline - idle timeout cannot be greater than max lifetime.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Capture old values for auditing
		oldVals := map[string]interface{}{
			"tokenExpirationInSeconds":                currentSettings.TokenExpirationInSeconds,
			"refreshTokenOfflineIdleTimeoutInSeconds": currentSettings.RefreshTokenOfflineIdleTimeoutInSeconds,
			"refreshTokenOfflineMaxLifetimeInSeconds": currentSettings.RefreshTokenOfflineMaxLifetimeInSeconds,
			"includeOpenIDConnectClaimsInAccessToken": currentSettings.IncludeOpenIDConnectClaimsInAccessToken,
			"includeOpenIDConnectClaimsInIdToken":     currentSettings.IncludeOpenIDConnectClaimsInIdToken,
		}

		// Apply updates
		currentSettings.TokenExpirationInSeconds = req.TokenExpirationInSeconds
		currentSettings.RefreshTokenOfflineIdleTimeoutInSeconds = req.RefreshTokenOfflineIdleTimeoutInSeconds
		currentSettings.RefreshTokenOfflineMaxLifetimeInSeconds = req.RefreshTokenOfflineMaxLifetimeInSeconds
		currentSettings.IncludeOpenIDConnectClaimsInAccessToken = req.IncludeOpenIDConnectClaimsInAccessToken
		currentSettings.IncludeOpenIDConnectClaimsInIdToken = req.IncludeOpenIDConnectClaimsInIdToken

		if err := database.UpdateSettings(nil, currentSettings); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Audit with old/new values
		newVals := map[string]interface{}{
			"tokenExpirationInSeconds":                currentSettings.TokenExpirationInSeconds,
			"refreshTokenOfflineIdleTimeoutInSeconds": currentSettings.RefreshTokenOfflineIdleTimeoutInSeconds,
			"refreshTokenOfflineMaxLifetimeInSeconds": currentSettings.RefreshTokenOfflineMaxLifetimeInSeconds,
			"includeOpenIDConnectClaimsInAccessToken": currentSettings.IncludeOpenIDConnectClaimsInAccessToken,
			"includeOpenIDConnectClaimsInIdToken":     currentSettings.IncludeOpenIDConnectClaimsInIdToken,
		}
		auditLogger.Log(constants.AuditUpdatedTokensSettings, map[string]interface{}{
			"loggedInUser": authHelper.GetLoggedInSubject(r),
			"old":          oldVals,
			"new":          newVals,
		})

		resp := api.SettingsTokensResponse{
			TokenExpirationInSeconds:                currentSettings.TokenExpirationInSeconds,
			RefreshTokenOfflineIdleTimeoutInSeconds: currentSettings.RefreshTokenOfflineIdleTimeoutInSeconds,
			RefreshTokenOfflineMaxLifetimeInSeconds: currentSettings.RefreshTokenOfflineMaxLifetimeInSeconds,
			IncludeOpenIDConnectClaimsInAccessToken: currentSettings.IncludeOpenIDConnectClaimsInAccessToken,
			IncludeOpenIDConnectClaimsInIdToken:     currentSettings.IncludeOpenIDConnectClaimsInIdToken,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}
