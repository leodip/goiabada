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

// HandleSettingsTokensGet - GET /api/v1/admin/settings/tokens
func HandleSettingsTokensGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
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

// settingsTokensDatabase is what the token settings endpoint needs: the settings write.
type settingsTokensDatabase interface {
	UpdateSettings(ctx context.Context, tx *sql.Tx, settings *record.Settings) error
}

// HandleSettingsTokensPut - PUT /api/v1/admin/settings/tokens
func HandleSettingsTokensPut(
	database settingsTokensDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentSettings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		var req api.UpdateSettingsTokensRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Preserve existing behavior: values must be > 0 and <= max, and idle <= max lifetime
		const maxValue = 160000000
		if req.TokenExpirationInSeconds <= 0 {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTokensTokenExpirationNotPositive, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if req.TokenExpirationInSeconds > maxValue {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTokensTokenExpirationTooLarge, map[string]any{"max": maxValue}), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if req.RefreshTokenOfflineIdleTimeoutInSeconds <= 0 {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTokensOfflineIdleTimeoutNotPositive, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if req.RefreshTokenOfflineIdleTimeoutInSeconds > maxValue {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTokensOfflineIdleTimeoutTooLarge, map[string]any{"max": maxValue}), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if req.RefreshTokenOfflineMaxLifetimeInSeconds <= 0 {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTokensOfflineMaxLifetimeNotPositive, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if req.RefreshTokenOfflineMaxLifetimeInSeconds > maxValue {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTokensOfflineMaxLifetimeTooLarge, map[string]any{"max": maxValue}), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if req.RefreshTokenOfflineIdleTimeoutInSeconds > req.RefreshTokenOfflineMaxLifetimeInSeconds {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientTokensOfflineIdleTimeoutAboveMaxLifetime, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Capture old values for auditing
		oldVals := map[string]interface{}{
			"token_expiration_in_seconds":                    currentSettings.TokenExpirationInSeconds,
			"refresh_token_offline_idle_timeout_in_seconds":  currentSettings.RefreshTokenOfflineIdleTimeoutInSeconds,
			"refresh_token_offline_max_lifetime_in_seconds":  currentSettings.RefreshTokenOfflineMaxLifetimeInSeconds,
			"include_open_id_connect_claims_in_access_token": currentSettings.IncludeOpenIDConnectClaimsInAccessToken,
			"include_open_id_connect_claims_in_id_token":     currentSettings.IncludeOpenIDConnectClaimsInIdToken,
		}

		// Apply updates
		currentSettings.TokenExpirationInSeconds = req.TokenExpirationInSeconds
		currentSettings.RefreshTokenOfflineIdleTimeoutInSeconds = req.RefreshTokenOfflineIdleTimeoutInSeconds
		currentSettings.RefreshTokenOfflineMaxLifetimeInSeconds = req.RefreshTokenOfflineMaxLifetimeInSeconds
		currentSettings.IncludeOpenIDConnectClaimsInAccessToken = req.IncludeOpenIDConnectClaimsInAccessToken
		currentSettings.IncludeOpenIDConnectClaimsInIdToken = req.IncludeOpenIDConnectClaimsInIdToken

		if err := database.UpdateSettings(r.Context(), nil, currentSettings); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Audit with old/new values
		newVals := map[string]interface{}{
			"token_expiration_in_seconds":                    currentSettings.TokenExpirationInSeconds,
			"refresh_token_offline_idle_timeout_in_seconds":  currentSettings.RefreshTokenOfflineIdleTimeoutInSeconds,
			"refresh_token_offline_max_lifetime_in_seconds":  currentSettings.RefreshTokenOfflineMaxLifetimeInSeconds,
			"include_open_id_connect_claims_in_access_token": currentSettings.IncludeOpenIDConnectClaimsInAccessToken,
			"include_open_id_connect_claims_in_id_token":     currentSettings.IncludeOpenIDConnectClaimsInIdToken,
		}
		auditLogger.Log(r.Context(), audit.EventUpdatedTokensSettings, map[string]interface{}{
			"logged_in_user": callerSubject(r),
			"old":            oldVals,
			"new":            newVals,
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
