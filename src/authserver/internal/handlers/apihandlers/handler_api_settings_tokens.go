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

// settingsTokensDatabase is what the token settings endpoint needs: the settings save.
type settingsTokensDatabase interface {
	settingsSaveDatabase
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
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTokensTokenExpirationNotPositive, nil))
			return
		}
		if req.TokenExpirationInSeconds > maxValue {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTokensTokenExpirationTooLarge, map[string]any{"max": maxValue}))
			return
		}

		if req.RefreshTokenOfflineIdleTimeoutInSeconds <= 0 {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTokensOfflineIdleTimeoutNotPositive, nil))
			return
		}
		if req.RefreshTokenOfflineIdleTimeoutInSeconds > maxValue {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTokensOfflineIdleTimeoutTooLarge, map[string]any{"max": maxValue}))
			return
		}

		if req.RefreshTokenOfflineMaxLifetimeInSeconds <= 0 {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTokensOfflineMaxLifetimeNotPositive, nil))
			return
		}
		if req.RefreshTokenOfflineMaxLifetimeInSeconds > maxValue {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTokensOfflineMaxLifetimeTooLarge, map[string]any{"max": maxValue}))
			return
		}

		if req.RefreshTokenOfflineIdleTimeoutInSeconds > req.RefreshTokenOfflineMaxLifetimeInSeconds {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientTokensOfflineIdleTimeoutAboveMaxLifetime, nil))
			return
		}

		// Apply updates, onto the row as stored when the save runs (#407). The old values, for
		// auditing, are that row's, read under the save's lock, which is what the save replaced.
		var oldVals map[string]interface{}
		saved, err := saveSettingsSection(r.Context(), database, currentSettings.Id, func(stored *record.Settings) {
			oldVals = map[string]interface{}{
				"token_expiration_in_seconds":                    stored.TokenExpirationInSeconds,
				"refresh_token_offline_idle_timeout_in_seconds":  stored.RefreshTokenOfflineIdleTimeoutInSeconds,
				"refresh_token_offline_max_lifetime_in_seconds":  stored.RefreshTokenOfflineMaxLifetimeInSeconds,
				"include_open_id_connect_claims_in_access_token": stored.IncludeOpenIDConnectClaimsInAccessToken,
				"include_open_id_connect_claims_in_id_token":     stored.IncludeOpenIDConnectClaimsInIdToken,
			}
			stored.TokenExpirationInSeconds = req.TokenExpirationInSeconds
			stored.RefreshTokenOfflineIdleTimeoutInSeconds = req.RefreshTokenOfflineIdleTimeoutInSeconds
			stored.RefreshTokenOfflineMaxLifetimeInSeconds = req.RefreshTokenOfflineMaxLifetimeInSeconds
			stored.IncludeOpenIDConnectClaimsInAccessToken = req.IncludeOpenIDConnectClaimsInAccessToken
			stored.IncludeOpenIDConnectClaimsInIdToken = req.IncludeOpenIDConnectClaimsInIdToken
		})
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Audit with old/new values
		newVals := map[string]interface{}{
			"token_expiration_in_seconds":                    saved.TokenExpirationInSeconds,
			"refresh_token_offline_idle_timeout_in_seconds":  saved.RefreshTokenOfflineIdleTimeoutInSeconds,
			"refresh_token_offline_max_lifetime_in_seconds":  saved.RefreshTokenOfflineMaxLifetimeInSeconds,
			"include_open_id_connect_claims_in_access_token": saved.IncludeOpenIDConnectClaimsInAccessToken,
			"include_open_id_connect_claims_in_id_token":     saved.IncludeOpenIDConnectClaimsInIdToken,
		}
		auditLogger.Log(r.Context(), audit.EventUpdatedTokensSettings, map[string]interface{}{
			"logged_in_user": callerSubject(r),
			"old":            oldVals,
			"new":            newVals,
		})

		resp := api.SettingsTokensResponse{
			TokenExpirationInSeconds:                saved.TokenExpirationInSeconds,
			RefreshTokenOfflineIdleTimeoutInSeconds: saved.RefreshTokenOfflineIdleTimeoutInSeconds,
			RefreshTokenOfflineMaxLifetimeInSeconds: saved.RefreshTokenOfflineMaxLifetimeInSeconds,
			IncludeOpenIDConnectClaimsInAccessToken: saved.IncludeOpenIDConnectClaimsInAccessToken,
			IncludeOpenIDConnectClaimsInIdToken:     saved.IncludeOpenIDConnectClaimsInIdToken,
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}
