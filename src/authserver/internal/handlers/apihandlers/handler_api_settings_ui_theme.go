package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/uithemes"
	"github.com/leodip/goiabada/core/api"
)

// HandleSettingsUIThemeGet - GET /api/v1/admin/settings/ui-theme
func HandleSettingsUIThemeGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		resp := api.SettingsUIThemeResponse{
			UITheme:         settings.UITheme,
			AvailableThemes: uithemes.Get(),
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}

// settingsUIThemeDatabase is what the UI theme settings endpoint needs: the settings write.
type settingsUIThemeDatabase interface {
	UpdateSettings(ctx context.Context, tx *sql.Tx, settings *models.Settings) error
}

// HandleSettingsUIThemePut - PUT /api/v1/admin/settings/ui-theme
func HandleSettingsUIThemePut(
	database settingsUIThemeDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentSettings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		var req api.UpdateSettingsUIThemeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		desired := strings.TrimSpace(req.UITheme)
		if desired != "" {
			valid := false
			for _, t := range uithemes.Get() {
				if t == desired {
					valid = true
					break
				}
			}
			if !valid {
				writeJSONError(w, "Invalid theme.", "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
		}

		oldTheme := currentSettings.UITheme
		currentSettings.UITheme = desired

		if err := database.UpdateSettings(r.Context(), nil, currentSettings); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Audit log old/new
		auditLogger.Log(r.Context(), audit.EventUpdatedUIThemeSettings, map[string]interface{}{
			"loggedInUser": callerSubject(r),
			"oldUITheme":   oldTheme,
			"newUITheme":   currentSettings.UITheme,
		})

		resp := api.SettingsUIThemeResponse{
			UITheme:         currentSettings.UITheme,
			AvailableThemes: uithemes.Get(),
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}
