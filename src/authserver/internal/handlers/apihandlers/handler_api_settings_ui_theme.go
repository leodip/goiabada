package apihandlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/uithemes"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
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

// settingsUIThemeDatabase is what the UI theme settings endpoint needs: the settings save.
type settingsUIThemeDatabase interface {
	settingsSaveDatabase
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
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsUIThemeInvalid, nil))
				return
			}
		}

		// The old theme is the stored row's, read under the save's lock, which is what it replaced.
		var oldTheme string
		saved, err := saveSettingsSection(r.Context(), database, currentSettings.Id, func(stored *record.Settings) {
			oldTheme = stored.UITheme
			stored.UITheme = desired
		})
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Audit log old/new
		auditLogger.Log(r.Context(), audit.EventUpdatedUIThemeSettings, map[string]interface{}{
			"logged_in_user": callerSubject(r),
			"old_ui_theme":   oldTheme,
			"new_ui_theme":   saved.UITheme,
		})

		resp := api.SettingsUIThemeResponse{
			UITheme:         saved.UITheme,
			AvailableThemes: uithemes.Get(),
		}

		writeJSON(w, r, http.StatusOK, resp)
	}
}
