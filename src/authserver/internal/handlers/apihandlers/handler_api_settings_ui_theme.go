package apihandlers

import (
    "encoding/json"
    "net/http"
    "strings"

    "github.com/leodip/goiabada/authserver/internal/handlers"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/data"
    "github.com/leodip/goiabada/core/models"
    "github.com/leodip/goiabada/core/uithemes"
)

// HandleAPISettingsUIThemeGet - GET /api/v1/admin/settings/ui-theme
func HandleAPISettingsUIThemeGet(
    httpHelper handlers.HttpHelper,
    database data.Database,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
        if settings == nil {
            writeJSONError(w, "Failed to load settings", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        resp := api.SettingsUIThemeResponse{
            UITheme:         settings.UITheme,
            AvailableThemes: uithemes.Get(),
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        httpHelper.EncodeJson(w, r, resp)
    }
}

// HandleAPISettingsUIThemePut - PUT /api/v1/admin/settings/ui-theme
func HandleAPISettingsUIThemePut(
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

        var req api.UpdateSettingsUIThemeRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
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

        if err := database.UpdateSettings(nil, currentSettings); err != nil {
            writeJSONError(w, "Failed to update settings", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Audit log old/new
        auditLogger.Log(constants.AuditUpdatedUIThemeSettings, map[string]interface{}{
            "loggedInUser": authHelper.GetLoggedInSubject(r),
            "oldUITheme":   oldTheme,
            "newUITheme":   currentSettings.UITheme,
        })

        resp := api.SettingsUIThemeResponse{
            UITheme:         currentSettings.UITheme,
            AvailableThemes: uithemes.Get(),
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        httpHelper.EncodeJson(w, r, resp)
    }
}

