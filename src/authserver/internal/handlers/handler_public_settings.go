package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/dtos"
	"github.com/leodip/goiabada/core/data"
)

type HandlerPublicSettings struct {
	database data.Database
}

func NewHandlerPublicSettings(database data.Database) *HandlerPublicSettings {
	return &HandlerPublicSettings{
		database: database,
	}
}

func (h *HandlerPublicSettings) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get settings from database
	settings, err := h.database.GetSettingsById(nil, 1)
	if err != nil {
		http.Error(w, "Unable to retrieve settings", http.StatusInternalServerError)
		return
	}
	// GetSettingsById returns (nil, nil) when the row is absent, so this guard is
	// what stops an unauthenticated request from panicking the handler.
	if settings == nil {
		http.Error(w, "Unable to retrieve settings", http.StatusInternalServerError)
		return
	}

	// Map to public response DTO. Only the fields below may ever appear here:
	// this endpoint needs no authentication, so the DTO is the whole boundary
	// between an anonymous caller and the 32 fields of models.Settings, which
	// include the legacy AES encryption key and the encrypted SMTP password.
	// handler_public_settings_test.go fails if that boundary widens.
	response := dtos.PublicSettingsResponse{
		AppName:     settings.AppName,
		UITheme:     settings.UITheme,
		SMTPEnabled: settings.SMTPEnabled,
	}

	// Set content type and return JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Unable to encode response", http.StatusInternalServerError)
		return
	}
}
