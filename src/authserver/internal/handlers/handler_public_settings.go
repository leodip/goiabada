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

	// Map to public response DTO
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
