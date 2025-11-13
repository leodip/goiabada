package middleware

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/cache"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
)

// MiddlewareSettingsCache adds settings to the request context by fetching from the cache
func MiddlewareSettingsCache(settingsCache *cache.SettingsCache) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Fetch settings from cache (auto-refreshes if expired)
			publicSettings, err := settingsCache.Get()
			if err != nil {
				// Return error to user as per requirement
				http.Error(w, "Unable to fetch settings from authserver: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Get issuer from config (defaults to auth server base URL)
			issuer := config.GetAdminConsole().Issuer

			// Convert to models.Settings for compatibility with existing code
			// Note: We populate fields from public API and issuer from config
			settings := &models.Settings{
				AppName:     publicSettings.AppName,
				Issuer:      issuer,
				UITheme:     publicSettings.UITheme,
				SMTPEnabled: publicSettings.SMTPEnabled,
			}

			// Add settings to request context
			ctx := context.WithValue(r.Context(), constants.ContextKeySettings, settings)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
