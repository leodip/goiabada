package middleware

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/cache"
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

			// The issuer has one writer, the auth server that stamps it into the iss
			// claim, so refuse to serve a request rather than guess it. oauth.IsIssuerValid
			// is plain string equality, so an expected issuer of "" rejects every token
			// the auth server can mint and locks the administrator out of the console
			// silently, which is the thing this check exists to end (#285). The only live
			// route here is an auth server too old to serve the field: an absent settings
			// row already answers 500 on its side, and the settings API refuses to store
			// an issuer shorter than three characters.
			//
			// English regardless of the request's locale, like the settings-fetch failure
			// above it and like a CSRF rejection: this middleware is mounted ahead of
			// i18n.MiddlewareLocale, so no localizer exists yet when either branch answers.
			// Server.initMiddleware records why the chain is ordered that way.
			if publicSettings.Issuer == "" {
				http.Error(w, "The authserver did not report an issuer; it may be running an older version", http.StatusInternalServerError)
				return
			}

			// Convert to models.Settings for compatibility with existing code
			// Note: every field here comes from the auth server's public API
			settings := &models.Settings{
				AppName:     publicSettings.AppName,
				Issuer:      publicSettings.Issuer,
				UITheme:     publicSettings.UITheme,
				SMTPEnabled: publicSettings.SMTPEnabled,
			}

			// Add settings to request context
			ctx := context.WithValue(r.Context(), constants.ContextKeySettings, settings)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
