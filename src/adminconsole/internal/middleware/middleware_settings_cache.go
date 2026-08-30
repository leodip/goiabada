package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/cache"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
)

// MiddlewareSettingsCache adds settings to the request context by fetching from the cache
func MiddlewareSettingsCache(settingsCache *cache.SettingsCache) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Fetch settings from cache (auto-refreshes if expired)
			publicSettings, err := settingsCache.Get()
			if err != nil {
				// The detail goes to the log rather than to the browser. It names the auth
				// server's address and whatever the transport failed with, which the operator
				// needs and the person looking at the page cannot act on, and until now it went
				// only to the browser and was never logged at all.
				//
				// err.Error() rather than err: slog renders an error value with %+v, and this
				// one carries a pkg/errors stack. The cache does not cache a failure, so an auth
				// server that is down produces one of these per request, and the stack is the
				// same three frames every time.
				slog.Error("unable to fetch settings from the auth server", "error", err.Error())
				http.Error(w, i18n.T(r.Context(), "adminconsole.error.settings_unavailable"), http.StatusInternalServerError)
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
			// Both refusals answer in plain text rather than through the error page every
			// other 500 in this module renders: that page reads settings off the context for
			// its layout, and settings are the thing that is missing here.
			//
			// They are localized, which they could not be until i18n.MiddlewareLocale was
			// moved ahead of this middleware on the application branch. Server.initMiddleware
			// records why that reorder is safe.
			if publicSettings.Issuer == "" {
				slog.Error("the auth server did not report an issuer; it may be running an older version")
				http.Error(w, i18n.T(r.Context(), "adminconsole.error.issuer_missing"), http.StatusInternalServerError)
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
