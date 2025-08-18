package middleware

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
)

func MiddlewareSkipCsrf() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			skip := false
			if strings.HasPrefix(r.URL.Path, "/static") ||
				strings.HasPrefix(r.URL.Path, "/userinfo") ||
				strings.HasPrefix(r.URL.Path, "/auth/token") ||
				strings.HasPrefix(r.URL.Path, "/auth/callback") {
				skip = true
			}
			if skip {
				r = csrf.UnsafeSkipCheck(r)
			}
			next.ServeHTTP(w, r.WithContext(r.Context()))
		}
		return http.HandlerFunc(fn)
	}
}

func MiddlewareCsrf(settings *models.Settings) func(next http.Handler) http.Handler {
	// For gorilla/csrf v1.7.3+, we need to explicitly set TrustedOrigins for localhost development
	// This is required due to stricter origin validation introduced in v1.7.3
	
	// Extract hosts from configured URLs for production safety
	baseURL := config.Get().BaseURL
	adminURL := config.GetAdminConsole().BaseURL
	
	var trustedOrigins []string
	
	// Parse base URL to get host
	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		trustedOrigins = append(trustedOrigins, u.Host)
	}
	
	// Parse admin URL to get host  
	if u, err := url.Parse(adminURL); err == nil && u.Host != "" {
		// Avoid duplicates
		if len(trustedOrigins) == 0 || trustedOrigins[0] != u.Host {
			trustedOrigins = append(trustedOrigins, u.Host)
		}
	}
	
	slog.Info("CSRF middleware configured", "trustedOrigins", trustedOrigins, "secure", config.Get().SetCookieSecure)
	
	return csrf.Protect(
		settings.SessionAuthenticationKey,
		csrf.Secure(config.Get().SetCookieSecure),
		csrf.TrustedOrigins(trustedOrigins),
	)
}
