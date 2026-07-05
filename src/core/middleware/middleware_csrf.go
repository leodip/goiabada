package middleware

import (
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
)

// csrfCookieMaxAgeSeconds keeps the CSRF cookie valid for a year so it never
// expires before a session (whose real length is governed by the session
// idle/max-lifetime settings). gorilla/csrf's default is only 12h, which could
// expire mid-session if the idle timeout is raised above it. The CSRF token is
// session-bound, so a longer lifetime is not a credential-exposure concern.
const csrfCookieMaxAgeSeconds = 86400 * 365

func MiddlewareSkipCsrf() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// Resolve the effective request path: chi's StripSlashes middleware
			// writes the normalized path to RouteContext.RoutePath (not r.URL.Path)
			// when a RouteContext is present. Fall back to r.URL.Path to keep this
			// safe outside chi (e.g. unit tests that don't wire chi).
			path := r.URL.Path
			if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.RoutePath != "" {
				path = rctx.RoutePath
			}

			skip := strings.HasPrefix(path, "/static") ||
				strings.HasPrefix(path, "/userinfo") ||
				strings.HasPrefix(path, "/auth/token") ||
				path == "/auth/authorize" ||
				strings.HasPrefix(path, "/auth/callback") ||
				strings.HasPrefix(path, "/connect/") ||
				strings.HasPrefix(path, "/api/")

			if skip {
				r = csrf.UnsafeSkipCheck(r)
			}
			next.ServeHTTP(w, r.WithContext(r.Context()))
		}
		return http.HandlerFunc(fn)
	}
}

func MiddlewareCsrf(sessionAuthKeyHex string, baseURL, adminConsoleBaseURL string, setCookieSecure bool) func(next http.Handler) http.Handler {
	// For gorilla/csrf v1.7.3+, we need to explicitly set TrustedOrigins for localhost development
	// This is required due to stricter origin validation introduced in v1.7.3

	// Extract hosts from configured URLs for production safety

	var trustedOrigins []string

	// Parse base URL to get host
	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		trustedOrigins = append(trustedOrigins, u.Host)
	}

	// Parse admin URL to get host
	if u, err := url.Parse(adminConsoleBaseURL); err == nil && u.Host != "" {
		// Avoid duplicates
		if len(trustedOrigins) == 0 || trustedOrigins[0] != u.Host {
			trustedOrigins = append(trustedOrigins, u.Host)
		}
	}

	slog.Info("CSRF middleware configured", "trustedOrigins", trustedOrigins, "secure", setCookieSecure)

	// Decode the hex-encoded session authentication key
	sessionAuthKey, _ := hex.DecodeString(sessionAuthKeyHex)

	return csrf.Protect(
		sessionAuthKey,
		csrf.Secure(setCookieSecure),
		csrf.TrustedOrigins(trustedOrigins),
		csrf.MaxAge(csrfCookieMaxAgeSeconds),
	)
}
