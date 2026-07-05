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

// csrfExemptExactPaths lists individual endpoints that carry no session cookie
// and therefore have no CSRF token to present. Each authenticates by another
// means:
//
//	/auth/authorize   - OAuth2 authorization endpoint (GET/POST); not cookie-authenticated.
//	/auth/token       - OAuth2 token endpoint; client-authenticated (POST).
//	/auth/callback    - Admin-console OAuth callback: a cross-site form_post carrying
//	                    the auth code, protected by the OAuth `state` parameter (POST).
//	/userinfo         - OIDC userinfo; bearer-token authenticated (GET/POST).
//	/connect/register - Dynamic Client Registration; client/none auth (POST).
//
// These are matched EXACTLY, not by prefix, so a future sibling route (e.g.
// /auth/token-introspect or /userinfo-export) is NOT silently exempted: it keeps
// full CSRF protection until it is deliberately added to this list.
var csrfExemptExactPaths = map[string]bool{
	"/auth/authorize":   true,
	"/auth/token":       true,
	"/auth/callback":    true,
	"/userinfo":         true,
	"/connect/register": true,
}

// csrfExemptPrefixes lists whole subtrees where prefix inheritance is
// intentional (unlike the exact paths above):
//
//	/api/    - Bearer-token REST API surface. Every route authenticates via the
//	           Authorization header, never the session cookie, so new endpoints
//	           added under this prefix SHOULD inherit the exemption. Cookie-
//	           authenticated routes must never be mounted here.
//	/static/ - Static assets, served with safe methods (GET/HEAD) only, which
//	           gorilla/csrf never checks anyway; listed for clarity.
var csrfExemptPrefixes = []string{
	"/api/",
	"/static/",
}

// shouldSkipCsrf reports whether CSRF protection should be bypassed for the
// given request path. CSRF defends cookie-authenticated, state-changing
// requests; the exempt paths carry no session cookie (they are bearer/client-
// authenticated or safe-method static assets), so a CSRF token would never be
// present and enforcing it would only break legitimate non-browser clients.
// See csrfExemptExactPaths and csrfExemptPrefixes for the per-endpoint rationale.
func shouldSkipCsrf(path string) bool {
	if csrfExemptExactPaths[path] {
		return true
	}
	for _, prefix := range csrfExemptPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

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

			if shouldSkipCsrf(path) {
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
