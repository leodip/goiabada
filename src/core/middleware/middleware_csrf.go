package middleware

import (
	"encoding/hex"
	"errors"
	"fmt"
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

	// A CSRF rejection is otherwise a bare 403 with a five-word body, which tells an
	// operator nothing: the same status covers a genuine attack, a stale form, a
	// misconfigured base URL and a response header interfering with the browser. This
	// handler explains which of those it was and what to do about it, then reproduces
	// gorilla's own response body exactly (unauthorizedHandler, csrf.go:374) so the
	// response is unchanged.
	//
	// Nothing sensitive is logged: no cookies, no token value, no request body. Header
	// values are attacker-controlled, so they go in structured fields where the handler
	// quotes them, never interpolated into the message.
	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reason := csrf.FailureReason(r)
		explanation, remedy := explainCsrfFailure(reason, r)

		slog.Warn(explanation,
			"remedy", remedy,
			"reason", reason,
			"method", r.Method,
			"path", r.URL.Path,
			"requestHost", r.Host,
			"originHeader", headerOrPlaceholder(r, "Origin"),
			"refererHeader", headerOrPlaceholder(r, "Referer"),
			"secFetchSite", headerOrPlaceholder(r, "Sec-Fetch-Site"),
			"trustedOrigins", trustedOrigins,
			"hasCsrfCookie", hasCookie(r, "_gorilla_csrf"),
		)

		http.Error(w, fmt.Sprintf("%s - %s",
			http.StatusText(http.StatusForbidden), reason),
			http.StatusForbidden)
	})

	return csrf.Protect(
		sessionAuthKey,
		csrf.Secure(setCookieSecure),
		csrf.TrustedOrigins(trustedOrigins),
		csrf.MaxAge(csrfCookieMaxAgeSeconds),
		csrf.ErrorHandler(errorHandler),
	)
}

// explainCsrfFailure turns a gorilla/csrf failure into a sentence an operator can act on,
// plus a one-line remedy. Each branch corresponds to one of the five errors gorilla can
// report, and the wording distinguishes "your deployment is misconfigured" from "a browser
// behaved unexpectedly" from "this may be a real attack", because the same 403 covers all
// three and guessing between them has cost real debugging time.
func explainCsrfFailure(reason error, r *http.Request) (explanation, remedy string) {
	origin := r.Header.Get("Origin")

	switch {
	case errors.Is(reason, csrf.ErrBadOrigin) && origin == "null":
		return "CSRF rejected a state-changing request because the browser sent an opaque origin (Origin: null). " +
				"An opaque origin has no host, so no trusted origin can ever match it, and this is not an attack signature: " +
				"a browser produces it on a form POST when the page was served with Referrer-Policy: no-referrer.",
			"Check the Referrer-Policy response header before touching any CSRF setting. It must not be no-referrer; same-origin keeps codes and state off other origins without breaking the Origin header."

	case errors.Is(reason, csrf.ErrBadOrigin) && origin == "":
		return "CSRF rejected a state-changing request for an invalid origin, but no Origin header was present, " +
				"which means the header was there and unparseable rather than absent.",
			"Look for a proxy or client rewriting the Origin header."

	case errors.Is(reason, csrf.ErrBadOrigin):
		return "CSRF rejected a state-changing request because it came from an origin that is not trusted. " +
				"The trusted list is derived from the configured base URLs, so this is usually a host-spelling mismatch " +
				"rather than an attack: reaching the app on 127.0.0.1 when it is configured as localhost fails here, and so does the reverse.",
			"Browse using exactly the configured base URL, or correct GOIABADA_AUTHSERVER_BASEURL and GOIABADA_ADMINCONSOLE_BASEURL. If the origin is genuinely foreign, this rejection is the control working."

	case errors.Is(reason, csrf.ErrNoReferer):
		return "CSRF rejected a state-changing request that carried neither an Origin nor a Referer header. " +
				"Browsers send at least one for form POSTs, so this is typically a non-browser client, a stripped-header proxy, or a hand-made request.",
			"If this came from a legitimate integration, it needs to use the API endpoints under /api/, which authenticate by bearer token and are exempt from CSRF."

	case errors.Is(reason, csrf.ErrBadReferer):
		return "CSRF rejected a state-changing request because its Referer did not match this origin. " +
				"Over TLS, gorilla/csrf falls back to a strict Referer check when no Origin is present, and it requires an https referer.",
			"Confirm the deployment's base URL scheme matches how the browser reached it, and that no proxy is rewriting Referer."

	case errors.Is(reason, csrf.ErrNoToken):
		return "CSRF rejected a state-changing request that carried no CSRF token. " +
				"The origin checks passed, so this is about the form rather than the caller: the page was probably rendered without the hidden token field, or the request did not come from one of our forms.",
			"If a form is affected, check that its template renders the csrfField. If a script or tool sent this, it needs the token from the rendered page."

	case errors.Is(reason, csrf.ErrBadToken):
		return "CSRF rejected a state-changing request whose CSRF token did not match the one bound to the session cookie. " +
				"The usual cause is a form left open long enough for the cookie to be replaced, or a page restored from the browser's back-forward cache.",
			"Reload the page and resubmit. If it recurs immediately, suspect the session cookie being rewritten, for example by two deployments sharing a host on different ports."
	}

	return "CSRF rejected a state-changing request.", "See the reason field."
}

// headerOrPlaceholder distinguishes an absent header from one present but empty, which is
// the difference between "the browser sent nothing" and "something stripped the value".
func headerOrPlaceholder(r *http.Request, name string) string {
	if _, ok := r.Header[http.CanonicalHeaderKey(name)]; !ok {
		return "<absent>"
	}
	return r.Header.Get(name)
}

func hasCookie(r *http.Request, name string) bool {
	_, err := r.Cookie(name)
	return err == nil
}
