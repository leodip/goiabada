package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/core/handlerhelpers"
)

// csrfSkipContextKey marks a request that the exemption tables below have already cleared, so
// MiddlewareCsrf can honour a decision MiddlewareSkipCsrf made earlier in the chain. It replaces
// gorilla/csrf's UnsafeSkipCheck, which left with the library (#155).
//
// The key type is unexported and the value is written only by markCsrfSkipped, which is what stops
// any other package forging an exemption: a handler cannot name the key, so it cannot set it.
type csrfSkipContextKey struct{}

// markCsrfSkipped returns a request carrying the exemption mark. Callers must use the returned
// request, since context values are immutable.
func markCsrfSkipped(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), csrfSkipContextKey{}, true))
}

// csrfSkipped reports whether MiddlewareSkipCsrf cleared this request.
func csrfSkipped(r *http.Request) bool {
	skipped, _ := r.Context().Value(csrfSkipContextKey{}).(bool)
	return skipped
}

// csrfExemptExactPaths lists individual endpoints that are cross-origin by protocol design, so the
// origin check cannot apply to them. What stands in for it differs per endpoint, and stating that
// per endpoint matters: there is no single property they share. In particular they do NOT all
// authenticate the caller, and /auth/authorize does read the session cookie (#155).
//
//	/auth/authorize   - OAuth2 authorization endpoint (GET/POST). OIDC Core 3.1.2.1 requires both
//	                    methods. It does consult the session cookie for SSO, so the exemption rests
//	                    instead on a cross-site POST here reaching nothing a plain link would not:
//	                    it starts a ceremony, and every state-changing step it leads to (password,
//	                    OTP, consent) is itself origin-checked (#67).
//	/auth/token       - OAuth2 token endpoint (POST). A confidential client authenticates with its
//	                    secret; a public client instead redeems a one-time code bound to its
//	                    registered redirect URI and, when PKCE was used, to a code verifier. No
//	                    session cookie is read either way.
//	/auth/callback    - Admin-console OAuth callback: a cross-site form_post carrying
//	                    the auth code, protected by the OAuth `state` parameter (POST).
//	/userinfo         - OIDC userinfo; bearer-token authenticated (GET/POST).
//	/connect/register - Dynamic Client Registration (POST). Deliberately unauthenticated when
//	                    enabled: it creates a client rather than acting on a signed-in user, so
//	                    there is no user state for CSRF to reach. Disabled by default, rate limited.
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
//	/static/ - Static assets, served with safe methods (GET/HEAD) only, which the origin check
//	           never applies to anyway; listed for clarity.
var csrfExemptPrefixes = []string{
	"/api/",
	"/static/",
}

// csrfConditionalExemptions lists endpoints whose exemption depends on the request rather than only
// on its path. Matched EXACTLY, like csrfExemptExactPaths, and the predicate decides the rest; a
// path absent from all three tables keeps full CSRF protection.
//
//	/auth/logout - RP-initiated logout, exempt only for a POST carrying an id_token_hint. See
//	               logoutIdTokenHintPresent.
//
// This table exists because an unconditional entry above would be a hole: any site could then POST
// to /auth/logout with no hint and no token, and the handler treats a hintless POST as the
// confirmation of its consent page, so the End-User would be signed out without ever being asked.
var csrfConditionalExemptions = map[string]func(*http.Request) bool{
	"/auth/logout": logoutIdTokenHintPresent,
}

// logoutIdTokenHintPresent reports whether this is a POST to the logout endpoint carrying an
// id_token_hint, which is the one shape of /auth/logout that must work cross-site.
//
// OpenID Connect RP-Initiated Logout 1.0 section 2 is a MUST here: "OpenID Providers MUST support
// the use of the HTTP GET and POST methods defined in RFC 7231". Without an exemption the origin
// check rejects every cross-origin POST, so the binding exists for relying parties that cannot reach
// it, and an RP that wants a self-submitting form to keep the ID token out of the URL has no way in.
//
// PRESENCE, not a value, and read through the same function the handler classifies the parameter
// with. The two readings must agree in one direction above all: this saying "present" where the
// handler reads "absent" would exempt a cross-site POST and then send it down the hintless branch,
// which tears the whole session down with no consent. Sharing handlerhelpers'
// LookupFromUrlQueryOrFormPost is what makes that agreement structural rather than a promise, and
// it is why "id_token_hint=" is exempt here and Rejected there (#109).
//
// Presence alone is safe because middleware cannot judge whether a hint is genuine and the handler
// does not trust it to: a POST whose hint fails to validate tears nothing down, it is answered with
// a redirect to the GET binding and ends at the consent page. So the exemption buys an attacker a
// consent page they cannot confirm, which is where a plain link to /auth/logout already lands.
//
// POST only. Everything the origin check refuses is a POST here in practice, and confining it means
// the form parse below happens on one path and one method rather than on requests that have no
// business being read.
//
// The admin console registers this same middleware and mounts only GET /auth/logout, so a POST
// there is answered by chi with 405 before any handler runs. Exempting a route that does not exist
// changes nothing; noted so the shared table does not read as an oversight.
// Reading the body here does let a foreign origin have its body parsed before it is turned away,
// where the origin check would otherwise have rejected it on the headers alone. That is inherent
// to decision 9 rather than introduced by reading the body: the same origin need only move the hint
// into the query to reach the handler, which parses the body itself to honour ui_locales. Go bounds
// the parse the same way it bounds every other form endpoint here, and middleware_ratelimiter and
// middleware_jwt already parse forms on this side of the chain.
func logoutIdTokenHintPresent(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	// Reads the query first and only then the body, so a hint in the query costs no parse. When it
	// does parse, Go caches the result in r.PostForm and the handler's own r.FormValue reuses it,
	// which is what stops this middleware consuming the body the handler is about to read.
	_, present := handlerhelpers.LookupFromUrlQueryOrFormPost(r, "id_token_hint")
	return present
}

// shouldSkipCsrf reports whether CSRF protection should be bypassed for this request. CSRF defends
// the state-changing requests a browser makes on a signed-in person's behalf; the exempt paths are
// bindings a protocol requires to work cross-origin, or safe-method static assets, so enforcing the
// origin check on them would break legitimate callers rather than stop an attacker. What replaces
// it differs per endpoint: see csrfExemptExactPaths, csrfExemptPrefixes and
// csrfConditionalExemptions for the rationale of each, and do not assume a shared one (#155).
//
// The path is passed in rather than read off the request because the caller has already resolved
// chi's normalized RoutePath, which is what a trailing slash arrives as.
func shouldSkipCsrf(r *http.Request, path string) bool {
	if csrfExemptExactPaths[path] {
		return true
	}
	for _, prefix := range csrfExemptPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	// Last, so an unconditional entry always wins and no predicate is consulted, and with it no
	// request body read, for a path that was exempt anyway.
	if exempt, ok := csrfConditionalExemptions[path]; ok {
		return exempt(r)
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

			if shouldSkipCsrf(r, path) {
				r = markCsrfSkipped(r)
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

// MiddlewareCsrf rejects state-changing cross-origin requests, using
// net/http.CrossOriginProtection: the browser's own Sec-Fetch-Site report, falling back to
// comparing the Origin header's host against Host when that header is absent.
//
// It takes no parameters, and each of the four it used to take left for its own reason (#155):
//
//   - No trusted origins. AddTrustedOrigin is deliberately never called. Every cross-site POST this
//     system serves is already listed in the exemption tables above, so there is nothing for a
//     trusted list to hold, and an entry added speculatively would silently widen the boundary for
//     whatever cross-origin POST someone adds next. Trusting a host across both schemes is exactly
//     what CVE-2025-47909 was, so the absence is the point.
//   - No AddInsecureBypassPattern. The exemption tables and MiddlewareSkipCsrf already own that
//     decision, including the conditional /auth/logout predicate, which a pattern cannot express.
//   - No session key and no cookie. There is no CSRF token: the origin is the whole control.
//   - No cookie-secure flag. The check never consults the server's idea of its own scheme, so a
//     plain-HTTP deployment needs no configuration to work.
//
// Check is called inline rather than through CrossOriginProtection.Handler so the skip mark can
// short-circuit it and so explainCsrfFailure still holds the request, which is the only thing that
// can tell the failure causes apart.
func MiddlewareCsrf() func(next http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if csrfSkipped(r) {
				next.ServeHTTP(w, r)
				return
			}

			err := cop.Check(r)
			if err == nil {
				next.ServeHTTP(w, r)
				return
			}

			// A CSRF rejection is otherwise a bare 403 with a five-word body, which tells an
			// operator nothing: the same status covers a genuine attack, a stale form, a
			// misconfigured base URL and a response header interfering with the browser. This
			// explains which of those it was and what to do about it.
			//
			// Nothing sensitive is logged: no cookies, no request body. Header values are
			// attacker-controlled, so they go in structured fields where the handler quotes them,
			// never interpolated into the message.
			explanation, remedy := explainCsrfFailure(r)

			slog.Warn(explanation,
				"remedy", remedy,
				"reason", err,
				"method", r.Method,
				"path", r.URL.Path,
				"requestHost", r.Host,
				"originHeader", headerOrPlaceholder(r, "Origin"),
				"secFetchSite", headerOrPlaceholder(r, "Sec-Fetch-Site"),
			)

			http.Error(w, fmt.Sprintf("%s - %s",
				http.StatusText(http.StatusForbidden), err),
				http.StatusForbidden)
		})
	}
}

// explainCsrfFailure turns a rejection into a sentence an operator can act on, plus a one-line
// remedy. The wording distinguishes "your deployment is misconfigured" from "a browser behaved
// unexpectedly" from "this may be a real attack", because the same 403 covers all three and guessing
// between them has cost real debugging time.
//
// It branches on the request rather than on the error, and has to: both of the errors
// CrossOriginProtection.Check returns are unexported package-level values in net/http, so errors.Is
// has no target and only string comparison could separate them, which would break on any Go release.
// It does not need the error anyway, because the two headers Check consults fully determine the
// cause (#155).
func explainCsrfFailure(r *http.Request) (explanation, remedy string) {
	origin := r.Header.Get("Origin")
	secFetchSite := r.Header.Get("Sec-Fetch-Site")

	switch secFetchSite {
	case "cross-site":
		return "CSRF rejected a state-changing request that the browser itself reported as cross-site. " +
				"No origin is trusted for state-changing requests other than this deployment's own, so a genuine " +
				"third-party page reaching a form endpoint is refused here and this is usually the control working.",
			"If the origin is foreign, no action is needed. If it is one of our own hosts, the deployment is being reached on a hostname or port the browser sees as a different site: browse using exactly the configured base URL."

	case "same-site":
		return "CSRF rejected a state-changing request from a sibling host on the same registrable domain. " +
				"Same-site is not same-origin: a different subdomain, port or scheme lands here, and unlike a " +
				"cross-site rejection this usually means a real deployment misconfiguration rather than an attack.",
			"Serve the form and its target from one origin. Reaching the app on a second hostname that resolves to it (for example a bare domain alongside a www host) fails here, and so does mixing http and https."
	}

	// Below here Sec-Fetch-Site must be genuinely absent, not merely unrecognized. Check refuses any
	// value it does not know without ever reaching the Origin comparison, so diagnosing such a request
	// as "no Sec-Fetch-Site" would name the wrong cause. W3C Fetch Metadata section 2.3 enumerates
	// exactly four values, so an unrecognized one is a header somebody or something forged, and the
	// generic fallback at the bottom is the honest answer for it.
	switch {
	case secFetchSite != "":
		// Fall through to the fallback.

	case origin == "null":
		return "CSRF rejected a state-changing request because the browser sent an opaque origin (Origin: null) " +
				"and no Sec-Fetch-Site header to override it. An opaque origin has no host to compare against ours, " +
				"and this is not an attack signature: a browser produces it on a form POST when the page was served " +
				"with Referrer-Policy: no-referrer.",
			"Check the Referrer-Policy response header before touching any CSRF setting. It must not be no-referrer; same-origin keeps codes and state off other origins without producing an opaque origin."

	case origin != "":
		return "CSRF rejected a state-changing request whose Origin host did not match the Host header, with no " +
				"Sec-Fetch-Site header to decide it. Every browser has sent Sec-Fetch-Site since 2023, so this is " +
				"an out-of-date browser, a non-browser client, or a reverse proxy rewriting Host into something " +
				"the browser never asked for.",
			"Compare the Origin and requestHost fields below. If they differ only by proxy rewriting, configure the proxy to preserve the original Host header. If they are genuinely different sites, this rejection is the control working."
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
