package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging"
)

// csrfSkipContextKey marks a request that the application's CsrfPolicy has already cleared, so
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

// CsrfPolicy is one application's set of endpoints that are cross-origin by protocol design, so
// the origin check cannot apply to them. Each server declares its own at its composition root and
// passes it to MiddlewareSkipCsrf; core owns the matching and owns none of the routes, because a
// shared table means each binary exempts the other's endpoints, and the one that used to live here
// had the admin console exempting /auth/authorize, /auth/token, /userinfo and /connect/register,
// none of which it mounts, and the auth server exempting /auth/callback, which it does not (#385).
//
// What stands in for the origin check differs per endpoint, and stating that per endpoint matters:
// there is no single property the exempt set shares. In particular they do NOT all authenticate
// the caller, and the auth server's /auth/authorize does read the session cookie (#155). Each
// server's policy therefore carries a rationale comment per entry, and that is where they are.
//
// The three shapes are distinct on purpose, and the distinction is load-bearing rather than
// stylistic:
//
//   - ExactPaths is matched EXACTLY, so a future sibling route (say /auth/token-introspect beside
//     /auth/token, or /userinfo-export beside /userinfo) is NOT silently exempted: it keeps full
//     CSRF protection until somebody deliberately adds it.
//   - Prefixes inherit, and that inheritance is the point where it is used: a bearer-authenticated
//     REST subtree wants new endpoints under it to be exempt without a fresh decision each time.
//     A path is not a prefix, so listing one here where an exact entry was meant exempts every
//     sibling that shares its text.
//   - Conditional is what a prefix cannot express: the exemption depends on the request rather
//     than only on its path. An unconditional entry where a conditional one was meant is a hole,
//     which is exactly what the auth server's /auth/logout predicate exists to avoid.
//
// A collapse to one predicate per application was rejected for that reason (decision 5): the
// reasoning above would then have to be re-established in each module, and an application writing
// HasPrefix where it meant an exact match would get no help at all.
//
// The zero value exempts nothing, which is a usable policy and not a misconfiguration: a server
// with no cross-origin binding supplies it and every state-changing request is origin-checked.
type CsrfPolicy struct {
	// ExactPaths are exempt when the request path equals one of them.
	ExactPaths []string

	// Prefixes are exempt when the request path begins with one of them. Write the trailing
	// slash: "/api/" exempts /api/v1/users and not /api-internal.
	Prefixes []string

	// Conditional maps an exact path to the predicate that decides each request on that path.
	// Consulted only when neither table above already exempted the path, so a predicate is never
	// asked about a request that was exempt anyway.
	Conditional map[string]func(*http.Request) bool
}

// csrfSkipper is a policy compiled for matching: the exact paths as a set, so a lookup does not
// scan, and the other two as they were given.
type csrfSkipper struct {
	exact       map[string]bool
	prefixes    []string
	conditional map[string]func(*http.Request) bool
}

// newCsrfSkipper compiles a policy and refuses the two shapes that are silently wrong.
//
// It panics rather than returning an error because a policy is a literal at a composition root,
// evaluated once at startup: both refusals are programming errors that no request can produce and
// that no deployment can configure its way into, so failing to start is the whole of the correct
// response. Answering them per request would instead mean a server that boots with a hole in it.
func newCsrfSkipper(policy CsrfPolicy) csrfSkipper {
	exact := make(map[string]bool, len(policy.ExactPaths))
	for _, path := range policy.ExactPaths {
		exact[path] = true
	}

	for _, prefix := range policy.Prefixes {
		// An empty prefix is a prefix of every path, so it turns the whole server off. It is what
		// an unset constant or a dropped element of a slice literal looks like.
		if prefix == "" {
			panic("csrf policy: an empty prefix exempts every path on this server")
		}
	}

	for path := range policy.Conditional {
		// shouldSkip consults the exact set first, so a path in both is unconditionally exempt and
		// its predicate is never called. That is precisely the hole a conditional entry exists to
		// close: /auth/logout listed unconditionally would let any origin POST a logout with no
		// hint, which the handler reads as the confirmation of its consent page (#109).
		if exact[path] {
			panic("csrf policy: " + path + " is listed both exactly and conditionally, so the exact entry " +
				"wins and the predicate is never consulted, which exempts the path unconditionally; list it once")
		}
	}

	return csrfSkipper{exact: exact, prefixes: policy.Prefixes, conditional: policy.Conditional}
}

// shouldSkip reports whether CSRF protection should be bypassed for this request. CSRF defends the
// state-changing requests a browser makes on a signed-in person's behalf; the exempt paths are
// bindings a protocol requires to work cross-origin, or safe-method static assets, so enforcing the
// origin check on them would break legitimate callers rather than stop an attacker. What replaces
// it differs per endpoint, and the rationale for each is at the composition root that supplied it;
// do not assume a shared one (#155).
//
// The path is passed in rather than read off the request because the caller has already resolved
// chi's normalized RoutePath, which is what a trailing slash arrives as.
func (s csrfSkipper) shouldSkip(r *http.Request, path string) bool {
	if s.exact[path] {
		return true
	}
	for _, prefix := range s.prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	// Last, so an unconditional entry always wins and no predicate is consulted, and with it no
	// request body read, for a path that was exempt anyway.
	if exempt, ok := s.conditional[path]; ok {
		return exempt(r)
	}
	return false
}

// MiddlewareSkipCsrf marks the requests policy exempts, for MiddlewareCsrf below to honour. The
// policy is the caller's because the routes are: see CsrfPolicy.
func MiddlewareSkipCsrf(policy CsrfPolicy) func(next http.Handler) http.Handler {
	skipper := newCsrfSkipper(policy)

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

			if skipper.shouldSkip(r, path) {
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
//   - No AddInsecureBypassPattern. The application's CsrfPolicy and MiddlewareSkipCsrf already own
//     that decision, including its conditional entries, which a pattern cannot express.
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
			// Nothing sensitive is logged: no cookies, no request body. The method, the target,
			// Host, Origin and Sec-Fetch-Site are the client's to choose and reach this record
			// before anything has authenticated it, so each is escaped and bounded the way the
			// request logger bounds the same values: FieldForLog for the scalars and
			// RequestTargetForLog for the target, under the key that logger uses for it. Without
			// that one unauthenticated request with a 1 MB Origin wrote a 1 MB log line (#159,
			// #425).
			explanation, remedy := explainCsrfFailure(r)

			// The message is a literal and the sentence explainCsrfFailure built is an attribute:
			// a variable message cannot be grepped for, and a collector counting CSRF refusals
			// had to know all four wordings to find them (#320 decision 4).
			slog.WarnContext(r.Context(), "cross-origin request refused",
				"explanation", explanation,
				"remedy", remedy,
				"error", err,
				"method", logging.FieldForLog(r.Method),
				"target", RequestTargetForLog(r.URL),
				"request_host", logging.FieldForLog(r.Host),
				"origin_header", logging.FieldForLog(headerOrPlaceholder(r, "Origin")),
				"sec_fetch_site", logging.FieldForLog(headerOrPlaceholder(r, "Sec-Fetch-Site")),
			)

			// The reason stays in the log. It describes the deployment's origin handling,
			// which is of no use to whoever is looking at the page and, on a genuine
			// attack, tells the attacker which check refused them.
			//
			// This middleware is mounted on the root router, above the branch that carries
			// i18n.MiddlewareLocale, so there is no localizer on the context to reach for:
			// mounting it below the branch would gain one at the cost of leaving any route
			// registered outside that branch unprotected. ResolveRequestLocale is the same
			// resolution the locale middleware performs, done here for this one response.
			ctx := i18n.ResolveRequestLocale(r.Context(), r)
			http.Error(w, i18n.T(ctx, "error.csrf_refused"), http.StatusForbidden)
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
			"Compare the origin_header and request_host fields below. If they differ only by proxy rewriting, configure the proxy to preserve the original Host header. If they are genuinely different sites, this rejection is the control working."
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
