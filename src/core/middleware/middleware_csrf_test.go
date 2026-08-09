package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

func TestMiddlewareSkipCsrf(t *testing.T) {
	tests := []struct {
		name string
		// method defaults to GET, which is what every path-only row wants: the exemption those rows
		// describe does not depend on the method.
		method string
		path   string
		// body is sent as application/x-www-form-urlencoded when set, which is how a relying party
		// serializes logout parameters into a POST per OpenID Connect Core's Form Serialization.
		body string
		skip bool
	}{
		// Exempt: exact-match endpoints (bearer/client-authenticated, no cookie).
		{"Authorize exact", "", "/auth/authorize", "", true},
		{"Token exact", "", "/auth/token", "", true},
		{"Callback exact", "", "/auth/callback", "", true},
		{"Userinfo exact", "", "/userinfo", "", true},
		{"DCR register exact", "", "/connect/register", "", true},

		// Exempt: intentional subtree prefixes.
		{"API admin subtree", "", "/api/v1/admin/users", "", true},
		{"API account subtree", "", "/api/v1/account/profile", "", true},
		{"API public settings", "", "/api/public/settings", "", true},
		{"Static css", "", "/static/file.css", "", true},
		{"Static nested js", "", "/static/js/app.js", "", true},

		// Drift guards: sibling routes under a formerly-prefixed path must NOT
		// inherit the exemption now that single endpoints are matched exactly.
		{"Token introspect not skipped", "", "/auth/token-introspect", "", false},
		{"Tokeninfo not skipped", "", "/auth/tokeninfo", "", false},
		{"Tokens not skipped", "", "/auth/tokens", "", false},
		{"Userinfo export not skipped", "", "/userinfo-export", "", false},
		{"Userinfo typo not skipped", "", "/userinfoo", "", false},
		{"Connect register status not skipped", "", "/connect/register-status", "", false},
		{"Connect bare not skipped", "", "/connect/", "", false},
		{"Static without slash not skipped", "", "/static-secret", "", false},
		{"Authorize-extra not skipped", "", "/auth/authorize-extra", "", false},

		// Cookie-authenticated routes must keep CSRF protection.
		{"Auth pwd protected", "", "/auth/pwd", "", false},
		{"Auth otp protected", "", "/auth/otp", "", false},
		{"Auth consent protected", "", "/auth/consent", "", false},
		{"Auth logout protected", "", "/auth/logout", "", false},
		{"Account register protected", "", "/account/register", "", false},
		{"Account profile protected", "", "/account/profile", "", false},
		{"Admin console page protected", "", "/admin/clients", "", false},
		{"Forgot password protected", "", "/forgot-password", "", false},
		{"Reset password protected", "", "/reset-password", "", false},
		{"Root protected", "", "/", "", false},
		{"Other path", "", "/other", "", false},

		// The one conditional exemption: POST /auth/logout carrying an id_token_hint, which
		// RP-Initiated Logout 1.0 section 2 makes a MUST ("OpenID Providers MUST support the use of
		// the HTTP GET and POST methods defined in RFC 7231") and which the origin check otherwise
		// refuses from every foreign origin (#109 decision 9).
		//
		// Both arrival routes, because a relying party may put the parameter in the query or
		// serialize it into the body, and the handler reads both.
		{"Logout POST with a hint in the query", http.MethodPost, "/auth/logout?id_token_hint=abc", "", true},
		{"Logout POST with a hint in the body", http.MethodPost, "/auth/logout", "id_token_hint=abc", true},

		// PRESENCE, not a value, and this pair is the reason the shared extractor exists. The
		// handler classifies "id_token_hint=" as a hint that was supplied and cannot be confirmed,
		// so it asks the End-User. Were this predicate to read the same parameter as no hint at all,
		// the exempted POST would take the hintless branch instead, which is the confirmation of the
		// consent page and tears the whole session down without asking anybody (#109 decision 13).
		{"Logout POST with an empty hint in the query", http.MethodPost, "/auth/logout?id_token_hint=", "", true},
		{"Logout POST with an empty hint in the body", http.MethodPost, "/auth/logout", "id_token_hint=", true},

		// And the hintless POST keeps full protection, which is the whole reason the exemption is
		// conditional: an unconditional entry would let any site force a logout from any origin.
		{"Logout POST with no hint", http.MethodPost, "/auth/logout", "", false},
		{"Logout POST with only other parameters", http.MethodPost, "/auth/logout", "state=abc&client_id=x", false},
		{"Logout POST with a lookalike parameter", http.MethodPost, "/auth/logout?id_token_hintx=abc", "", false},
		{"Logout POST with a lookalike parameter in the body", http.MethodPost, "/auth/logout", "id_token_hint_x=abc", false},

		// Methods other than POST are not exempted even with a hint. GET is a safe method the
		// origin check never applies to; PUT and DELETE are checked, and neither is routed here, so exempting them
		// would widen the hole for a route that would have to be added deliberately.
		{"Logout GET with a hint", http.MethodGet, "/auth/logout?id_token_hint=abc", "", false},
		{"Logout PUT with a hint", http.MethodPut, "/auth/logout?id_token_hint=abc", "", false},
		{"Logout DELETE with a hint", http.MethodDelete, "/auth/logout?id_token_hint=abc", "", false},

		// The predicate is bound to its exact path, like the exact-match table above and for the same
		// drift reason: an id_token_hint on any other endpoint exempts nothing.
		{"Auth pwd POST with a hint", http.MethodPost, "/auth/pwd?id_token_hint=abc", "", false},
		{"Logout sibling route with a hint", http.MethodPost, "/auth/logout-extra?id_token_hint=abc", "", false},
		{"Logout prefix route with a hint", http.MethodPost, "/auth/logout/confirm?id_token_hint=abc", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := tt.method
			if method == "" {
				method = http.MethodGet
			}
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest(method, tt.path, body)
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			rr := httptest.NewRecorder()

			handler := MiddlewareSkipCsrf()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				skipValue := csrfSkipped(r)
				if tt.skip {
					if !skipValue {
						t.Errorf("MiddlewareSkipCsrf() for path %s: expected CSRF check to be skipped, but it wasn't", tt.path)
					}
				} else {
					if skipValue {
						t.Errorf("MiddlewareSkipCsrf() for path %s: expected CSRF check not to be skipped, but it was", tt.path)
					}
				}
			}))

			handler.ServeHTTP(rr, req)
		})
	}
}

// TestMiddlewareSkipCsrf_LogoutBodySurvivesTheHintCheck is the case decision 9 names as the thing
// that has to be pinned: looking for the hint in a POST body means parsing the form in middleware,
// and a form parse consumes the request body.
//
// It survives because Go caches the parse in r.PostForm and r.Form, and the handler's r.FormValue
// reads the cache rather than the socket. If it ever stopped surviving, the logout handler would see
// a request with no ui_locales, no state and no post_logout_redirect_uri, which is a page in the
// wrong language and a redirect that silently does not happen, so this asserts the siblings and not
// only the hint itself.
func TestMiddlewareSkipCsrf_LogoutBodySurvivesTheHintCheck(t *testing.T) {
	body := url.Values{
		"id_token_hint":            {"a.b.c"},
		"post_logout_redirect_uri": {"https://rp.example/bye"},
		"state":                    {"opaque+value/=="},
		"ui_locales":               {"pt-BR"},
	}

	var seen url.Values
	var skipped bool
	handler := MiddlewareSkipCsrf()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		skipped = csrfSkipped(r)
		seen = url.Values{}
		for _, key := range []string{"id_token_hint", "post_logout_redirect_uri", "state", "ui_locales"} {
			seen.Set(key, r.FormValue(key))
		}
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !skipped {
		t.Fatal("a POST carrying an id_token_hint in its body must be exempted")
	}
	for key, want := range body {
		if got := seen.Get(key); got != want[0] {
			t.Errorf("handler read %s = %q after the middleware parsed the body, want %q", key, got, want[0])
		}
	}
}

// TestMiddlewareSkipCsrf_OtherPathsKeepAnUnreadBody is the boundary on the test above: the body is
// read for the one path that has a predicate and for nothing else.
//
// It matters because the exempt prefixes include the whole /api/ subtree, whose handlers decode JSON
// straight off r.Body. A predicate table that grew a prefix entry, or a parse hoisted out of the
// predicate and up into the middleware, would leave those handlers reading an empty body and the
// failure would look nothing like a CSRF change.
func TestMiddlewareSkipCsrf_OtherPathsKeepAnUnreadBody(t *testing.T) {
	const payload = `{"name":"unread"}`

	for _, path := range []string{"/api/v1/admin/users", "/auth/token", "/auth/pwd", "/auth/logout-extra"} {
		t.Run(path, func(t *testing.T) {
			var got string
			handler := MiddlewareSkipCsrf()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("reading the body: %v", err)
				}
				got = string(raw)
			}))

			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if got != payload {
				t.Errorf("handler read %q from the body, want %q: the middleware consumed it", got, payload)
			}
		})
	}
}

// TestMiddlewareSkipCsrf_CombinedChain mounts the production middleware chain
// (StripSlashes -> MiddlewareSkipCsrf -> MiddlewareCsrf) onto a chi router and issues real
// cross-origin POSTs. This proves the exemptions reach the enforcing middleware end-to-end,
// beyond the context-flag check in TestMiddlewareSkipCsrf.
//
// Its table is unchanged by the move off gorilla/csrf (#155) and that is deliberate rather than
// lucky: every row sends a foreign Origin with no Sec-Fetch-Site against httptest's default
// example.com host, so each Forbidden row now fails the Origin-versus-Host comparison where it
// used to fail the trusted list, and each OK row still passes on its exemption.
func TestMiddlewareSkipCsrf_CombinedChain(t *testing.T) {
	const foreignOrigin = "https://www.certification.openid.net"

	newRouter := func() *chi.Mux {
		r := chi.NewRouter()
		r.Use(chimiddleware.StripSlashes)
		r.Use(MiddlewareSkipCsrf())
		r.Use(MiddlewareCsrf())

		inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		r.Post("/auth/authorize", inner)
		r.Post("/auth/authorize-extra", inner)
		r.Post("/auth/pwd", inner)
		r.Post("/auth/token", inner)
		r.Post("/auth/token-introspect", inner)
		r.Post("/userinfo", inner)
		r.Post("/userinfo-export", inner)
		r.Post("/api/v1/admin/users", inner)
		r.Post("/auth/logout", inner)
		r.Post("/auth/logout-extra", inner)
		return r
	}

	tests := []struct {
		name       string
		path       string
		body       string
		wantStatus int
	}{
		// Exempt endpoints let the foreign-origin POST through.
		{"POST /auth/authorize foreign origin reaches handler", "/auth/authorize", "", http.StatusOK},
		{"POST /auth/authorize/ trailing slash reaches handler", "/auth/authorize/", "", http.StatusOK},
		{"POST /auth/token reaches handler", "/auth/token", "", http.StatusOK},
		{"POST /userinfo reaches handler", "/userinfo", "", http.StatusOK},
		{"POST /api/v1/admin/users reaches handler", "/api/v1/admin/users", "", http.StatusOK},

		// Non-exempt routes are still blocked (403 origin invalid).
		{"POST /auth/pwd foreign origin still blocked", "/auth/pwd", "", http.StatusForbidden},
		{"POST /auth/authorize-extra not skipped", "/auth/authorize-extra", "", http.StatusForbidden},
		{"POST /auth/token-introspect not skipped", "/auth/token-introspect", "", http.StatusForbidden},
		{"POST /userinfo-export not skipped", "/userinfo-export", "", http.StatusForbidden},

		// The logout binding, which is what the exemption is for: a relying party POSTs a hint from
		// its own origin and must reach the handler. Both arrival routes and the trailing-slash form,
		// since the path the predicate is matched against comes from chi's StripSlashes.
		{"POST /auth/logout with a hint in the query reaches handler", "/auth/logout?id_token_hint=abc", "", http.StatusOK},
		{"POST /auth/logout with a hint in the body reaches handler", "/auth/logout", "id_token_hint=abc", http.StatusOK},
		{"POST /auth/logout/ trailing slash with a hint reaches handler", "/auth/logout/?id_token_hint=abc", "", http.StatusOK},
		{"POST /auth/logout with an empty hint reaches handler", "/auth/logout?id_token_hint=", "", http.StatusOK},

		// And the shape the exemption must never cover. This is the case that makes the conditional
		// table worth its complexity: an unconditional /auth/logout entry would answer this 200 and
		// any site could force a logout (#109 decision 9).
		{"POST /auth/logout with no hint is still blocked", "/auth/logout", "", http.StatusForbidden},
		{"POST /auth/logout with only other parameters is still blocked", "/auth/logout", "state=abc", http.StatusForbidden},
		{"POST /auth/logout-extra with a hint is still blocked", "/auth/logout-extra?id_token_hint=abc", "", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := newRouter()
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest(http.MethodPost, tt.path, body)
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			req.Header.Set("Origin", foreignOrigin)
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("path %s: got status %d, want %d", tt.path, rr.Code, tt.wantStatus)
			}
		})
	}
}

// TestMiddlewareCsrf_OriginDecisions is the matrix CVE-2025-47909 lives in, at the seam where it is
// observable: MiddlewareCsrf composed with a recording handler, no chi, no exemption tables.
//
// Every row varies exactly one thing from a passing neighbour, so no row can pass for the wrong
// reason: change only the method, or only Sec-Fetch-Site, or only the Origin scheme, and the expected
// outcome is the only thing that moves with it.
//
// The two rows named CVE are the regression guard and the reason this table exists. Both PASS under
// the code this replaced, because it listed the auth server's own host and the admin console's as
// trusted origins and gorilla/csrf compared only the host, never the scheme, so a network attacker
// serving a page over plaintext http on either host was accepted. Their value is invisible once the
// design is right, which is exactly when a later reader is tempted to delete them: keep them.
func TestMiddlewareCsrf_OriginDecisions(t *testing.T) {
	// The host this deployment is reached on. The old code derived a trusted list from the
	// configured base URLs; the new one compares against Host and trusts nothing else.
	const ourHost = "auth.example.com"

	// The admin console's host. Formerly trusted, which is half of what the CVE exploited.
	const adminHost = "admin.example.com"

	tests := []struct {
		name string
		// method defaults to POST, the state-changing case the check exists for.
		method string
		// origin is sent only when non-empty; absentOrigin forces it absent even so.
		origin string
		// secFetchSite is sent only when non-empty.
		secFetchSite string
		// skipped marks the request the way MiddlewareSkipCsrf does for an exempt path.
		skipped bool
		allowed bool
	}{
		// The three fetch-metadata verdicts a browser can report about a state-changing POST.
		{name: "same-origin POST is allowed", secFetchSite: "same-origin", origin: "https://" + ourHost, allowed: true},
		{name: "cross-site POST is refused", secFetchSite: "cross-site", origin: "https://evil.example.com", allowed: false},
		{name: "same-site POST is refused", secFetchSite: "same-site", origin: "https://sibling." + ourHost, allowed: false},

		// The fourth value W3C Fetch Metadata section 2.3 enumerates, and the one a regression is
		// most likely to drop: Go groups "none" with "same-origin" in a single accepting branch, so
		// mapping it onto the rejecting branch would leave every other row in this table passing.
		// It is what a browser reports for a user-initiated top-level request, so allowing it is
		// correct. The Origin is foreign to prove the verdict decides this and the Origin does not.
		{name: "none POST is allowed even from a foreign origin", secFetchSite: "none", origin: "https://evil.example.com", allowed: true},

		// THE CVE, as the issue states it: a network attacker serves a page over plaintext http on
		// the admin console's host, which the old code trusted by host alone.
		{name: "CVE: cross-site POST from http on the formerly trusted admin host is refused", secFetchSite: "cross-site", origin: "http://" + adminHost, allowed: false},

		// THE CVE on our own host, which the issue does not state and the agreement's section 1
		// found: the auth server listed its own host too, so a MitM at http://auth.example.com was
		// accepted against https://auth.example.com just as readily.
		{name: "CVE: cross-site POST from http on our own host is refused", secFetchSite: "cross-site", origin: "http://" + ourHost, allowed: false},

		// The documented fail-open, reached only when no Sec-Fetch-Site header is present. This is
		// also the shape the integration suite rides, which is why it must stay allowed.
		{name: "no Sec-Fetch-Site with a matching Origin host is allowed", origin: "https://" + ourHost, allowed: true},
		{name: "no Sec-Fetch-Site with a differing Origin host is refused", origin: "https://evil.example.com", allowed: false},

		// An opaque origin, which Referrer-Policy: no-referrer produces. Fetch metadata settles it
		// when present; without it there is no host to compare and the request is refused.
		{name: "Origin null with Sec-Fetch-Site is allowed", secFetchSite: "same-origin", origin: "null", allowed: true},
		{name: "Origin null without Sec-Fetch-Site is refused", origin: "null", allowed: false},

		// Neither header: not a browser request, so it carries no ambient credentials and CSRF does
		// not apply to it. Allowing this is the deliberate boundary of an origin-only defense.
		{name: "neither header is allowed", allowed: true},

		// Safe methods are never state-changing, so they are allowed from anywhere. Every handler
		// this middleware fronts must keep honouring that.
		{name: "GET from a foreign origin is allowed", method: http.MethodGet, secFetchSite: "cross-site", origin: "https://evil.example.com", allowed: true},
		{name: "HEAD from a foreign origin is allowed", method: http.MethodHead, secFetchSite: "cross-site", origin: "https://evil.example.com", allowed: true},
		{name: "OPTIONS from a foreign origin is allowed", method: http.MethodOptions, secFetchSite: "cross-site", origin: "https://evil.example.com", allowed: true},

		// And the unsafe methods that are not POST, which are checked identically.
		{name: "PUT cross-site is refused", method: http.MethodPut, secFetchSite: "cross-site", origin: "https://evil.example.com", allowed: false},
		{name: "DELETE cross-site is refused", method: http.MethodDelete, secFetchSite: "cross-site", origin: "https://evil.example.com", allowed: false},

		// The context-key contract between the two middlewares, which is the only assertion here
		// that pins it. MiddlewareSkipCsrf marks an exempt path and MiddlewareCsrf must honour the
		// mark even for a request it would otherwise refuse outright.
		{name: "a marked-skipped cross-site POST is allowed", secFetchSite: "cross-site", origin: "https://evil.example.com", skipped: true, allowed: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := tt.method
			if method == "" {
				method = http.MethodPost
			}

			reached := false
			handler := MiddlewareCsrf()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(method, "/auth/pwd", nil)
			req.Host = ourHost
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tt.secFetchSite)
			}
			if tt.skipped {
				req = markCsrfSkipped(req)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if tt.allowed {
				if !reached {
					t.Errorf("request was refused with %d, want it to reach the handler", rr.Code)
				}
				return
			}

			if reached {
				t.Error("request reached the handler, want it refused")
			}
			if rr.Code != http.StatusForbidden {
				t.Errorf("got status %d, want %d", rr.Code, http.StatusForbidden)
			}
			// The prefix is ours; the reason after it is the standard library's wording and is
			// deliberately not asserted, since pinning it would pin the suite to a Go release.
			if body := rr.Body.String(); !strings.HasPrefix(body, "Forbidden - ") {
				t.Errorf("body = %q, want it to start with %q", body, "Forbidden - ")
			}
		})
	}
}

// TestExplainCsrfFailure covers the diagnostic the 403 carries into the log, which is the only place
// an operator can learn which of four unrelated causes produced the same status code.
//
// It asserts a distinguishing substring rather than a whole sentence, so rewording the explanation
// does not fail the test while confusing two causes still does.
func TestExplainCsrfFailure(t *testing.T) {
	const ourHost = "auth.example.com"

	tests := []struct {
		name            string
		origin          string
		secFetchSite    string
		wantExplanation string
		wantRemedy      string
	}{
		{
			name:            "cross-site is the control working",
			secFetchSite:    "cross-site",
			origin:          "https://evil.example.com",
			wantExplanation: "reported as cross-site",
			wantRemedy:      "no action is needed",
		},
		{
			name:            "same-site is a deployment misconfiguration",
			secFetchSite:    "same-site",
			origin:          "https://sibling." + ourHost,
			wantExplanation: "sibling host on the same registrable domain",
			wantRemedy:      "Serve the form and its target from one origin",
		},
		{
			name:            "an opaque origin points at Referrer-Policy",
			origin:          "null",
			wantExplanation: "opaque origin (Origin: null)",
			wantRemedy:      "Referrer-Policy",
		},
		{
			name:            "a host mismatch points at an old browser or a rewriting proxy",
			origin:          "https://evil.example.com",
			wantExplanation: "did not match the Host header",
			wantRemedy:      "preserve the original Host header",
		},
		{
			// W3C Fetch Metadata section 2.3 enumerates exactly four values, so a fifth is forged
			// or mangled. Diagnosing it as "no Sec-Fetch-Site" would name a cause that is not the
			// one Check acted on, so it must reach the generic fallback instead.
			name:            "an unrecognized Sec-Fetch-Site value falls back rather than guessing",
			secFetchSite:    "bogus",
			origin:          "https://" + ourHost,
			wantExplanation: "CSRF rejected a state-changing request.",
			wantRemedy:      "See the reason field.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/pwd", nil)
			req.Host = ourHost
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tt.secFetchSite)
			}

			// Each row must be a request the middleware actually refuses, or it would be asserting
			// on a diagnostic for a case that never reaches the diagnostic.
			if err := http.NewCrossOriginProtection().Check(req); err == nil {
				t.Fatal("this row is allowed by the origin check, so explainCsrfFailure would never see it")
			}

			explanation, remedy := explainCsrfFailure(req)
			if !strings.Contains(explanation, tt.wantExplanation) {
				t.Errorf("explanation = %q, want it to contain %q", explanation, tt.wantExplanation)
			}
			if !strings.Contains(remedy, tt.wantRemedy) {
				t.Errorf("remedy = %q, want it to contain %q", remedy, tt.wantRemedy)
			}
		})
	}
}
