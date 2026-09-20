package middleware

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/i18n"
)

// The fixture policy every matching test below drives, and it is deliberately not either
// application's.
//
// core owns the matching and owns no route, so a test here naming /auth/token would be asserting
// about a table this package no longer declares and could not fail when that table changed. The
// concrete route tables moved to the binaries that supply them: the auth server's to
// src/authserver/internal/server/server_csrf_test.go with its predicate's own table at
// src/authserver/internal/middleware/middleware_csrf_test.go, and the admin console's to
// src/adminconsole/internal/server/server_csrf_test.go. What is left here is the mechanism, which
// is what this package is now responsible for (#385).
//
// The names are shaped so that every negative case differs from a positive one in exactly the thing
// under test: /exact against /exact-extra and /exact/child, /prefix/ against /prefix-extra.
func fixtureCsrfPolicy(conditional func(*http.Request) bool) CsrfPolicy {
	return CsrfPolicy{
		ExactPaths: []string{"/exact", "/other-exact"},
		Prefixes:   []string{"/prefix/"},
		Conditional: map[string]func(*http.Request) bool{
			"/conditional": conditional,
		},
	}
}

// alwaysExempt and neverExempt are the two constant predicates the path-matching table uses, so a
// conditional row fails on its path rather than on whatever a realistic predicate would have read.
func alwaysExempt(*http.Request) bool { return true }

func neverExempt(*http.Request) bool { return false }

func TestMiddlewareSkipCsrf(t *testing.T) {
	tests := []struct {
		name string
		path string
		// exemptWhenCalled is what the conditional predicate answers for this row. It only
		// decides the two /conditional rows; every other row is settled before the predicate is
		// reached, which the ordering test below asserts directly.
		exemptWhenCalled bool
		skip             bool
	}{
		// Exact: the path itself, and nothing that merely shares its text. These are the drift
		// guards, and they are why ExactPaths is not a prefix list: a sibling route added beside an
		// exempt one must keep full CSRF protection until somebody lists it deliberately.
		{"the exact path is exempt", "/exact", false, true},
		{"the second exact path is exempt", "/other-exact", false, true},
		{"a suffixed sibling is not", "/exact-extra", false, false},
		{"a child route is not", "/exact/child", false, false},
		{"a parent route is not", "/", false, false},
		{"a prefixed sibling is not", "/not/exact", false, false},

		// Prefix: inheritance at any depth is the point, and the trailing slash is what bounds it.
		{"a path directly under the prefix is exempt", "/prefix/thing", false, true},
		{"a path nested under the prefix is exempt", "/prefix/a/b/c", false, true},
		{"the prefix itself is exempt", "/prefix/", false, true},
		{"the prefix without its trailing slash is not", "/prefix", false, false},
		{"a path sharing the prefix's text is not", "/prefix-extra/thing", false, false},

		// Conditional: the predicate decides, and it is bound to its exact path the same way
		// ExactPaths is, so the same signal on a neighbouring route exempts nothing.
		{"the conditional path is exempt when the predicate says so", "/conditional", true, true},
		{"the conditional path is not exempt when the predicate refuses", "/conditional", false, false},
		{"a suffixed sibling of the conditional path is not", "/conditional-extra", true, false},
		{"a child of the conditional path is not", "/conditional/child", true, false},

		// And a path in no table at all.
		{"an unlisted path is not exempt", "/unlisted", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			predicate := neverExempt
			if tt.exemptWhenCalled {
				predicate = alwaysExempt
			}

			var got bool
			handler := MiddlewareSkipCsrf(fixtureCsrfPolicy(predicate))(
				http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					got = csrfSkipped(r)
				}))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, tt.path, nil))

			if got != tt.skip {
				t.Errorf("path %s: exempted = %v, want %v", tt.path, got, tt.skip)
			}
		})
	}
}

// TestMiddlewareSkipCsrf_TheZeroPolicyExemptsNothing is the case that fails if the matching ever
// grows a default. A server with no cross-origin binding supplies CsrfPolicy{} and must get the
// origin check on everything; the paths below are the ones the table this replaced used to exempt
// for every binary, which is the shape of the bug that would reintroduce them.
func TestMiddlewareSkipCsrf_TheZeroPolicyExemptsNothing(t *testing.T) {
	for _, path := range []string{"/", "/auth/authorize", "/auth/token", "/auth/callback",
		"/userinfo", "/connect/register", "/api/v1/admin/users", "/static/app.css", "/auth/logout"} {

		t.Run(path, func(t *testing.T) {
			var got bool
			handler := MiddlewareSkipCsrf(CsrfPolicy{})(
				http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					got = csrfSkipped(r)
				}))
			handler.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest(http.MethodPost, path, nil))

			if got {
				t.Errorf("path %s was exempted by an empty policy", path)
			}
		})
	}
}

// TestMiddlewareSkipCsrf_OnlyTheConditionalPathConsultsThePredicate pins the ordering, which is
// load-bearing rather than incidental: a predicate may read the request body, and the auth server's
// does. A path an exact entry or a prefix already exempted must not reach one, or the /api/ subtree
// would have its JSON body parsed by middleware before its handler decoded it, and the failure
// would look nothing like a CSRF change.
//
// It counts calls rather than watching a body, so the assertion names the mechanism instead of a
// side effect of it. The body-survival property belongs to the predicate that does the reading and
// is asserted where that predicate lives, in the auth server.
func TestMiddlewareSkipCsrf_OnlyTheConditionalPathConsultsThePredicate(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantCalls int
	}{
		{"an exact path settles before the predicate", "/exact", 0},
		{"a prefixed path settles before the predicate", "/prefix/thing", 0},
		{"an unlisted path never reaches the predicate", "/unlisted", 0},
		{"a sibling of the conditional path never reaches it", "/conditional-extra", 0},
		{"the conditional path is the one that consults it", "/conditional", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			predicate := func(*http.Request) bool {
				calls++
				return true
			}

			handler := MiddlewareSkipCsrf(fixtureCsrfPolicy(predicate))(
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, tt.path, nil))

			if calls != tt.wantCalls {
				t.Errorf("path %s: the predicate was consulted %d times, want %d", tt.path, calls, tt.wantCalls)
			}
		})
	}
}

// TestMiddlewareSkipCsrf_RefusesASilentlyWrongPolicy covers the two shapes a policy value can
// express that the package-level tables it replaces could not, and that no request could reveal.
//
// Both are refused at construction, which is a composition root evaluated once at startup, so the
// failure is a server that does not boot rather than a server that boots with a hole in it.
func TestMiddlewareSkipCsrf_RefusesASilentlyWrongPolicy(t *testing.T) {
	// A path in both tables is unconditionally exempt, because shouldSkip consults the exact set
	// first and the predicate is never called. That is the whole hole the conditional shape exists
	// to close: /auth/logout exempt unconditionally lets any origin POST a hintless logout, which
	// the handler reads as the confirmation of its consent page (#109, decision 5).
	t.Run("a path listed both exactly and conditionally", func(t *testing.T) {
		assertPanics(t, func() {
			MiddlewareSkipCsrf(CsrfPolicy{
				ExactPaths:  []string{"/auth/logout"},
				Conditional: map[string]func(*http.Request) bool{"/auth/logout": neverExempt},
			})
		})
	})

	// An empty prefix is a prefix of every path, so it turns the origin check off for the whole
	// server. It is what an unset constant or a dropped slice element looks like.
	t.Run("an empty prefix", func(t *testing.T) {
		assertPanics(t, func() {
			MiddlewareSkipCsrf(CsrfPolicy{Prefixes: []string{"/static/", ""}})
		})
	})

	// The other half, without which the two above are satisfied by a constructor that refuses
	// everything: a policy naming the same path once, in each table, is accepted.
	t.Run("a policy naming each path once is accepted", func(t *testing.T) {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("a well-formed policy panicked: %v", recovered)
			}
		}()
		MiddlewareSkipCsrf(CsrfPolicy{
			ExactPaths:  []string{"/auth/authorize"},
			Prefixes:    []string{"/api/"},
			Conditional: map[string]func(*http.Request) bool{"/auth/logout": neverExempt},
		})
	})
}

func assertPanics(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("the policy was accepted, but it exempts more than it names")
		}
	}()
	fn()
}

// TestMiddlewareSkipCsrf_CombinedChain mounts the production middleware chain
// (StripSlashes -> MiddlewareSkipCsrf -> MiddlewareCsrf) onto a chi router and issues real
// cross-origin POSTs. This proves the exemptions reach the enforcing middleware end-to-end, beyond
// the context-flag check in TestMiddlewareSkipCsrf, and it is the only place the trailing-slash
// form is exercised: chi's StripSlashes writes the normalized path to RouteContext.RoutePath rather
// than to r.URL.Path, and MiddlewareSkipCsrf has to read it from there.
//
// Over the fixture policy, like everything else here. Each binary's own chain test makes the same
// claims about its own routes, which is where "this server exempts /auth/token" now belongs.
func TestMiddlewareSkipCsrf_CombinedChain(t *testing.T) {
	const foreignOrigin = "https://www.certification.openid.net"

	newRouter := func(predicate func(*http.Request) bool) *chi.Mux {
		r := chi.NewRouter()
		r.Use(chimiddleware.StripSlashes)
		r.Use(MiddlewareSkipCsrf(fixtureCsrfPolicy(predicate)))
		r.Use(MiddlewareCsrf())

		inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		r.Post("/exact", inner)
		r.Post("/exact-extra", inner)
		r.Post("/prefix/thing", inner)
		r.Post("/prefix-extra/thing", inner)
		r.Post("/conditional", inner)
		r.Post("/conditional-extra", inner)
		r.Post("/unlisted", inner)
		return r
	}

	tests := []struct {
		name             string
		path             string
		exemptWhenCalled bool
		wantStatus       int
	}{
		{"an exact path reaches the handler", "/exact", false, http.StatusOK},
		{"its trailing-slash form reaches the handler", "/exact/", false, http.StatusOK},
		{"a prefixed path reaches the handler", "/prefix/thing", false, http.StatusOK},

		{"a suffixed sibling is refused", "/exact-extra", false, http.StatusForbidden},
		{"a path sharing the prefix's text is refused", "/prefix-extra/thing", false, http.StatusForbidden},
		{"an unlisted path is refused", "/unlisted", false, http.StatusForbidden},

		{"the conditional path reaches the handler when the predicate exempts it", "/conditional", true, http.StatusOK},
		{"its trailing-slash form does too", "/conditional/", true, http.StatusOK},
		{"and is refused when the predicate does not", "/conditional", false, http.StatusForbidden},
		{"a sibling of it is refused even so", "/conditional-extra", true, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			predicate := neverExempt
			if tt.exemptWhenCalled {
				predicate = alwaysExempt
			}

			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(""))
			req.Header.Set("Origin", foreignOrigin)
			rr := httptest.NewRecorder()

			newRouter(predicate).ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("path %s: got status %d, want %d", tt.path, rr.Code, tt.wantStatus)
			}
		})
	}
}

// TestMiddlewareSkipCsrf_LeavesTheBodyForTheHandler is the boundary the ordering test states in
// terms of calls, asserted in the terms that actually bite: the exempt prefixes on a real server
// include a whole REST subtree whose handlers decode JSON straight off r.Body. Nothing in this
// middleware may consume it.
//
// The conditional path is included with a predicate that does parse the form, which is what the
// auth server's does, because Go caching the parse in r.PostForm is the only reason that is safe.
func TestMiddlewareSkipCsrf_LeavesTheBodyForTheHandler(t *testing.T) {
	const payload = "id_token_hint=a.b.c&state=opaque"

	for _, path := range []string{"/exact", "/prefix/thing", "/unlisted", "/conditional"} {
		t.Run(path, func(t *testing.T) {
			parsingPredicate := func(r *http.Request) bool {
				return r.FormValue("id_token_hint") != ""
			}

			var got string
			handler := MiddlewareSkipCsrf(fixtureCsrfPolicy(parsingPredicate))(
				http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					// r.FormValue, because that is what a handler uses and it reads the cache the
					// predicate populated. io.ReadAll would answer "" for the parsed case and say
					// nothing about whether the handler can still see its parameters.
					got = r.FormValue("id_token_hint") + "|" + r.FormValue("state")
					if raw, err := io.ReadAll(r.Body); err == nil && len(raw) > 0 && got == "|" {
						t.Errorf("the body arrived unparsed and unread as %q", raw)
					}
				}))

			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if got != "a.b.c|opaque" {
				t.Errorf("the handler read %q, want %q: the middleware consumed the body", got, "a.b.c|opaque")
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
			// The body is this middleware's own message, which is what attributes the 403 to
			// the origin check rather than to anything else that could answer 403. It is read
			// from the catalog rather than written out here, so rewording the message in one
			// place does not fail the suite; T on a bare context resolves the English entry.
			//
			// The refusal's reason is asserted absent. It used to be interpolated into the
			// body, where it described the deployment's own origin handling to whoever was
			// refused, an attacker included. TestExplainCsrfFailure covers it in the log,
			// which is where it belongs.
			wantBody := i18n.T(context.Background(), "error.csrf_refused")
			if body := strings.TrimSpace(rr.Body.String()); body != wantBody {
				t.Errorf("body = %q, want %q", body, wantBody)
			}
			if body := rr.Body.String(); strings.Contains(body, "Origin") || strings.Contains(body, "Sec-Fetch-Site") {
				t.Errorf("body = %q, want the refusal reason kept out of the response", body)
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
