package httpmw

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	tests := []struct {
		name   string
		secure bool
		want   map[string]string
	}{
		{
			name:   "insecure omits HSTS",
			secure: false,
			want: map[string]string{
				"X-Frame-Options":           "DENY",
				"Content-Security-Policy":   "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
				"X-Content-Type-Options":    "nosniff",
				"Referrer-Policy":           "same-origin",
				"Strict-Transport-Security": "",
			},
		},
		{
			name:   "secure includes HSTS",
			secure: true,
			want: map[string]string{
				"X-Frame-Options":           "DENY",
				"Content-Security-Policy":   "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
				"X-Content-Type-Options":    "nosniff",
				"Referrer-Policy":           "same-origin",
				"Strict-Transport-Security": strictTransportSecurityValue,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := SecurityHeaders(tt.secure)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if !called {
				t.Fatal("expected next handler to be called")
			}

			for header, want := range tt.want {
				if got := rr.Header().Get(header); got != want {
					t.Errorf("header %q = %q, want %q", header, got, want)
				}
			}
		})
	}
}

// TestSecurityHeaders_ReferrerPolicyIsNotNoReferrer guards a regression that
// broke every login: Referrer-Policy: no-referrer makes browsers send "Origin: null" on
// form POSTs, and the CSRF origin check rejects an opaque origin because it has no host to
// compare against Host. The result was a 403 on the password form, the OTP form, the
// consent screen and every admin console form.
//
// The check is now net/http.CrossOriginProtection (#155), which reads Sec-Fetch-Site first
// and allows a same-origin POST regardless of the Origin header, so the breakage is confined
// to browsers predating fetch metadata (2023). Those still fall through to the Origin
// comparison and "null" still matches nothing there, so the ban stands; it simply costs
// fewer users than it used to.
//
// no-referrer looks like the strictest and therefore safest choice, which is exactly why
// this test exists: the table above would keep passing if someone "tightened" the value
// back, since it only asserts equality with whatever is written there. This test says why
// the value is what it is.
//
// Verified in a browser across four policies: same-origin,
// strict-origin-when-cross-origin and omitting the header all send a usable Origin; only
// no-referrer does not. same-origin is chosen because it still keeps authorization codes
// and state values out of Referer headers sent to other origins, which was the point of
// setting the header in the first place.
func TestSecurityHeaders_ReferrerPolicyIsNotNoReferrer(t *testing.T) {
	for _, secure := range []bool{false, true} {
		handler := SecurityHeaders(secure)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/auth/pwd", nil))

		got := rr.Header().Get("Referrer-Policy")
		if got == "no-referrer" {
			t.Fatalf("Referrer-Policy is no-referrer (secure=%v); that makes browsers send "+
				"Origin: null on form POSTs, which fails the CSRF origin check on any "+
				"browser that sends no Sec-Fetch-Site header", secure)
		}
		if got == "" {
			t.Errorf("Referrer-Policy is unset (secure=%v); it should be same-origin", secure)
		}
	}
}

// TestSecurityHeaders_ScriptPolicyRunsOnlyTheServersOwnScriptFiles says why the
// Content-Security-Policy is what it is, so that relaxing it fails with a reason rather than
// a string mismatch in the table above (#518).
//
// script-src is exactly 'self': a browser runs the script files this origin serves and
// nothing else, so markup that reaches a page through a missed sink or an operator's
// template cannot run an inline <script>, an on… attribute, a javascript: URL or eval (CSP
// Level 3 §6.1.10). Every built-in page already keeps its scripts in static files (#617),
// which core/guard.AssertWellFormedTemplates holds, so nothing needs more:
//
//   - 'unsafe-inline' and 'unsafe-eval' switch the protection off for what it exists to stop.
//   - A nonce or a hash marks an inline script as allowed, and there is none to mark; a
//     nonce would also need per-request state threaded through every layout and every
//     operator's template, for nothing 'self' refuses that a page needs.
//   - 'strict-dynamic' trusts whatever an allowed script loads, and makes a browser ignore
//     'self' altogether.
//   - A scheme (https:, data:, blob:), a host or a wildcard allows scripts from elsewhere;
//     every script both servers load is a same-origin /static/ file, vendored ones included.
//
// object-src is 'none' because, with no default-src sent, a policy without it leaves
// <object> and <embed> unrestricted (§6.1.9). base-uri is 'none' because an injected <base
// href> would move every relative form action, the password form's /auth/pwd among them, to
// another origin, which script-src does not stop (§6.3.1); no page uses a <base>, so one an
// operator's template adds is refused visibly rather than allowed for the same origin.
// frame-ancestors 'none' is the clickjacking protection the header carried before.
func TestSecurityHeaders_ScriptPolicyRunsOnlyTheServersOwnScriptFiles(t *testing.T) {
	for _, secure := range []bool{false, true} {
		handler := SecurityHeaders(secure)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/pwd", nil))

		if got := rr.Header().Values("Content-Security-Policy"); len(got) != 1 {
			t.Fatalf("Content-Security-Policy sent %d times (secure=%v), want once: a browser "+
				"enforces every policy it receives, so a second one can only tighten the first, "+
				"and the value under test here would no longer be the whole policy", len(got), secure)
		}
		if got := rr.Header().Get("Content-Security-Policy-Report-Only"); got != "" {
			t.Errorf("Content-Security-Policy-Report-Only is %q (secure=%v); a report-only policy "+
				"enforces nothing, and the policy is enforced from the release that ships it", got, secure)
		}

		directives := map[string][]string{}
		for _, directive := range strings.Split(rr.Header().Get("Content-Security-Policy"), ";") {
			fields := strings.Fields(directive)
			if len(fields) == 0 {
				continue
			}
			name := strings.ToLower(fields[0])
			if _, seen := directives[name]; seen {
				t.Errorf("directive %s appears twice (secure=%v); a browser ignores the second, "+
					"so what it says is not what is enforced", name, secure)
				continue
			}
			directives[name] = fields[1:]
		}

		scriptSrc, ok := directives["script-src"]
		if !ok {
			t.Fatalf("the policy has no script-src (secure=%v), so a browser runs any inline "+
				"script, on… attribute or javascript: URL that reaches a page", secure)
		}
		for _, source := range scriptSrc {
			lower := strings.ToLower(source)
			switch {
			case lower == "'unsafe-inline'", lower == "'unsafe-eval'", lower == "'unsafe-hashes'",
				lower == "'wasm-unsafe-eval'":
				t.Errorf("script-src carries %s (secure=%v), which lets the inline code or eval "+
					"the policy exists to refuse run again", source, secure)
			case strings.HasPrefix(lower, "'nonce-"), strings.HasPrefix(lower, "'sha"):
				t.Errorf("script-src carries %s (secure=%v); no page has an inline script to "+
					"mark, so a nonce or a hash only opens a way to run one", source, secure)
			case lower == "'strict-dynamic'":
				t.Errorf("script-src carries 'strict-dynamic' (secure=%v), which makes a browser "+
					"ignore 'self' and trust whatever an allowed script loads", secure)
			case strings.Contains(lower, "*"), strings.HasSuffix(lower, ":"):
				t.Errorf("script-src carries %s (secure=%v), a wildcard or a scheme that allows "+
					"scripts from other origins; every script the servers load is their own "+
					"/static/ file", source, secure)
			}
		}
		if len(scriptSrc) != 1 || scriptSrc[0] != "'self'" {
			t.Errorf("script-src is %q (secure=%v), want exactly 'self': only the script files "+
				"the server itself serves", strings.Join(scriptSrc, " "), secure)
		}

		for _, name := range []string{"object-src", "base-uri", "frame-ancestors"} {
			if got := directives[name]; len(got) != 1 || got[0] != "'none'" {
				t.Errorf("%s is %q (secure=%v), want 'none'", name, strings.Join(got, " "), secure)
			}
		}
	}
}
