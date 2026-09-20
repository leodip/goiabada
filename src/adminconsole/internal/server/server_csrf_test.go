package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/cache"
	"github.com/leodip/goiabada/core/i18n"
)

// TestInitMiddleware_CsrfIsRegistered makes the claim the CSRF unit tables in
// src/core/middleware cannot: that MiddlewareCsrf is actually mounted on the admin console's
// router. Those tables pass perfectly against a middleware nobody wired up, and #155 rewrote this
// wiring, so a deleted Use() line is exactly the regression they would miss.
//
// The compiler does not cover it. Deleting the CSRF registration from initMiddleware still builds:
// the package references custom_middleware on four other lines, so nothing goes unused. And the
// admin console has no integration suite (src/authserver/tests holds the only one), so there is no
// running-server test to catch it either. initMiddleware is an ordinary method though, and httptest
// drives it with no harness at all.
//
// The two halves are otherwise identical requests, differing only in their origin headers. That
// pairing is what makes the 403 attributable to the CSRF middleware rather than to anything else in
// the chain: a lone 403 would prove nothing.
func TestInitMiddleware_CsrfIsRegistered(t *testing.T) {
	// The settings cache points at an address nothing listens on, and that is deliberate: it is
	// what keeps this a unit test. MiddlewareSettingsCache is the next entry after CSRF in
	// initMiddleware, and on a fetch failure it answers through http.Error rather than panicking,
	// so a request that passes the origin check has a deterministic non-403 outcome and no live
	// auth server is needed.
	const unreachableAuthServer = "http://127.0.0.1:1"

	newServer := func() *Server {
		s := &Server{
			router:        chi.NewRouter(),
			sessionStore:  newTestSessionStore(),
			settingsCache: cache.NewSettingsCache(unreachableAuthServer),
		}
		s.initMiddleware()
		s.router.Post("/admin/clients", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		return s
	}

	post := func(t *testing.T, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()

		form := url.Values{"name": {"whatever"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/clients", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for name, value := range headers {
			req.Header.Set(name, value)
		}

		rr := httptest.NewRecorder()
		newServer().router.ServeHTTP(rr, req)
		return rr
	}

	t.Run("a cross-site POST is refused by the CSRF middleware", func(t *testing.T) {
		rr := post(t, map[string]string{
			"Origin":         "https://relying-party.example",
			"Sec-Fetch-Site": "cross-site",
		})

		if rr.Code != http.StatusForbidden {
			t.Fatalf("got status %d, want %d: a cross-site POST must be refused, and if it is not "+
				"then MiddlewareCsrf is no longer registered on the admin console", rr.Code, http.StatusForbidden)
		}

		// The body is MiddlewareCsrf's own message, which is what attributes the 403 to the
		// origin check rather than to any handler further down. Read from the catalog, so
		// rewording the entry does not fail this test while a 403 from somewhere else still
		// does. TestInitMiddleware_RefusalsAreLocalized covers it in the caller's language.
		want := i18n.T(context.Background(), "error.csrf_refused")
		if body := strings.TrimSpace(rr.Body.String()); body != want {
			t.Errorf("body = %q, want the CSRF middleware's message %q", body, want)
		}
	})

	t.Run("a same-origin POST is not refused by the CSRF middleware", func(t *testing.T) {
		rr := post(t, map[string]string{"Sec-Fetch-Site": "same-origin"})

		// Deliberately != 403 rather than == 500, so this does not couple to which middleware
		// answers next. All that matters is that the origin headers alone decided the case above.
		if rr.Code == http.StatusForbidden {
			t.Errorf("got status %d: a same-origin POST must pass the origin check", rr.Code)
		}
	})
}

// TestInitMiddleware_CsrfPolicy makes the claims about which of this binary's routes the origin
// check applies to. Until #385 the exemption table lived in core and named both binaries' routes,
// so the admin console exempted /auth/authorize, /auth/token, /userinfo and /connect/register,
// none of which it mounts. The table is this server's policy now (csrfPolicy in server.go), and
// these are the claims it owes (decision 5).
//
// The test above proves the middleware is mounted at all; this one proves what it decides. Both
// are needed: a policy asserted in isolation passes against a middleware nobody wired up, and a
// mounted middleware proves nothing about which routes it exempts.
//
// Every row is paired with a same-origin control differing only in the origin headers, so no 403
// can be attributed to anything else in the chain.
func TestInitMiddleware_CsrfPolicy(t *testing.T) {
	tests := []struct {
		name string
		path string
		// mounted mirrors whether this binary registers the path, and decides only what the
		// same-origin control expects.
		mounted             bool
		wantCrossSiteStatus int
	}{
		// Claim 1: a mounted exempt route is still exempt. /auth/callback is the OAuth callback, a
		// cross-site form_post carrying the auth code, protected by the OAuth `state` parameter
		// rather than by the origin check. It is the only exact entry this server has.
		{"POST /auth/callback is exempt", "/auth/callback", true, http.StatusOK},

		// Claim 2: a mounted protected route is still refused. Every admin page is a
		// cookie-authenticated form, which is exactly what CSRF defends.
		{"POST /admin/clients is refused", "/admin/clients", true, http.StatusForbidden},
		{"POST /account/profile is refused", "/account/profile", true, http.StatusForbidden},

		// A sibling of the exempt route inherits nothing, because ExactPaths is matched exactly.
		{"POST /auth/callback-extra is refused", "/auth/callback-extra", true, http.StatusForbidden},

		// Claim 3, the one behaviour change. These are the auth server's endpoints. This binary
		// mounts none of them, and the shared table in core exempted them for both, so a
		// cross-origin POST used to pass the origin check here and reach chi for a 404. Each is
		// refused 403 by the origin check now, which tells a prober less than the 404 did.
		{"POST /auth/token is refused rather than routed", "/auth/token", false, http.StatusForbidden},
		{"POST /auth/authorize is refused rather than routed", "/auth/authorize", false, http.StatusForbidden},
		{"POST /userinfo is refused rather than routed", "/userinfo", false, http.StatusForbidden},
		{"POST /connect/register is refused rather than routed", "/connect/register", false, http.StatusForbidden},
		{"POST under the /api/ prefix is refused rather than routed", "/api/v1/admin/users", false, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := csrfProbe(t, tt.path, map[string]string{
				"Origin":         "https://relying-party.example",
				"Sec-Fetch-Site": "cross-site",
			})

			if rr.Code != tt.wantCrossSiteStatus {
				t.Fatalf("cross-site POST %s: got status %d, want %d", tt.path, rr.Code, tt.wantCrossSiteStatus)
			}
			if tt.wantCrossSiteStatus == http.StatusForbidden {
				// The catalog message, which is what attributes the 403 to the origin check rather
				// than to a handler further down. The unmounted rows are the ones this matters
				// most for: a 403 that was really a routing answer would read differently.
				want := i18n.T(context.Background(), "error.csrf_refused")
				if got := strings.TrimSpace(rr.Body.String()); got != want {
					t.Errorf("body = %q, want the CSRF middleware's message %q", got, want)
				}
			}
		})
	}

	// The control half. Same-origin, every row, so each 403 above is the origin check and not the
	// router. On the unmounted rows it is load-bearing rather than hygienic: the 404 here is what
	// the cross-origin request used to get, which is the behaviour change stated as a difference
	// rather than asserted as a status.
	for _, tt := range tests {
		t.Run("same-origin control: "+tt.name, func(t *testing.T) {
			rr := csrfProbe(t, tt.path, map[string]string{"Sec-Fetch-Site": "same-origin"})

			want := http.StatusOK
			if !tt.mounted {
				want = http.StatusNotFound
			}
			if rr.Code != want {
				t.Errorf("same-origin POST %s: got status %d, want %d", tt.path, rr.Code, want)
			}
		})
	}
}

// csrfProbe drives the real chain through initMiddleware with probe handlers registered on the
// root branch, which is where CSRF is mounted. The application branch adds the settings cache and
// the cookie reset, neither of which has anything to say about the origin check, so staying off it
// keeps a passing request at a deterministic 200 and needs no live auth server.
//
// The route set stands in for initRoutes rather than being it, and it is faithful in the way that
// decides this test: the auth server's endpoints are absent, because this binary does not mount
// them.
func csrfProbe(t *testing.T, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	const unreachableAuthServer = "http://127.0.0.1:1"

	s := &Server{
		router:        chi.NewRouter(),
		sessionStore:  newTestSessionStore(),
		settingsCache: cache.NewSettingsCache(unreachableAuthServer),
	}
	s.initMiddleware()

	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	for _, mounted := range []string{
		"/auth/callback",
		"/auth/callback-extra",
		"/admin/clients",
		"/account/profile",
	} {
		s.router.Post(mounted, ok)
	}

	form := url.Values{"name": {"whatever"}}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	return rr
}
