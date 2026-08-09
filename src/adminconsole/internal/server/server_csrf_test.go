package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/cache"
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
			sessionStore:  sessions.NewCookieStore(securecookie.GenerateRandomKey(64)),
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

		// The prefix is MiddlewareCsrf's own, written by its http.Error call, which is what
		// attributes the 403 to the CSRF middleware rather than to any handler further down. The
		// reason after it is the standard library's wording and is deliberately not asserted.
		if body := rr.Body.String(); !strings.HasPrefix(body, "Forbidden - ") {
			t.Errorf("body = %q, want the CSRF middleware's %q prefix", body, "Forbidden - ")
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
