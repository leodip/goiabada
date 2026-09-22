package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/mock"
)

// The auth server's CSRF behaviour at the chain, which this binary has never had a test for: until
// #385 the exemption table lived in core and was asserted there, in isolation from the routes it
// named and from the router it was mounted on. The table is this server's policy now
// (csrfPolicy in server.go), so the claims about it belong here (decision 5).
//
// Three claims, and each is unprovable anywhere else. That a mounted exempt route is still exempt
// and a mounted protected one still refused are properties of the policy composed with this
// router; core's tables pass perfectly against a policy nobody wired up. That a path this binary
// does not mount is refused rather than routed is the one behaviour change the split makes, and it
// exists only at the chain.
//
// Every case is a pair differing in exactly one thing, the origin headers, so no 403 can be
// attributed to anything but the origin check. The 403 body is asserted against the catalog for the
// same reason: a 403 from a handler further down would read differently.

const (
	// foreignOrigin is a third-party site POSTing into this deployment. The header pair is what a
	// browser sends for a genuine cross-site form submission.
	foreignOrigin = "https://www.certification.openid.net"
)

func TestInitMiddleware_CsrfPolicy(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		// mounted says whether newCsrfTestServer registers a handler for this path, mirroring
		// whether the real binary mounts it. It decides only what the same-origin control expects.
		mounted    bool
		wantStatus int
	}{
		// Claim 1: a mounted exempt route is still exempt. One per shape the policy uses, so a
		// dropped entry in any of the three fails here.
		{"POST /auth/authorize is exempt", "/auth/authorize", "", true, http.StatusOK},
		{"POST /auth/token is exempt", "/auth/token", "", true, http.StatusOK},
		{"POST /userinfo is exempt", "/userinfo", "", true, http.StatusOK},
		{"POST /connect/register is exempt", "/connect/register", "", true, http.StatusOK},
		{"POST under the /api/ prefix is exempt", "/api/v1/admin/users", "", true, http.StatusOK},

		// The conditional entry, reaching the enforcing middleware through the policy rather than
		// through a package-level map. Both halves, because the hintless POST is the shape an
		// unconditional entry would have let through and the reason the shape exists at all (#109).
		{"POST /auth/logout with a hint in the query is exempt", "/auth/logout?id_token_hint=abc", "", true, http.StatusOK},
		{"POST /auth/logout with a hint in the body is exempt", "/auth/logout", "id_token_hint=abc", true, http.StatusOK},
		{"POST /auth/logout with no hint is refused", "/auth/logout", "", true, http.StatusForbidden},

		// Claim 2: a mounted protected route is still refused. /auth/pwd is a cookie-authenticated
		// form, which is exactly what CSRF defends.
		{"POST /auth/pwd is refused", "/auth/pwd", "", true, http.StatusForbidden},
		{"POST /auth/consent is refused", "/auth/consent", "", true, http.StatusForbidden},

		// Drift guards: a sibling of an exempt route inherits nothing, because ExactPaths is
		// matched exactly.
		{"POST /auth/token-introspect is refused", "/auth/token-introspect", "", true, http.StatusForbidden},
		{"POST /userinfo-export is refused", "/userinfo-export", "", true, http.StatusForbidden},

		// Claim 3, the one behaviour change. /auth/callback is the admin console's OAuth callback.
		// This binary does not mount it, and the shared table in core exempted it for both, so a
		// cross-origin POST used to pass the origin check and reach chi for a 404. It is refused
		// 403 by the origin check now, which tells a prober less than the 404 did (decision 5).
		{"POST /auth/callback is refused rather than routed", "/auth/callback", "", false, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body *strings.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			} else {
				body = strings.NewReader("")
			}

			req := httptest.NewRequest(http.MethodPost, tt.path, body)
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			req.Header.Set("Origin", foreignOrigin)
			req.Header.Set("Sec-Fetch-Site", "cross-site")

			rr := httptest.NewRecorder()
			newCsrfTestServer(t).router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("cross-site POST %s: got status %d, want %d", tt.path, rr.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusForbidden {
				// The body is MiddlewareCsrf's own message, which is what attributes the 403 to the
				// origin check rather than to any handler further down. Read from the catalog, so
				// rewording the entry does not fail this test while a 403 from somewhere else still
				// does.
				want := i18n.T(context.Background(), "error.csrf_refused")
				if got := strings.TrimSpace(rr.Body.String()); got != want {
					t.Errorf("body = %q, want the CSRF middleware's message %q", got, want)
				}
			}
		})
	}

	// The control half. Every request above, same-origin, so each 403 above is attributable to the
	// origin headers and to nothing else in the chain. Without this the table is satisfied by a
	// server that refuses everything.
	//
	// The unmounted path is where the control is load-bearing rather than hygienic: same-origin it
	// is a 404, which is what the cross-origin request used to get and what the 403 above replaced.
	for _, tt := range tests {
		t.Run("same-origin control: "+tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body))
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			req.Header.Set("Sec-Fetch-Site", "same-origin")

			rr := httptest.NewRecorder()
			newCsrfTestServer(t).router.ServeHTTP(rr, req)

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

// newCsrfTestServer builds the real chain through initMiddleware and registers probe handlers on
// the root branch for the routes under test.
//
// Root branch rather than the application branch on purpose: CSRF is mounted on the root, and the
// application branch adds the settings read and the session load, which would make this a test of
// those instead. The route set therefore stands in for initRoutes rather than being it, and the
// stand-in is faithful in the one way that matters here: /auth/callback is absent, because the auth
// server does not mount it, which is what the unmounted claim is about.
func newCsrfTestServer(t *testing.T) *Server {
	t.Helper()

	database := mocks_data.NewDatabase(t)
	// MiddlewareCors consults the registered web origins for /auth/token, /auth/logout and
	// /userinfo when an Origin header is present, which every cross-site row here sends. Answering
	// false is the production answer for an unregistered origin and keeps CORS out of the result:
	// the origin check is what these rows are about.
	database.On("WebOriginExists", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()

	s := &Server{
		router:       chi.NewRouter(),
		database:     database,
		sessionStore: newTestSessionStore(),
	}
	s.initMiddleware()

	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	for _, path := range []string{
		"/auth/authorize",
		"/auth/token",
		"/auth/token-introspect",
		"/auth/logout",
		"/auth/pwd",
		"/auth/consent",
		"/userinfo",
		"/userinfo-export",
		"/connect/register",
		"/api/v1/admin/users",
	} {
		s.router.Post(path, ok)
	}
	return s
}
