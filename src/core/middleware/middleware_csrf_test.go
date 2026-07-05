package middleware

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/securecookie"
)

const skipCheckKey string = "gorilla.csrf.Skip"

func TestMiddlewareSkipCsrf(t *testing.T) {
	tests := []struct {
		name string
		path string
		skip bool
	}{
		// Exempt: exact-match endpoints (bearer/client-authenticated, no cookie).
		{"Authorize exact", "/auth/authorize", true},
		{"Token exact", "/auth/token", true},
		{"Callback exact", "/auth/callback", true},
		{"Userinfo exact", "/userinfo", true},
		{"DCR register exact", "/connect/register", true},

		// Exempt: intentional subtree prefixes.
		{"API admin subtree", "/api/v1/admin/users", true},
		{"API account subtree", "/api/v1/account/profile", true},
		{"API public settings", "/api/public/settings", true},
		{"Static css", "/static/file.css", true},
		{"Static nested js", "/static/js/app.js", true},

		// Drift guards: sibling routes under a formerly-prefixed path must NOT
		// inherit the exemption now that single endpoints are matched exactly.
		{"Token introspect not skipped", "/auth/token-introspect", false},
		{"Tokeninfo not skipped", "/auth/tokeninfo", false},
		{"Tokens not skipped", "/auth/tokens", false},
		{"Userinfo export not skipped", "/userinfo-export", false},
		{"Userinfo typo not skipped", "/userinfoo", false},
		{"Connect register status not skipped", "/connect/register-status", false},
		{"Connect bare not skipped", "/connect/", false},
		{"Static without slash not skipped", "/static-secret", false},
		{"Authorize-extra not skipped", "/auth/authorize-extra", false},

		// Cookie-authenticated routes must keep CSRF protection.
		{"Auth pwd protected", "/auth/pwd", false},
		{"Auth otp protected", "/auth/otp", false},
		{"Auth consent protected", "/auth/consent", false},
		{"Auth logout protected", "/auth/logout", false},
		{"Account register protected", "/account/register", false},
		{"Account profile protected", "/account/profile", false},
		{"Admin console page protected", "/admin/clients", false},
		{"Forgot password protected", "/forgot-password", false},
		{"Reset password protected", "/reset-password", false},
		{"Root protected", "/", false},
		{"Other path", "/other", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.path, nil)
			rr := httptest.NewRecorder()

			handler := MiddlewareSkipCsrf()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				skipValue := r.Context().Value(skipCheckKey)
				if tt.skip {
					if skipValue != true {
						t.Errorf("MiddlewareSkipCsrf() for path %s: expected CSRF check to be skipped, but it wasn't", tt.path)
					}
				} else {
					if skipValue == true {
						t.Errorf("MiddlewareSkipCsrf() for path %s: expected CSRF check not to be skipped, but it was", tt.path)
					}
				}
			}))

			handler.ServeHTTP(rr, req)
		})
	}
}

// TestMiddlewareSkipCsrf_CombinedChain mounts the production middleware chain
// (StripSlashes -> MiddlewareSkipCsrf -> MiddlewareCsrf) onto a chi router and
// issues real cross-origin POSTs. This proves the actual `403 Forbidden -
// origin invalid` regression is fixed end-to-end, beyond the context-flag check
// in TestMiddlewareSkipCsrf.
func TestMiddlewareSkipCsrf_CombinedChain(t *testing.T) {
	testKey := securecookie.GenerateRandomKey(64)
	testKeyHex := hex.EncodeToString(testKey)

	const foreignOrigin = "https://www.certification.openid.net"

	newRouter := func() *chi.Mux {
		r := chi.NewRouter()
		r.Use(chimiddleware.StripSlashes)
		r.Use(MiddlewareSkipCsrf())
		r.Use(MiddlewareCsrf(testKeyHex, "http://localhost:9091", "http://localhost:9090", false))

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
		return r
	}

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		// Exempt endpoints let the foreign-origin POST through.
		{"POST /auth/authorize foreign origin reaches handler", "/auth/authorize", http.StatusOK},
		{"POST /auth/authorize/ trailing slash reaches handler", "/auth/authorize/", http.StatusOK},
		{"POST /auth/token reaches handler", "/auth/token", http.StatusOK},
		{"POST /userinfo reaches handler", "/userinfo", http.StatusOK},
		{"POST /api/v1/admin/users reaches handler", "/api/v1/admin/users", http.StatusOK},

		// Non-exempt routes are still blocked (403 origin invalid).
		{"POST /auth/pwd foreign origin still blocked", "/auth/pwd", http.StatusForbidden},
		{"POST /auth/authorize-extra not skipped", "/auth/authorize-extra", http.StatusForbidden},
		{"POST /auth/token-introspect not skipped", "/auth/token-introspect", http.StatusForbidden},
		{"POST /userinfo-export not skipped", "/userinfo-export", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := newRouter()
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			req.Header.Set("Origin", foreignOrigin)
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("path %s: got status %d, want %d", tt.path, rr.Code, tt.wantStatus)
			}
		})
	}
}

func TestMiddlewareCsrf(t *testing.T) {
	// Generate a test session key and hex-encode it
	testKey := securecookie.GenerateRandomKey(64)
	testKeyHex := hex.EncodeToString(testKey)

	handler := MiddlewareCsrf(testKeyHex, "http://localhost:9091", "http://localhost:9090", false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("CSRF middleware applied", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Header().Get("Set-Cookie") == "" || !strings.Contains(rr.Header().Get("Set-Cookie"), "_gorilla_csrf=") {
			t.Error("Expected CSRF cookie to be set")
		}
	})
}

// TestMiddlewareCsrf_CookieMaxAge verifies the CSRF cookie uses our one-year
// MaxAge rather than gorilla/csrf's 12h default, so it never expires mid-session.
func TestMiddlewareCsrf_CookieMaxAge(t *testing.T) {
	testKey := securecookie.GenerateRandomKey(64)
	testKeyHex := hex.EncodeToString(testKey)

	handler := MiddlewareCsrf(testKeyHex, "http://localhost:9091", "http://localhost:9090", false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req, _ := http.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_gorilla_csrf" {
			found = true
			if c.MaxAge != csrfCookieMaxAgeSeconds {
				t.Errorf("CSRF cookie MaxAge = %d, want %d", c.MaxAge, csrfCookieMaxAgeSeconds)
			}
		}
	}
	if !found {
		t.Fatal("expected _gorilla_csrf cookie to be set")
	}
}
