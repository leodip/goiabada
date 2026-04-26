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
		{"Static path", "/static/file.css", true},
		{"Userinfo path", "/userinfo", true},
		{"Token path", "/auth/token", true},
		{"Callback path", "/auth/callback", true},
		{"Authorize exact", "/auth/authorize", true},
		{"Authorize-extra not skipped", "/auth/authorize-extra", false},
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
		return r
	}

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{"POST /auth/authorize foreign origin reaches handler", "/auth/authorize", http.StatusOK},
		{"POST /auth/authorize/ trailing slash reaches handler", "/auth/authorize/", http.StatusOK},
		{"POST /auth/pwd foreign origin still blocked", "/auth/pwd", http.StatusForbidden},
		{"POST /auth/authorize-extra not skipped", "/auth/authorize-extra", http.StatusForbidden},
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
