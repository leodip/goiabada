package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/models"
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

func TestMiddlewareCsrf(t *testing.T) {
	settings := &models.Settings{
		SessionAuthenticationKey: []byte("test-key"),
	}

	handler := MiddlewareCsrf(settings, "http://localhost:9091", "http://localhost:9090", false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
