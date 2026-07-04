package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddlewareSecurityHeaders(t *testing.T) {
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
				"Content-Security-Policy":   "frame-ancestors 'none'",
				"X-Content-Type-Options":    "nosniff",
				"Referrer-Policy":           "no-referrer",
				"Strict-Transport-Security": "",
			},
		},
		{
			name:   "secure includes HSTS",
			secure: true,
			want: map[string]string{
				"X-Frame-Options":           "DENY",
				"Content-Security-Policy":   "frame-ancestors 'none'",
				"X-Content-Type-Options":    "nosniff",
				"Referrer-Policy":           "no-referrer",
				"Strict-Transport-Security": strictTransportSecurityValue,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := MiddlewareSecurityHeaders(tt.secure)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
