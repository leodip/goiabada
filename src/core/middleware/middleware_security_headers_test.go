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
				"Referrer-Policy":           "same-origin",
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
				"Referrer-Policy":           "same-origin",
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

// TestMiddlewareSecurityHeaders_ReferrerPolicyIsNotNoReferrer guards a regression that
// broke every login: Referrer-Policy: no-referrer makes browsers send "Origin: null" on
// form POSTs, and gorilla/csrf rejects an opaque origin because it has no host for any
// TrustedOrigins entry to match. The result was "403 Forbidden - origin invalid" on the
// password form, the OTP form, the consent screen and every admin console form.
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
func TestMiddlewareSecurityHeaders_ReferrerPolicyIsNotNoReferrer(t *testing.T) {
	for _, secure := range []bool{false, true} {
		handler := MiddlewareSecurityHeaders(secure)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/auth/pwd", nil))

		got := rr.Header().Get("Referrer-Policy")
		if got == "no-referrer" {
			t.Fatalf("Referrer-Policy is no-referrer (secure=%v); that makes browsers send "+
				"Origin: null on form POSTs, which fails CSRF validation for every "+
				"cookie-authenticated POST", secure)
		}
		if got == "" {
			t.Errorf("Referrer-Policy is unset (secure=%v); it should be same-origin", secure)
		}
	}
}
