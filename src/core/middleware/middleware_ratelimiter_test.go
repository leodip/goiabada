package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetClientIPFromRequest verifies the rate-limit key is derived from
// RemoteAddr only, ignoring spoofable X-Forwarded-For / X-Real-IP headers.
func TestGetClientIPFromRequest(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "IPv4 with port",
			remoteAddr: "203.0.113.7:54321",
			want:       "203.0.113.7",
		},
		{
			name:       "IPv6 with port",
			remoteAddr: "[2001:db8::1]:443",
			want:       "2001:db8::1",
		},
		{
			name:       "IP without port (as RealIP rewrites it)",
			remoteAddr: "203.0.113.7",
			want:       "203.0.113.7",
		},
		{
			name:       "bare IPv6 without port",
			remoteAddr: "::1",
			want:       "::1",
		},
		{
			name:       "X-Forwarded-For is ignored",
			remoteAddr: "203.0.113.7:54321",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8"},
			want:       "203.0.113.7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			if got := getClientIPFromRequest(req); got != tt.want {
				t.Errorf("getClientIPFromRequest(%q) = %q, want %q", tt.remoteAddr, got, tt.want)
			}
		})
	}
}

// TestLimitPwd_PerEmailAndPerIP verifies the password limiter enforces both a
// per-email budget (bounds brute force on one account) and a per-IP budget
// (stops one host hammering many accounts).
func TestLimitPwd_PerEmailAndPerIP(t *testing.T) {
	run := func(m *RateLimiterMiddleware, email, ip string) int {
		req := httptest.NewRequest(http.MethodPost, "/auth/pwd?email="+email, nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		m.LimitPwd(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		return rr.Code
	}

	t.Run("per-email limit trips even from varied IPs", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		blocked := false
		for i := 0; i < 25; i++ {
			ip := fmt.Sprintf("203.0.113.%d:5000", i+1) // distinct IPs so the IP bucket never trips
			if run(m, "victim@example.com", ip) == http.StatusTooManyRequests {
				blocked = true
				break
			}
		}
		if !blocked {
			t.Error("expected per-email limit to trip within 25 attempts")
		}
	})

	t.Run("per-IP limit trips even with varied emails", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		blocked := false
		for i := 0; i < 45; i++ {
			email := fmt.Sprintf("user%d@example.com", i) // distinct emails so no email bucket trips
			if run(m, email, "198.51.100.7:5000") == http.StatusTooManyRequests {
				blocked = true
				break
			}
		}
		if !blocked {
			t.Error("expected per-IP limit to trip within 45 attempts")
		}
	})

	t.Run("disabled limiter never blocks", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, false)
		for i := 0; i < 60; i++ {
			if run(m, "x@example.com", "203.0.113.1:5000") != http.StatusOK {
				t.Fatal("disabled limiter should never block")
			}
		}
	})
}
