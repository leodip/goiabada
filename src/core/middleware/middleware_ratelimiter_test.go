package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/oauth"
)

// stubAuthHelper stands in for the real AuthHelper, which needs a session store
// and a cookie to answer. It reads the user id from the request's query string so
// one middleware instance can be driven with several users, which is what shows
// the OTP budget is keyed per user rather than globally. A non-nil err is
// returned for every request, standing for an unreadable auth context.
type stubAuthHelper struct {
	err error
}

func (s stubAuthHelper) GetAuthContext(r *http.Request) (*oauth.AuthContext, error) {
	if s.err != nil {
		return nil, s.err
	}
	userId, _ := strconv.ParseInt(r.URL.Query().Get("userId"), 10, 64)
	return &oauth.AuthContext{UserId: userId}, nil
}

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

			if got := GetClientIPFromRequest(req); got != tt.want {
				t.Errorf("GetClientIPFromRequest(%q) = %q, want %q", tt.remoteAddr, got, tt.want)
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

// TestLimitForgotPwd_PerEmailAndPerIP verifies the forgot-password limiter
// bounds both a single address (mail-bombing) and a single source IP.
func TestLimitForgotPwd_PerEmailAndPerIP(t *testing.T) {
	run := func(m *RateLimiterMiddleware, email, ip string) int {
		req := httptest.NewRequest(http.MethodPost, "/forgot-password?email="+email, nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		m.LimitForgotPwd(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		return rr.Code
	}

	t.Run("per-email limit trips even from varied IPs", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		blocked := false
		for i := 0; i < 12; i++ {
			ip := fmt.Sprintf("203.0.113.%d:5000", i+1) // distinct IPs so the IP bucket never trips
			if run(m, "victim@example.com", ip) == http.StatusTooManyRequests {
				blocked = true
				break
			}
		}
		if !blocked {
			t.Error("expected per-email limit to trip within 12 attempts")
		}
	})

	t.Run("per-IP limit trips even with varied emails", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		blocked := false
		for i := 0; i < 30; i++ {
			email := fmt.Sprintf("user%d@example.com", i) // distinct emails so no email bucket trips
			if run(m, email, "198.51.100.9:5000") == http.StatusTooManyRequests {
				blocked = true
				break
			}
		}
		if !blocked {
			t.Error("expected per-IP limit to trip within 30 attempts")
		}
	})

	t.Run("disabled limiter never blocks", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, false)
		for i := 0; i < 40; i++ {
			if run(m, "x@example.com", "203.0.113.1:5000") != http.StatusOK {
				t.Fatal("disabled limiter should never block")
			}
		}
	})
}

// TestLimitResetPwd_PerIP verifies the reset-password limiter's budget and, above all, its
// key. It had no test at all until #112, which is why the value it enforced was free to
// change without anything noticing.
//
// The key is the point: the reset link no longer carries ?email=, and the two steps after it
// run on a URL with no query, so the old key would evaluate to the empty string on every
// request and the whole deployment would share one bucket. Keying on the client IP is what
// stops that being a denial of service on password reset (#112 decision 4).
//
// The budget is exact rather than approximate, because it is published policy: 30 requests
// per 5 minutes, which is 10 reset operations at the three requests a reset now costs
// (decision 11). An off-by-one here is a user locked out or a host given more room than the
// documentation promises, so the boundary is asserted on both sides.
//
// The handler stub writes 418 rather than 200 on purpose: a middleware that writes nothing
// produces exactly 200 with an empty body, so 418 is what tells "the handler ran" apart from
// "nothing was written", and from 429.
func TestLimitResetPwd_PerIP(t *testing.T) {
	const budget = 30

	run := func(m *RateLimiterMiddleware, target, ip string) (int, bool) {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		reached := false
		m.LimitResetPwd(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusTeapot)
		})).ServeHTTP(rr, req)
		return rr.Code, reached
	}

	t.Run("the budget is exactly 30 per IP", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		for i := 0; i < budget; i++ {
			if code, reached := run(m, "/reset-password", "203.0.113.7:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached := run(m, "/reset-password", "203.0.113.7:5000"); code != http.StatusTooManyRequests || reached {
			t.Errorf("request %d: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("a second client IP has an independent bucket", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		for i := 0; i < budget+1; i++ {
			run(m, "/reset-password", "203.0.113.7:5000")
		}
		// Same middleware instance, different host: a global key would block this, which is
		// exactly what an empty key would produce.
		if code, reached := run(m, "/reset-password", "198.51.100.9:5000"); code != http.StatusTeapot || !reached {
			t.Errorf("second IP: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("the address in the query no longer keys anything", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		// A distinct address per request used to buy a fresh bucket each time. From one host
		// they now share one, which is what makes the rekey observable.
		blocked := false
		for i := 0; i < budget+1; i++ {
			target := fmt.Sprintf("/reset-password?email=user%d@example.com", i)
			if code, _ := run(m, target, "203.0.113.7:5000"); code == http.StatusTooManyRequests {
				blocked = true
				break
			}
		}
		if !blocked {
			t.Errorf("expected one host to be limited within %d requests regardless of the address", budget+1)
		}
	})

	t.Run("disabled limiter never blocks", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, false)
		for i := 0; i < budget*2; i++ {
			if code, reached := run(m, "/reset-password", "203.0.113.1:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: disabled limiter should never block, got code %d, handler reached %v",
					i+1, code, reached)
			}
		}
	})
}

// TestLimitOtp_PerUserAndMissingAuthContext verifies the OTP limiter keys its
// budget on the user id, and that a request whose auth context cannot be read
// reaches the handler instead of being answered with a blank 200 (#114).
//
// The handler stub writes 418 rather than 200 on purpose: a middleware that
// writes nothing produces exactly 200 with an empty body, so 418 is what tells
// "the handler ran" apart from "nothing was written", and from 429.
func TestLimitOtp_PerUserAndMissingAuthContext(t *testing.T) {
	run := func(m *RateLimiterMiddleware, userId int) (int, bool) {
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/auth/otp?userId=%d", userId), nil)
		rr := httptest.NewRecorder()
		reached := false
		m.LimitOtp(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusTeapot)
		})).ServeHTTP(rr, req)
		return rr.Code, reached
	}

	t.Run("unreadable auth context reaches the handler", func(t *testing.T) {
		m := NewRateLimiterMiddleware(stubAuthHelper{err: customerrors.ErrNoAuthContext}, true)
		// Well past the 10/min budget: the pass-through is deliberately not
		// bounded by this middleware, since there is no user to key a bucket on.
		for i := 0; i < 20; i++ {
			code, reached := run(m, 0)
			if code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
	})

	t.Run("a readable auth context still spends the budget", func(t *testing.T) {
		m := NewRateLimiterMiddleware(stubAuthHelper{}, true)
		for i := 0; i < 10; i++ {
			if code, reached := run(m, 42); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached := run(m, 42); code != http.StatusTooManyRequests || reached {
			t.Errorf("11th attempt: got code %d, handler reached %v; want %d and false",
				code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("each user id has its own budget", func(t *testing.T) {
		m := NewRateLimiterMiddleware(stubAuthHelper{}, true)
		blocked := false
		for i := 0; i < 11; i++ {
			if code, _ := run(m, 42); code == http.StatusTooManyRequests {
				blocked = true
				break
			}
		}
		if !blocked {
			t.Fatal("expected user 42 to be limited within 11 attempts")
		}
		// Same middleware instance, different user: a global key would block this.
		if code, reached := run(m, 43); code != http.StatusTeapot || !reached {
			t.Errorf("second user: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("disabled limiter never blocks", func(t *testing.T) {
		m := NewRateLimiterMiddleware(stubAuthHelper{}, false)
		for i := 0; i < 60; i++ {
			if code, reached := run(m, 42); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d: disabled limiter should never block, got code %d, handler reached %v",
					i+1, code, reached)
			}
		}
	})
}
