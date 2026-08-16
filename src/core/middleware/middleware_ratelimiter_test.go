package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
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

// spellingsOf returns ten spellings of one address that differ only in case and
// surrounding whitespace. Every one of them names the same account: all five write
// paths store strings.ToLower(strings.TrimSpace(...)), so these are the shapes a
// user (or an attacker looking for a fresh bucket) can type for one account.
func spellingsOf(local, domain string) []string {
	base := local + "@" + domain
	return []string{
		base,
		strings.ToUpper(base),
		strings.ToUpper(local[:1]) + local[1:] + "@" + strings.ToUpper(domain[:1]) + domain[1:],
		strings.ToUpper(local) + "@" + domain,
		local + "@" + strings.ToUpper(domain),
		"  " + base,
		base + "   ",
		" " + strings.ToUpper(base) + " ",
		"\t" + base + "\t",
		"\n" + strings.ToUpper(local) + "@" + domain + "\n",
	}
}

// TestLimitPwd_PerEmailAndPerIP verifies the password limiter enforces both a
// per-email budget (bounds brute force on one account) and a per-IP budget
// (stops one host hammering many accounts), and that neither budget can be
// escaped by respelling the address or by moving inside one's own /64 (#219).
//
// Both budgets are asserted exactly, on both sides, because they are published
// policy in the reference documentation. That is the convention
// TestLimitResetPwd_PerIP established.
//
// The handler stub writes 418 rather than 200 on purpose: a middleware that writes
// nothing produces exactly 200 with an empty body, so 418 is what tells "the handler
// ran" apart from "nothing was written", and from 429.
//
// The request carries the address in a form body rather than a query string, which is
// what the real route sends. A query target cannot express the whitespace spellings at
// all: httptest.NewRequest parses its target as a request line and panics on one.
func TestLimitPwd_PerEmailAndPerIP(t *testing.T) {
	const emailBudget = 15
	const ipBudget = 30

	run := func(m *RateLimiterMiddleware, email, ip string) (int, bool) {
		form := url.Values{"email": {email}}
		req := httptest.NewRequest(http.MethodPost, "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		reached := false
		m.LimitPwd(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusTeapot)
		})).ServeHTTP(rr, req)
		return rr.Code, reached
	}

	// A distinct IPv4 address per request, so only the account tier can trip.
	freshIP := func(i int) string { return fmt.Sprintf("203.0.113.%d:5000", i+1) }

	t.Run("the per-email budget is exactly 15, from varied IPs", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		for i := 0; i < emailBudget; i++ {
			if code, reached := run(m, "victim@example.com", freshIP(i)); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached := run(m, "victim@example.com", freshIP(emailBudget)); code != http.StatusTooManyRequests || reached {
			t.Errorf("request %d: got code %d, handler reached %v; want %d and false",
				emailBudget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("ten case and whitespace variants of one address share the per-email bucket", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		spellings := spellingsOf("victim", "example.com")
		// Refused by accountRateLimitKey lowercasing and trimming, not by the limiter
		// merely working: without it each spelling is its own bucket and all 16 pass.
		for i := 0; i < emailBudget; i++ {
			if code, reached := run(m, spellings[i%len(spellings)], freshIP(i)); code != http.StatusTeapot || !reached {
				t.Fatalf("spelling %q (request %d): got code %d, handler reached %v; want %d and true",
					spellings[i%len(spellings)], i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached := run(m, spellings[emailBudget%len(spellings)], freshIP(emailBudget)); code != http.StatusTooManyRequests || reached {
			t.Errorf("request %d: got code %d, handler reached %v; want %d and false",
				emailBudget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("a second address still has its own bucket", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		spellings := spellingsOf("victim", "example.com")
		for i := 0; i < emailBudget+1; i++ {
			run(m, spellings[i%len(spellings)], freshIP(i))
		}
		// Same middleware instance, a genuinely different account: a key that stopped
		// distinguishing accounts at all would block this, so the case above cannot pass
		// by the normalization being over-broad.
		if code, reached := run(m, "other@example.com", freshIP(emailBudget+1)); code != http.StatusTeapot || !reached {
			t.Errorf("second address: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("the per-IP budget is exactly 30, from varied emails", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		for i := 0; i < ipBudget; i++ {
			// Distinct emails so no account bucket trips.
			email := fmt.Sprintf("user%d@example.com", i)
			if code, reached := run(m, email, "198.51.100.7:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached := run(m, "last@example.com", "198.51.100.7:5000"); code != http.StatusTooManyRequests || reached {
			t.Errorf("request %d: got code %d, handler reached %v; want %d and false",
				ipBudget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("200 addresses inside one /64 share the per-IP bucket", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		// A fresh IPv6 address per request, all inside 2001:db8:1:2::/64, which is what a
		// single SLAAC host owns. Refused by clientIPRateLimitKey masking to the /64:
		// without it all 200 reach the handler (measured, #219).
		addr := func(i int) string { return fmt.Sprintf("[2001:db8:1:2::%x]:5000", i+1) }
		for i := 0; i < ipBudget; i++ {
			email := fmt.Sprintf("user%d@example.com", i)
			if code, reached := run(m, email, addr(i)); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d from %s: got code %d, handler reached %v; want %d and true",
					i+1, addr(i), code, reached, http.StatusTeapot)
			}
		}
		for i := ipBudget; i < 200; i++ {
			email := fmt.Sprintf("user%d@example.com", i)
			if code, reached := run(m, email, addr(i)); code != http.StatusTooManyRequests || reached {
				t.Fatalf("request %d from %s: got code %d, handler reached %v; want %d and false",
					i+1, addr(i), code, reached, http.StatusTooManyRequests)
			}
		}
	})

	t.Run("a second /64 has its own bucket", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		for i := 0; i < ipBudget+1; i++ {
			run(m, fmt.Sprintf("user%d@example.com", i), fmt.Sprintf("[2001:db8:1:2::%x]:5000", i+1))
		}
		// A neighbouring /64 is a different client. This is what makes the mask
		// observable rather than the limiter: a key that collapsed every IPv6 address
		// into one bucket would block this too.
		if code, reached := run(m, "elsewhere@example.com", "[2001:db8:1:3::1]:5000"); code != http.StatusTeapot || !reached {
			t.Errorf("second /64: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("disabled limiter never blocks", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, false)
		for i := 0; i < 60; i++ {
			if code, reached := run(m, "x@example.com", "203.0.113.1:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: disabled limiter should never block, got code %d, handler reached %v",
					i+1, code, reached)
			}
		}
	})
}

// TestLimitForgotPwd_PerEmailAndPerIP verifies the forgot-password limiter bounds
// both a single address (mail-bombing) and a single source IP, and that neither
// budget can be escaped by respelling the address or by moving inside one's own
// /64 (#219). Same conventions as TestLimitPwd_PerEmailAndPerIP: exact budgets, a
// 418 stub, and a form body rather than a query target.
func TestLimitForgotPwd_PerEmailAndPerIP(t *testing.T) {
	const emailBudget = 5
	const ipBudget = 20

	run := func(m *RateLimiterMiddleware, email, ip string) (int, bool) {
		form := url.Values{"email": {email}}
		req := httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		reached := false
		m.LimitForgotPwd(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusTeapot)
		})).ServeHTTP(rr, req)
		return rr.Code, reached
	}

	// A distinct IPv4 address per request, so only the account tier can trip.
	freshIP := func(i int) string { return fmt.Sprintf("203.0.113.%d:5000", i+1) }

	t.Run("the per-email budget is exactly 5, from varied IPs", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		for i := 0; i < emailBudget; i++ {
			if code, reached := run(m, "victim@example.com", freshIP(i)); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached := run(m, "victim@example.com", freshIP(emailBudget)); code != http.StatusTooManyRequests || reached {
			t.Errorf("request %d: got code %d, handler reached %v; want %d and false",
				emailBudget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("ten case and whitespace variants of one address share the per-email bucket", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		spellings := spellingsOf("victim", "example.com")
		// Refused by accountRateLimitKey lowercasing and trimming: without it each
		// spelling buys a fresh mail-bombing budget for the same mailbox.
		for i := 0; i < emailBudget; i++ {
			if code, reached := run(m, spellings[i%len(spellings)], freshIP(i)); code != http.StatusTeapot || !reached {
				t.Fatalf("spelling %q (request %d): got code %d, handler reached %v; want %d and true",
					spellings[i%len(spellings)], i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached := run(m, spellings[emailBudget%len(spellings)], freshIP(emailBudget)); code != http.StatusTooManyRequests || reached {
			t.Errorf("request %d: got code %d, handler reached %v; want %d and false",
				emailBudget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("a second address still has its own bucket", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		spellings := spellingsOf("victim", "example.com")
		for i := 0; i < emailBudget+1; i++ {
			run(m, spellings[i%len(spellings)], freshIP(i))
		}
		if code, reached := run(m, "other@example.com", freshIP(emailBudget+1)); code != http.StatusTeapot || !reached {
			t.Errorf("second address: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("the per-IP budget is exactly 20, from varied emails", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		for i := 0; i < ipBudget; i++ {
			email := fmt.Sprintf("user%d@example.com", i) // distinct emails so no email bucket trips
			if code, reached := run(m, email, "198.51.100.9:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached := run(m, "last@example.com", "198.51.100.9:5000"); code != http.StatusTooManyRequests || reached {
			t.Errorf("request %d: got code %d, handler reached %v; want %d and false",
				ipBudget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("addresses inside one /64 share the per-IP bucket", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		addr := func(i int) string { return fmt.Sprintf("[2001:db8:1:2::%x]:5000", i+1) }
		for i := 0; i < ipBudget; i++ {
			email := fmt.Sprintf("user%d@example.com", i)
			if code, reached := run(m, email, addr(i)); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d from %s: got code %d, handler reached %v; want %d and true",
					i+1, addr(i), code, reached, http.StatusTeapot)
			}
		}
		if code, reached := run(m, "last@example.com", addr(ipBudget)); code != http.StatusTooManyRequests || reached {
			t.Errorf("request %d from %s: got code %d, handler reached %v; want %d and false",
				ipBudget+1, addr(ipBudget), code, reached, http.StatusTooManyRequests)
		}
		// A neighbouring /64 is a different client, which is what makes the mask
		// observable rather than the limiter.
		if code, reached := run(m, "elsewhere@example.com", "[2001:db8:1:3::1]:5000"); code != http.StatusTeapot || !reached {
			t.Errorf("second /64: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("disabled limiter never blocks", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, false)
		for i := 0; i < 40; i++ {
			if code, reached := run(m, "x@example.com", "203.0.113.1:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: disabled limiter should never block, got code %d, handler reached %v",
					i+1, code, reached)
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

// TestLimitActivate_PerIP verifies the activation limiter's budget and its key, the same
// pair TestLimitResetPwd_PerIP covers for the other emailed-link flow. It had no test at all
// until #112 either.
//
// The key is the point: the activation link no longer carries ?email=, and the step after it
// runs on a URL with no query, so the old key would evaluate to the empty string on every
// request and one deployment-wide bucket of 5 per 5 minutes would stop everyone activating an
// account.
//
// The budget is exact because it is published policy: 20 requests per 5 minutes, which is 10
// activation operations at the two requests an activation now costs, the same operation rate
// as reset over a chain one request shorter (decision 11).
//
// The handler stub writes 418 rather than 200 on purpose: a middleware that writes nothing
// produces exactly 200 with an empty body, so 418 is what tells "the handler ran" apart from
// "nothing was written", and from 429.
func TestLimitActivate_PerIP(t *testing.T) {
	const budget = 20

	run := func(m *RateLimiterMiddleware, target, ip string) (int, bool) {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		reached := false
		m.LimitActivate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusTeapot)
		})).ServeHTTP(rr, req)
		return rr.Code, reached
	}

	t.Run("the budget is exactly 20 per IP", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		for i := 0; i < budget; i++ {
			if code, reached := run(m, "/account/activate", "203.0.113.7:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached := run(m, "/account/activate", "203.0.113.7:5000"); code != http.StatusTooManyRequests || reached {
			t.Errorf("request %d: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("a second client IP has an independent bucket", func(t *testing.T) {
		m := NewRateLimiterMiddleware(nil, true)
		for i := 0; i < budget+1; i++ {
			run(m, "/account/activate", "203.0.113.7:5000")
		}
		// Same middleware instance, different host: a global key would block this, which is
		// exactly what an empty key would produce.
		if code, reached := run(m, "/account/activate", "198.51.100.9:5000"); code != http.StatusTeapot || !reached {
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
			target := fmt.Sprintf("/account/activate?email=user%d@example.com", i)
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
			if code, reached := run(m, "/account/activate", "203.0.113.1:5000"); code != http.StatusTeapot || !reached {
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
