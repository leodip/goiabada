package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-chi/httprate"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
)

// testTemplateFS is the smallest tree RenderTemplate needs: a layout that includes the
// three blocks the real one includes, and the error page the browser rejection renders.
//
// The real templates live in the authserver module, which depends on core, so core's tests
// cannot reach them. What stands in here is only their shape. What is genuinely under test
// is the middleware's half (the layout and template it names, the bind keys it fills) plus
// the half RenderTemplate itself owns and a stub renderer would fake: the Content-Type it
// sets and the status it takes from _httpStatus.
var testTemplateFS = fstest.MapFS{
	"layouts/no_menu_layout.html": &fstest.MapFile{Data: []byte(
		`<!DOCTYPE html><html><head><title>{{template "title" .}}</title>{{template "head" .}}</head>` +
			`<body>{{template "body" .}}</body></html>`)},
	"auth_error.html": &fstest.MapFile{Data: []byte(
		`{{define "title"}}{{.appName}}{{end}}{{define "head"}}{{end}}` +
			`{{define "body"}}<h1>{{.title}}</h1><p id="errorMsg">{{.error}}</p>{{end}}`)},
}

// auditEvent is one call the middleware made to its audit logger.
type auditEvent struct {
	name    string
	details map[string]interface{}
}

// stubAuditLogger records what the limiter audited. Hand-written rather than generated,
// which is the convention stubAuthHelper already sets in this file for a one-method
// interface. The mutex is not decoration: the reservation cases in later stages drive the
// middleware from several goroutines at once.
type stubAuditLogger struct {
	mu     sync.Mutex
	events []auditEvent
}

func (s *stubAuditLogger) Log(name string, details map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, auditEvent{name: name, details: details})
}

func (s *stubAuditLogger) count(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.events {
		if e.name == name {
			n++
		}
	}
	return n
}

// newTestMiddleware builds the middleware with a real HttpHelper over testTemplateFS and a
// throwaway audit logger, for the cases that do not look at what was audited.
func newTestMiddleware(authHelper AuthHelper, enabled bool) *RateLimiterMiddleware {
	m, _ := newAuditedTestMiddleware(authHelper, enabled)
	return m
}

func newAuditedTestMiddleware(authHelper AuthHelper, enabled bool) (*RateLimiterMiddleware, *stubAuditLogger) {
	audit := &stubAuditLogger{}
	return NewRateLimiterMiddleware(authHelper, handlerhelpers.NewHttpHelper(testTemplateFS), audit, enabled), audit
}

// limiterRequest builds the request a limited route actually receives. Settings are on the
// context because MiddlewareSettings is a global router.Use registered ahead of every
// per-route limiter, and the browser rejection renders a template, which reads settings off
// the context. A request built without them panics on the first 429, so this is the shape
// the reject path has to work in rather than test scaffolding.
func limiterRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	return req.WithContext(context.WithValue(req.Context(),
		constants.ContextKeySettings, &models.Settings{AppName: "Goiabada"}))
}

// rateLimitHeaderNames are the four headers decision 13 blanks. They told any caller the
// exact budget, how much was left and whether the limiter was on at all, without tripping
// anything (#219).
var rateLimitHeaderNames = []string{
	"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Increment", "X-RateLimit-Reset",
}

func assertNoRateLimitHeaders(t *testing.T, rr *httptest.ResponseRecorder, when string) {
	t.Helper()
	for _, h := range rateLimitHeaderNames {
		if got := rr.Header().Get(h); got != "" {
			t.Errorf("%s: header %s = %q, want it absent", when, h, got)
		}
	}
}

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

// runPwd drives one request through LimitPwd and reports the status, whether the handler
// ran, and the response.
//
// failed is what the handler found when it checked the credential, and it is the whole
// point of the helper: a failures-only tier is spent by calling RecordCredentialFailure
// from inside the handler, exactly as HandleAuthPwdPost does on a wrong password. A case
// that drives requests without it is measuring the per-IP tier, whatever it says it is
// measuring (#219).
func runPwd(m *RateLimiterMiddleware, email, ip string, failed bool) (int, bool, *httptest.ResponseRecorder) {
	form := url.Values{"email": {email}}
	req := limiterRequest(http.MethodPost, "/auth/pwd", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ip
	rr := httptest.NewRecorder()
	reached := false
	m.LimitPwd(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		if failed {
			m.RecordCredentialFailure(r)
		}
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rr, req)
	return rr.Code, reached, rr
}

// TestLimitPwd_PerIP verifies the password limiter's per-IP budget, which stops one
// host hammering many accounts and is the tier that still counts every request. The
// per-account tiers are in TestLimitPwd_AccountFailureBudget, since only a failure
// spends those (#219).
//
// The budget is asserted exactly, on both sides, because it is published policy in the
// reference documentation. That is the convention TestLimitResetPwd_PerIP established.
//
// The handler stub writes 418 rather than 200 on purpose: a middleware that writes
// nothing produces exactly 200 with an empty body, so 418 is what tells "the handler
// ran" apart from "nothing was written", and from 429.
//
// The request carries the address in a form body rather than a query string, which is
// what the real route sends. A query target cannot express the whitespace spellings at
// all: httptest.NewRequest parses its target as a request line and panics on one.
func TestLimitPwd_PerIP(t *testing.T) {
	const ipBudget = 30

	run := func(m *RateLimiterMiddleware, email, ip string) (int, bool) {
		code, reached, _ := runPwd(m, email, ip, false)
		return code, reached
	}

	t.Run("the per-IP budget is exactly 30, from varied emails", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
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
		m := newTestMiddleware(nil, true)
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
		m := newTestMiddleware(nil, true)
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
		m := newTestMiddleware(nil, false)
		for i := 0; i < 60; i++ {
			if code, reached := run(m, "x@example.com", "203.0.113.1:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: disabled limiter should never block, got code %d, handler reached %v",
					i+1, code, reached)
			}
		}
	})
}

// TestLimitPwd_AccountFailureBudget verifies the two-tier account gate: a tight budget of
// 10 failures per 15 minutes per (account, client block) and an account-wide backstop of
// 100 per hour, both spent only by a credential check that failed (#219).
//
// Three separate properties live here and each has a case that fails on its own:
//
//   - Only failures count. Every tier before this one charged in middleware, before the
//     handler knew whether the password was right, so a user signing in spent the same
//     allowance an attacker did. That is what made a budget this tight unsafe.
//   - The tight tier carries the network. Without it, ten failures from anyone who knows
//     an address refuse the owner, which made denial cheaper than the 15 requests a minute
//     it replaced rather than dearer.
//   - The backstop exists. Without it an attacker with a /48 owns 65,536 buckets and the
//     account-wide ceiling RFC 6749 Section 4.3.2 makes a MUST is gone.
//
// Every case stays under the per-IP tier's 30 per minute, which is checked first: a case
// that crosses it would be measuring pwd_ip while claiming to measure the account gate.
func TestLimitPwd_AccountFailureBudget(t *testing.T) {
	const tightBudget = 10
	const backstop = 100

	// One fixed host, so the tight tier is the one under test.
	const attacker = "203.0.113.7:5000"

	t.Run("the tight budget is exactly 10 failures", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < tightBudget; i++ {
			if code, reached, _ := runPwd(m, "victim@example.com", attacker, true); code != http.StatusTeapot || !reached {
				t.Fatalf("failure %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached, _ := runPwd(m, "victim@example.com", attacker, true); code != http.StatusTooManyRequests || reached {
			t.Errorf("failure %d: got code %d, handler reached %v; want %d and false",
				tightBudget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("a successful sign-in spends nothing, and hands its slot back", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		// Interleaved rather than grouped: a slot that leaked instead of being handed
		// back would shrink the budget permanently, and the count below is what sees it.
		for i := 0; i < 5; i++ {
			if code, _, _ := runPwd(m, "owner@example.com", attacker, false); code != http.StatusTeapot {
				t.Fatalf("success %d: got code %d, want %d", i+1, code, http.StatusTeapot)
			}
		}
		for i := 0; i < tightBudget; i++ {
			failed := i%2 == 0
			code, _, _ := runPwd(m, "owner@example.com", attacker, failed)
			if code != http.StatusTeapot {
				t.Fatalf("request %d (failed=%v): got code %d, want %d", i+1, failed, code, http.StatusTeapot)
			}
		}
		// 5 failures spent so far out of 10, so 5 more must still be admitted.
		for i := 0; i < 5; i++ {
			if code, _, _ := runPwd(m, "owner@example.com", attacker, true); code != http.StatusTeapot {
				t.Fatalf("failure %d after the interleaved run: got code %d, want %d",
					i+1, code, http.StatusTeapot)
			}
		}
		if code, reached, _ := runPwd(m, "owner@example.com", attacker, true); code != http.StatusTooManyRequests || reached {
			t.Errorf("the 11th failure: got code %d, handler reached %v; want %d and false",
				code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("ten case and whitespace variants of one address share the bucket", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		spellings := spellingsOf("victim", "example.com")
		// Refused by accountRateLimitKey lowercasing and trimming, not by the limiter
		// merely working: without it each spelling is its own bucket and all 11 pass.
		for i := 0; i < tightBudget; i++ {
			if code, reached, _ := runPwd(m, spellings[i%len(spellings)], attacker, true); code != http.StatusTeapot || !reached {
				t.Fatalf("spelling %q (failure %d): got code %d, handler reached %v; want %d and true",
					spellings[i%len(spellings)], i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached, _ := runPwd(m, spellings[tightBudget%len(spellings)], attacker, true); code != http.StatusTooManyRequests || reached {
			t.Errorf("failure %d: got code %d, handler reached %v; want %d and false",
				tightBudget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("a second address still has its own bucket", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < tightBudget+1; i++ {
			runPwd(m, "victim@example.com", attacker, true)
		}
		// A genuinely different account: a key that stopped distinguishing accounts at
		// all would block this, so the case above cannot pass by over-normalizing.
		if code, reached, _ := runPwd(m, "other@example.com", attacker, true); code != http.StatusTeapot || !reached {
			t.Errorf("second address: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTooManyRequests)
		}
	})

	// The case the two-tier shape exists for. Under a single account-wide tier this
	// request is refused, which is a third party denying an account its login.
	t.Run("an attacker exhausting one network leaves the owner's network allowed", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < tightBudget; i++ {
			if code, _, _ := runPwd(m, "victim@example.com", attacker, true); code != http.StatusTeapot {
				t.Fatalf("attacker failure %d: got code %d, want %d", i+1, code, http.StatusTeapot)
			}
		}
		if code, _, _ := runPwd(m, "victim@example.com", attacker, true); code != http.StatusTooManyRequests {
			t.Fatalf("the attacker's 11th failure was not refused: got code %d", code)
		}
		// The owner, in a different block, with the correct password.
		if code, reached, _ := runPwd(m, "victim@example.com", "198.51.100.9:5000", false); code != http.StatusTeapot || !reached {
			t.Errorf("the owner from another network: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	// And the other side of it: spreading across networks does not buy an unlimited
	// number of guesses, because the account-wide backstop counts them all.
	t.Run("failures spread across networks still reach the account-wide backstop", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		admitted := 0
		for net := 0; net < backstop/tightBudget; net++ {
			ip := fmt.Sprintf("[2001:db8:%x::1]:5000", net)
			for i := 0; i < tightBudget; i++ {
				if code, _, _ := runPwd(m, "victim@example.com", ip, true); code == http.StatusTeapot {
					admitted++
				}
			}
		}
		if admitted != backstop {
			t.Fatalf("%d failures admitted across %d networks, want exactly %d",
				admitted, backstop/tightBudget, backstop)
		}
		// A fresh network, whose own tight bucket is untouched: only the backstop can
		// refuse this, so removing the backstop makes the case fail here.
		if code, reached, _ := runPwd(m, "victim@example.com", "[2001:db8:ff::1]:5000", true); code != http.StatusTooManyRequests || reached {
			t.Errorf("failure %d, from a fresh network: got code %d, handler reached %v; want %d and false",
				backstop+1, code, reached, http.StatusTooManyRequests)
		}
	})

	// Decision 18's reservation, and the only case that can see it: sequential callers
	// hold the budget under either design, because the defect lives in the window between
	// reading the recorded rate and charging it.
	t.Run("concurrent failures admit exactly the budget", func(t *testing.T) {
		const callers = 25 // under the per-IP tier's 30, so only the account gate refuses
		m := newTestMiddleware(nil, true)

		release := make(chan struct{})
		var entered, refused atomic.Int64
		var start, done sync.WaitGroup
		start.Add(1)
		for i := 0; i < callers; i++ {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()

				form := url.Values{"email": {"victim@example.com"}}
				req := limiterRequest(http.MethodPost, "/auth/pwd", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.RemoteAddr = attacker
				rr := httptest.NewRecorder()
				m.LimitPwd(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					entered.Add(1)
					m.RecordCredentialFailure(r)
					// Stands in for the bcrypt the handler is about to run, which is
					// what makes the window wide enough to matter in production.
					<-release
					w.WriteHeader(http.StatusTeapot)
				})).ServeHTTP(rr, req)
				if rr.Code == http.StatusTooManyRequests {
					refused.Add(1)
				}
			}()
		}
		start.Done()

		// Hold every admitted caller inside the handler until all 25 have been through
		// the gate, so no reservation is released before the last one is decided.
		deadline := time.Now().Add(10 * time.Second)
		for entered.Load()+refused.Load() < callers {
			if time.Now().After(deadline) {
				close(release)
				t.Fatalf("only %d of %d callers reached a verdict", entered.Load()+refused.Load(), callers)
			}
			time.Sleep(time.Millisecond)
		}
		close(release)
		done.Wait()

		if entered.Load() != tightBudget {
			t.Errorf("%d of %d concurrent callers were admitted, want exactly %d; a gate that "+
				"reads the recorded rate without counting what is in flight admits all of them",
				entered.Load(), callers, tightBudget)
		}
	})

	t.Run("the refusal is the browser shape, with Retry-After and no rate-limit headers", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		var rr *httptest.ResponseRecorder
		for i := 0; i < tightBudget+1; i++ {
			_, _, rr = runPwd(m, "victim@example.com", attacker, true)
		}
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("got code %d, want %d", rr.Code, http.StatusTooManyRequests)
		}
		// The failures-only path never calls OnLimit on a refusal, so it writes this
		// header itself. httprate would otherwise have written it and nothing here would
		// notice it was gone.
		if got := rr.Header().Get("Retry-After"); got != "900" {
			t.Errorf("Retry-After = %q, want 900, the tier's 15 minute window", got)
		}
		if got := rr.Header().Get("Content-Type"); got != "text/html; charset=UTF-8" {
			t.Errorf("Content-Type = %q, want text/html; charset=UTF-8", got)
		}
		assertNoRateLimitHeaders(t, rr, "failures-only rejection")
	})

	t.Run("disabled limiter never blocks, and a recorded failure is a no-op", func(t *testing.T) {
		m := newTestMiddleware(nil, false)
		for i := 0; i < tightBudget*4; i++ {
			if code, reached, _ := runPwd(m, "victim@example.com", attacker, true); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: disabled limiter should never block, got code %d, handler reached %v",
					i+1, code, reached)
			}
		}
	})
}

// TestFailureTier_FailsClosedOnACounterError is the one case that reaches failureTier
// directly, and the reason for the exception is that nothing else can reach this branch:
// httprate's in-process counter documents that all its methods always return a nil error,
// so no request through the middleware can produce one. An implementation that returned
// true on a counter error would leave every other case in this file green while the gate
// failed open for the duration of a storage fault (#219).
func TestFailureTier_FailsClosedOnACounterError(t *testing.T) {
	f := newFailureTier("test", 5, time.Minute)
	f.rl = httprate.NewRateLimiter(5, time.Minute, httprate.WithLimitCounter(&erroringLimitCounter{}))

	if f.Reserve("anyone@example.com") {
		t.Error("Reserve returned true with the counter erroring; the gate must fail closed")
	}
}

// erroringLimitCounter is a LimitCounter whose reads fail, standing in for a counter
// implementation that can (unlike the in-process one).
type erroringLimitCounter struct{}

func (c *erroringLimitCounter) Config(requestLimit int, windowLength time.Duration) {}

func (c *erroringLimitCounter) Increment(key string, currentWindow time.Time) error { return nil }

func (c *erroringLimitCounter) IncrementBy(key string, currentWindow time.Time, amount int) error {
	return nil
}

func (c *erroringLimitCounter) Get(key string, currentWindow, previousWindow time.Time) (int, int, error) {
	return 0, 0, errors.New("counter unavailable")
}

// TestLimitForgotPwd_PerEmailAndPerIP verifies the forgot-password limiter bounds
// both a single address (mail-bombing) and a single source IP, and that neither
// budget can be escaped by respelling the address or by moving inside one's own
// /64 (#219). Same conventions as TestLimitPwd_PerIP: exact budgets, a
// 418 stub, and a form body rather than a query target.
func TestLimitForgotPwd_PerEmailAndPerIP(t *testing.T) {
	const emailBudget = 5
	const ipBudget = 20

	run := func(m *RateLimiterMiddleware, email, ip string) (int, bool) {
		form := url.Values{"email": {email}}
		req := limiterRequest(http.MethodPost, "/forgot-password", strings.NewReader(form.Encode()))
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
		m := newTestMiddleware(nil, true)
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
		m := newTestMiddleware(nil, true)
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
		m := newTestMiddleware(nil, true)
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
		m := newTestMiddleware(nil, true)
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
		m := newTestMiddleware(nil, true)
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
		m := newTestMiddleware(nil, false)
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
		req := limiterRequest(http.MethodGet, target, nil)
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
		m := newTestMiddleware(nil, true)
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
		m := newTestMiddleware(nil, true)
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
		m := newTestMiddleware(nil, true)
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
		m := newTestMiddleware(nil, false)
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
		req := limiterRequest(http.MethodGet, target, nil)
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
		m := newTestMiddleware(nil, true)
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
		m := newTestMiddleware(nil, true)
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
		m := newTestMiddleware(nil, true)
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
		m := newTestMiddleware(nil, false)
		for i := 0; i < budget*2; i++ {
			if code, reached := run(m, "/account/activate", "203.0.113.1:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: disabled limiter should never block, got code %d, handler reached %v",
					i+1, code, reached)
			}
		}
	})
}

// TestLimitRegister_PerIP verifies self-registration is bounded per client block, at the same
// budget as the activation step that follows it, and that a distinct address per request buys
// nothing (#219).
//
// That last case is the one the limiter exists for. The endpoint answers whether an address
// already has an account, sends mail to whichever do not, and writes a pre_registrations row for
// each, and all three are only harmful across distinct addresses. A limiter keyed on the submitted
// address would bucket the attacker's own choice of victim and bound none of it, which is why
// decision 8 has no per-email tier.
//
// The budget is exact because it is published policy: 20 requests per 5 minutes, matching
// activate so registration and its activation trip at the same rate.
//
// The handler stub writes 418 rather than 200 on purpose: a middleware that writes nothing
// produces exactly 200 with an empty body, so 418 is what tells "the handler ran" apart from
// "nothing was written", and from 429.
func TestLimitRegister_PerIP(t *testing.T) {
	const budget = 20

	run := func(m *RateLimiterMiddleware, email, ip string) (int, bool, *httptest.ResponseRecorder) {
		form := url.Values{"email": {email}, "password": {"whatever"}}
		req := limiterRequest(http.MethodPost, "/account/register", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		reached := false
		m.LimitRegister(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusTeapot)
		})).ServeHTTP(rr, req)
		return rr.Code, reached, rr
	}

	t.Run("the budget is exactly 20 per IP", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < budget; i++ {
			if code, reached, _ := run(m, "newuser@example.com", "203.0.113.7:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached, _ := run(m, "newuser@example.com", "203.0.113.7:5000"); code != http.StatusTooManyRequests || reached {
			t.Errorf("request %d: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("a distinct address per request shares one host's bucket", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		// The enumeration bound itself: 21 addresses probed from one host, and the 21st is
		// refused. A per-address key would allow all of them.
		for i := 0; i < budget; i++ {
			email := fmt.Sprintf("candidate%d@example.com", i)
			if code, reached, _ := run(m, email, "203.0.113.7:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d for %s: got code %d, handler reached %v; want %d and true",
					i+1, email, code, reached, http.StatusTeapot)
			}
		}
		if code, _, _ := run(m, "candidate20@example.com", "203.0.113.7:5000"); code != http.StatusTooManyRequests {
			t.Errorf("request %d with a fresh address: got code %d, want %d",
				budget+1, code, http.StatusTooManyRequests)
		}
	})

	t.Run("addresses inside one /64 share the bucket, a second /64 does not", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		addr := func(i int) string { return fmt.Sprintf("[2001:db8:1:2::%x]:5000", i+1) }
		for i := 0; i < budget; i++ {
			if code, _, _ := run(m, "newuser@example.com", addr(i)); code != http.StatusTeapot {
				t.Fatalf("request %d from %s: got code %d, want %d", i+1, addr(i), code, http.StatusTeapot)
			}
		}
		if code, _, _ := run(m, "newuser@example.com", addr(budget)); code != http.StatusTooManyRequests {
			t.Errorf("request %d from %s: got code %d, want %d",
				budget+1, addr(budget), code, http.StatusTooManyRequests)
		}
		// A neighbouring /64 is a different client, which is what makes the mask observable
		// rather than the limiter.
		if code, reached, _ := run(m, "newuser@example.com", "[2001:db8:1:3::1]:5000"); code != http.StatusTeapot || !reached {
			t.Errorf("second /64: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("the refusal is the browser shape, with Retry-After and no rate-limit headers", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		var rr *httptest.ResponseRecorder
		for i := 0; i < budget+1; i++ {
			_, _, rr = run(m, "newuser@example.com", "203.0.113.7:5000")
		}
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("got code %d, want %d", rr.Code, http.StatusTooManyRequests)
		}
		if got := rr.Header().Get("Retry-After"); got != "300" {
			t.Errorf("Retry-After = %q, want 300, the tier's 5 minute window", got)
		}
		// A registration form is a browser route, so the refusal is the error page rather
		// than httprate's plain text.
		if got := rr.Header().Get("Content-Type"); got != "text/html; charset=UTF-8" {
			t.Errorf("Content-Type = %q, want text/html; charset=UTF-8", got)
		}
		assertNoRateLimitHeaders(t, rr, "registration rejection")
	})

	t.Run("disabled limiter never blocks", func(t *testing.T) {
		m := newTestMiddleware(nil, false)
		for i := 0; i < budget*2; i++ {
			if code, reached, _ := run(m, "newuser@example.com", "203.0.113.1:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: disabled limiter should never block, got code %d, handler reached %v",
					i+1, code, reached)
			}
		}
	})
}

// TestLimitOtp_PerUserAndMissingAuthContext verifies the OTP limiter keys its
// budget on the user id, that only a wrong code spends it, and that a request whose auth
// context cannot be read reaches the handler instead of being answered with a blank 200
// (#114).
//
// Five failures per 15 minutes rather than the 10 requests a minute it replaces: with the
// verifier accepting three of a million codes at any instant, the old budget was 14,400
// guesses a day and a 72.6% chance of a hit within a month against an account whose
// password the attacker already holds. Five is what enrollment needs rather than what
// login needs, since the same limiter covers the form a user with no authenticator yet
// sees (#219).
//
// The handler stub writes 418 rather than 200 on purpose: a middleware that
// writes nothing produces exactly 200 with an empty body, so 418 is what tells
// "the handler ran" apart from "nothing was written", and from 429.
func TestLimitOtp_PerUserAndMissingAuthContext(t *testing.T) {
	const budget = 5

	run := func(m *RateLimiterMiddleware, userId int, failed bool) (int, bool) {
		req := limiterRequest(http.MethodPost, fmt.Sprintf("/auth/otp?userId=%d", userId), nil)
		rr := httptest.NewRecorder()
		reached := false
		m.LimitOtp(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			if failed {
				m.RecordCredentialFailure(r)
			}
			w.WriteHeader(http.StatusTeapot)
		})).ServeHTTP(rr, req)
		return rr.Code, reached
	}

	t.Run("unreadable auth context reaches the handler", func(t *testing.T) {
		m := newTestMiddleware(stubAuthHelper{err: customerrors.ErrNoAuthContext}, true)
		// Well past the budget: the pass-through is deliberately not
		// bounded by this middleware, since there is no user to key a bucket on.
		for i := 0; i < 20; i++ {
			code, reached := run(m, 0, true)
			if code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
	})

	t.Run("the budget is exactly 5 failures", func(t *testing.T) {
		m := newTestMiddleware(stubAuthHelper{}, true)
		for i := 0; i < budget; i++ {
			if code, reached := run(m, 42, true); code != http.StatusTeapot || !reached {
				t.Fatalf("failure %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached := run(m, 42, true); code != http.StatusTooManyRequests || reached {
			t.Errorf("failure %d: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("a correct code spends nothing", func(t *testing.T) {
		m := newTestMiddleware(stubAuthHelper{}, true)
		// Well past the budget, all of them verified. A tier that still counted every
		// request would refuse the sixth, which is what a user re-authenticating through
		// a working authenticator would meet.
		for i := 0; i < budget*4; i++ {
			if code, reached := run(m, 42, false); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		// And the full budget is still there afterwards.
		for i := 0; i < budget; i++ {
			if code, _ := run(m, 42, true); code != http.StatusTeapot {
				t.Fatalf("failure %d after the successful run: got code %d, want %d",
					i+1, code, http.StatusTeapot)
			}
		}
		if code, _ := run(m, 42, true); code != http.StatusTooManyRequests {
			t.Errorf("failure %d: got code %d, want %d", budget+1, code, http.StatusTooManyRequests)
		}
	})

	t.Run("each user id has its own budget", func(t *testing.T) {
		m := newTestMiddleware(stubAuthHelper{}, true)
		blocked := false
		for i := 0; i < budget+1; i++ {
			if code, _ := run(m, 42, true); code == http.StatusTooManyRequests {
				blocked = true
				break
			}
		}
		if !blocked {
			t.Fatalf("expected user 42 to be limited within %d failures", budget+1)
		}
		// Same middleware instance, different user: a global key would block this.
		if code, reached := run(m, 43, true); code != http.StatusTeapot || !reached {
			t.Errorf("second user: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("disabled limiter never blocks", func(t *testing.T) {
		m := newTestMiddleware(stubAuthHelper{}, false)
		for i := 0; i < 60; i++ {
			if code, reached := run(m, 42, true); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d: disabled limiter should never block, got code %d, handler reached %v",
					i+1, code, reached)
			}
		}
	})
}

// verificationRequest builds the request LimitEmailVerification actually receives. The
// account API's authentication middleware runs ahead of every per-route limiter and leaves
// the validated token on the context as a value rather than a pointer, so this is the shape
// the key helper has to read. A blank subject omits the token entirely, standing for a
// request no bucket can be derived from.
func verificationRequest(subject string) *http.Request {
	req := limiterRequest(http.MethodPost, "/api/v1/account/email/verification", nil)
	if subject == "" {
		return req
	}
	return req.WithContext(context.WithValue(req.Context(), constants.ContextKeyValidatedToken,
		oauth.JwtToken{Claims: map[string]interface{}{"sub": subject}}))
}

// runVerification drives one request through LimitEmailVerification and reports the status,
// whether the handler ran, and the response. failed is what the handler found when it
// compared the code, which is the only thing that spends this budget.
func runVerification(m *RateLimiterMiddleware, subject string, failed bool) (int, bool, *httptest.ResponseRecorder) {
	rr := httptest.NewRecorder()
	reached := false
	m.LimitEmailVerification(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		if failed {
			m.RecordCredentialFailure(r)
		}
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rr, verificationRequest(subject))
	return rr.Code, reached, rr
}

// TestLimitEmailVerification_PerSubject is seam 1 for the email verification check, which
// had no limiter and no failure counter at all while comparing a code an attacker can have
// sent to an address they chose (#219).
//
// The budget is asserted exactly, on both sides, because it is published policy in the
// reference documentation.
func TestLimitEmailVerification_PerSubject(t *testing.T) {
	const budget = 5
	const subject = "11111111-1111-1111-1111-111111111111"

	t.Run("the budget is exactly 5 failures", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < budget; i++ {
			if code, reached, _ := runVerification(m, subject, true); code != http.StatusTeapot || !reached {
				t.Fatalf("failure %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached, _ := runVerification(m, subject, true); code != http.StatusTooManyRequests || reached {
			t.Errorf("failure %d: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("a correct code spends nothing, and hands its slot back", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		// Well past the budget, every one of them verified. A tier that counted every
		// request would refuse the sixth, which is a user locked out of verifying their
		// own address by having verified it.
		for i := 0; i < budget*4; i++ {
			if code, reached, _ := runVerification(m, subject, false); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		// And the full budget is still there, which a leaked reservation would have shrunk.
		for i := 0; i < budget; i++ {
			if code, _, _ := runVerification(m, subject, true); code != http.StatusTeapot {
				t.Fatalf("failure %d after the successful run: got code %d, want %d",
					i+1, code, http.StatusTeapot)
			}
		}
		if code, _, _ := runVerification(m, subject, true); code != http.StatusTooManyRequests {
			t.Errorf("failure %d: got code %d, want %d", budget+1, code, http.StatusTooManyRequests)
		}
	})

	t.Run("each subject has its own budget", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < budget+1; i++ {
			runVerification(m, subject, true)
		}
		if code, _, _ := runVerification(m, subject, true); code != http.StatusTooManyRequests {
			t.Fatalf("the exhausted subject got code %d, want %d", code, http.StatusTooManyRequests)
		}
		// Same middleware instance, a different account: a global key would refuse this.
		if code, reached, _ := runVerification(m, "22222222-2222-2222-2222-222222222222", true); code != http.StatusTeapot || !reached {
			t.Errorf("second subject: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("a request carrying no token reaches the handler", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		// Well past the budget: with no subject there is no bucket, and the handler
		// answers ACCESS_TOKEN_REQUIRED before it compares anything, so the skipped limit
		// costs nothing. Returning here instead would write no response at all.
		for i := 0; i < budget*4; i++ {
			if code, reached, _ := runVerification(m, "", true); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
	})

	t.Run("a token whose subject is blank reaches the handler", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < budget*4; i++ {
			if code, reached, _ := runVerification(m, "   ", true); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
	})

	t.Run("disabled limiter never blocks", func(t *testing.T) {
		m := newTestMiddleware(nil, false)
		for i := 0; i < budget*6; i++ {
			if code, reached, _ := runVerification(m, subject, true); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d: disabled limiter should never block, got code %d, handler reached %v",
					i+1, code, reached)
			}
		}
	})
}

// -----------------------------------------------------------------------------
// Seam 1, stage 2: what a rejection looks like, and that it leaves a trace.
//
// Every case below drives a real limiter past its budget and reads the response
// the caller would actually receive. Nothing asserts on a spy, because the defect
// these exist to prevent is a rejection wired up everywhere except where it is
// written: httprate's own default answers "Too Many Requests\n" as text/plain on
// every route regardless of how much configuration surrounds it (#219).
// -----------------------------------------------------------------------------

// tripBrowser drives failed password checks at LimitPwd from one host until it is refused
// and returns the refusal. The tight account tier of 10 failures is what trips, since it is
// reached before the per-IP 30.
//
// Every request has to record a failure: since stage 3 the account tiers count nothing
// else, so a loop of plain requests would drive the per-IP tier instead and the cases below
// would silently be about a different limiter.
func tripBrowser(t *testing.T, m *RateLimiterMiddleware) *httptest.ResponseRecorder {
	t.Helper()
	var last *httptest.ResponseRecorder
	for i := 0; i < 12; i++ {
		_, _, rr := runPwd(m, "victim@example.com", "203.0.113.7:5000", true)
		last = rr
		if last.Code == http.StatusTooManyRequests {
			return last
		}
	}
	t.Fatalf("LimitPwd never refused within 12 failures; last code %d", last.Code)
	return nil
}

// tripOAuth drives LimitDCR from one host until it is refused, at a budget of 10.
func tripOAuth(t *testing.T, m *RateLimiterMiddleware) *httptest.ResponseRecorder {
	t.Helper()
	var last *httptest.ResponseRecorder
	for i := 0; i < 12; i++ {
		req := limiterRequest(http.MethodPost, "/connect/register", nil)
		req.RemoteAddr = "203.0.113.8:5000"
		last = httptest.NewRecorder()
		m.LimitDCR(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		})).ServeHTTP(last, req)
		if last.Code == http.StatusTooManyRequests {
			return last
		}
	}
	t.Fatalf("LimitDCR never refused within 12 requests; last code %d", last.Code)
	return nil
}

// TestRejection_BrowserClass verifies a browser route's 429 is the error page that
// route's other refusals render, not plain text (decision 11), and that it carries
// Retry-After and none of the four X-RateLimit-* headers (decision 13).
func TestRejection_BrowserClass(t *testing.T) {
	m := newTestMiddleware(nil, true)
	rr := tripBrowser(t, m)

	if got := rr.Header().Get("Content-Type"); got != "text/html; charset=UTF-8" {
		t.Errorf("Content-Type = %q, want %q; a plain-text body is what httprate's default writes",
			got, "text/html; charset=UTF-8")
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	// RFC 6585 section 4 names Retry-After as what a 429 MAY carry, and it is the one
	// header decision 13 keeps. It is the tier's window length, 15 minutes here.
	if got := rr.Header().Get("Retry-After"); got != "900" {
		t.Errorf("Retry-After = %q, want 900", got)
	}
	assertNoRateLimitHeaders(t, rr, "browser rejection")

	// The catalog message, not the key: TestMain loads the bundle, so a raw key in the
	// body would mean the string is missing from active.en.toml.
	want := i18n.T(context.Background(), "auth_error.rate_limited.message")
	if strings.HasPrefix(want, "auth_error.") {
		t.Fatalf("auth_error.rate_limited.message is missing from the English catalog")
	}
	if !strings.Contains(rr.Body.String(), want) {
		t.Errorf("body does not carry the rate-limited message.\nbody: %s", rr.Body.String())
	}
	if title := i18n.T(context.Background(), "auth_error.rate_limited.title"); !strings.Contains(rr.Body.String(), title) {
		t.Errorf("body does not carry the rate-limited title %q", title)
	}
}

// TestRejection_OAuthClass verifies the token and registration endpoints answer with
// the JSON error object their callers already parse, under the media type both RFCs
// require: RFC 6749 section 5.2 puts the token error parameters in "the
// "application/json" media type", and RFC 7591 section 3.2.2 requires "content type
// application/json". Go writes no header for a hand-encoded body, so a JSON body
// labelled text/plain is the failure this case exists to catch.
func TestRejection_OAuthClass(t *testing.T) {
	m := newTestMiddleware(nil, true)
	rr := tripOAuth(t, m)

	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rr.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}
	if got := rr.Header().Get("Retry-After"); got != "60" {
		t.Errorf("Retry-After = %q, want 60", got)
	}
	assertNoRateLimitHeaders(t, rr, "oauth rejection")

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v\nbody: %s", err, rr.Body.String())
	}
	// RFC 6749 section 5.2 makes error REQUIRED and closes the list it comes from, so
	// the exact string matters: slow_down would tell a conformant client to keep polling.
	if body["error"] != "invalid_request" {
		t.Errorf(`error = %q, want "invalid_request"`, body["error"])
	}
	if body["error_description"] == "" {
		t.Error("error_description is empty")
	}
}

// tripAPI drives failed verification checks at LimitEmailVerification until it is refused,
// at a budget of 5 failures. Every request has to record a failure: the tier counts nothing
// else, so a loop of plain requests would never refuse and the case would hang on its own
// success.
func tripAPI(t *testing.T, m *RateLimiterMiddleware) *httptest.ResponseRecorder {
	t.Helper()
	var last *httptest.ResponseRecorder
	for i := 0; i < 8; i++ {
		_, _, rr := runVerification(m, "11111111-1111-1111-1111-111111111111", true)
		last = rr
		if last.Code == http.StatusTooManyRequests {
			return last
		}
	}
	t.Fatalf("LimitEmailVerification never refused within 8 failures; last code %d", last.Code)
	return nil
}

// TestRejection_APIClass verifies the account and admin API routes answer with the flat
// error envelope every other refusal on those routes writes, so a caller already switching
// on error_code needs no new shape (decision 11), and that the 429 carries Retry-After and
// none of the four X-RateLimit-* headers (decision 13).
func TestRejection_APIClass(t *testing.T) {
	m := newTestMiddleware(nil, true)
	rr := tripAPI(t, m)

	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json; a plain-text body is what httprate's default writes", got)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	// The tier's window, 15 minutes.
	if got := rr.Header().Get("Retry-After"); got != "900" {
		t.Errorf("Retry-After = %q, want 900", got)
	}
	assertNoRateLimitHeaders(t, rr, "api rejection")

	var body struct {
		ErrorCode        string `json:"error_code"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v\nbody: %s", err, rr.Body.String())
	}
	if body.ErrorCode != "TOO_MANY_REQUESTS" {
		t.Errorf(`error_code = %q, want "TOO_MANY_REQUESTS"`, body.ErrorCode)
	}
	if body.ErrorDescription == "" {
		t.Error("error_description is empty")
	}
}

// TestRejection_HeadersAbsentOnAllowedRequests is the other half of decision 13. The
// headers rode every response including successful ones, so a caller could read the
// budget and the remaining count without ever tripping anything.
func TestRejection_HeadersAbsentOnAllowedRequests(t *testing.T) {
	m := newTestMiddleware(nil, true)

	form := url.Values{"email": {"someone@example.com"}}
	req := limiterRequest(http.MethodPost, "/auth/pwd", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.30:5000"
	rr := httptest.NewRecorder()
	m.LimitPwd(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusTeapot {
		t.Fatalf("first request got code %d, want %d", rr.Code, http.StatusTeapot)
	}
	assertNoRateLimitHeaders(t, rr, "allowed request")
	if got := rr.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After = %q on an allowed request, want it absent", got)
	}
}

// TestRejection_AuditedOncePerKeyPerWindow verifies the gate that makes decision 12
// safe. An event per 429 would turn the limiter into the unbounded audit-write
// amplifier it exists to stop, since every write is a settings read plus an insert on
// an unauthenticated path (#212).
func TestRejection_AuditedOncePerKeyPerWindow(t *testing.T) {
	// One fixed host throughout, and never more than 30 requests to it, so the tight
	// account tier is the only one that can trip and the counts below belong to one
	// limiter rather than two.
	const host = "203.0.113.7:5000"

	t.Run("many rejections on one key produce one event", func(t *testing.T) {
		m, audit := newAuditedTestMiddleware(nil, true)
		refused := 0
		for i := 0; i < 25; i++ {
			if code, _, _ := runPwd(m, "victim@example.com", host, true); code == http.StatusTooManyRequests {
				refused++
			}
		}
		if refused < 10 {
			t.Fatalf("only %d of 25 requests were refused; the case needs a burst of rejections", refused)
		}
		if got := audit.count(constants.AuditRateLimitExceeded); got != 1 {
			t.Errorf("got %d rate_limit_exceeded events for %d rejections on one key, want exactly 1",
				got, refused)
		}
	})

	t.Run("the event carries the limiter and the account", func(t *testing.T) {
		m, audit := newAuditedTestMiddleware(nil, true)
		for i := 0; i < 11; i++ {
			runPwd(m, "Victim@Example.com", host, true)
		}
		audit.mu.Lock()
		defer audit.mu.Unlock()
		if len(audit.events) != 1 {
			t.Fatalf("got %d events, want 1", len(audit.events))
		}
		e := audit.events[0]
		if e.name != constants.AuditRateLimitExceeded {
			t.Errorf("event name = %q, want %q", e.name, constants.AuditRateLimitExceeded)
		}
		if e.details["limiter"] != "pwd_account_net" {
			t.Errorf("details[limiter] = %v, want pwd_account_net", e.details["limiter"])
		}
		// The normalized address, which is the identifier AuditAuthFailedPwd already
		// records under the same name, and the one the log line no longer carries.
		if e.details["email"] != "victim@example.com" {
			t.Errorf("details[email] = %v, want victim@example.com", e.details["email"])
		}
		// And the block it was refused for, which is half of this tier's key: an
		// administrator reading the event needs to know which network spent the budget.
		if e.details["ip"] != "203.0.113.7" {
			t.Errorf("details[ip] = %v, want 203.0.113.7", e.details["ip"])
		}
	})

	t.Run("two keys produce two events", func(t *testing.T) {
		m, audit := newAuditedTestMiddleware(nil, true)
		for i := 0; i < 11; i++ {
			runPwd(m, "one@example.com", host, true)
		}
		for i := 0; i < 11; i++ {
			runPwd(m, "two@example.com", host, true)
		}
		// A gate keyed globally rather than per key would report the first account and
		// go silent for the second, which is the failure that makes the bound useless.
		if got := audit.count(constants.AuditRateLimitExceeded); got != 2 {
			t.Errorf("got %d events for two rejected accounts, want 2", got)
		}
	})

	t.Run("no event when nothing is refused", func(t *testing.T) {
		m, audit := newAuditedTestMiddleware(nil, true)
		for i := 0; i < 10; i++ {
			runPwd(m, fmt.Sprintf("user%d@example.com", i), host, true)
		}
		if got := audit.count(constants.AuditRateLimitExceeded); got != 0 {
			t.Errorf("got %d events with nothing refused, want 0", got)
		}
	})
}

// TestRejection_WarnsWithoutNamingTheUser pins decision 14. Nothing else observes the
// log line, so deleting it or restoring the address it used to interpolate would leave
// the stage green.
//
// The repository already settled the policy this asserts: MiddlewareRequestLogger in
// this same package logs by allowlist "because a denylist fails open", and email is
// deliberately not on that list. The address is carried by the audit event instead.
func TestRejection_WarnsWithoutNamingTheUser(t *testing.T) {
	t.Run("an account tier names the limiter and nothing else", func(t *testing.T) {
		buf := captureSlog(t)
		m := newTestMiddleware(nil, true)
		tripBrowser(t, m)

		out := buf.String()
		if strings.Contains(out, "victim@example.com") {
			t.Errorf("the warning line carries the address:\n%s", out)
		}
		if !strings.Contains(out, `level=WARN`) {
			t.Errorf("the trip was not logged at WARN; an auth server whose error log fills "+
				"with expected events has no error log left:\n%s", out)
		}
		if !strings.Contains(out, `limiter=pwd_account_net`) {
			t.Errorf("the warning line does not name the limiter that tripped:\n%s", out)
		}
	})

	t.Run("an IP tier keeps its bucket, which names no user", func(t *testing.T) {
		buf := captureSlog(t)
		m := newTestMiddleware(nil, true)
		tripOAuth(t, m)

		out := buf.String()
		if !strings.Contains(out, "limiter=dcr") || !strings.Contains(out, "ip=203.0.113.8") {
			t.Errorf("the warning line should carry the limiter and the client block:\n%s", out)
		}
	})
}

// TestLimitDCR_PerIP is LimitDCR's first test, which is half of #195's remainder. RFC
// 7591 section 3 permits rate limiting an unauthenticated registration request "to
// prevent a denial-of-service attack on the client registration endpoint"; the budget
// is exact because it is published policy.
func TestLimitDCR_PerIP(t *testing.T) {
	const budget = 10

	run := func(m *RateLimiterMiddleware, ip string) (int, bool) {
		req := limiterRequest(http.MethodPost, "/connect/register", nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		reached := false
		m.LimitDCR(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusTeapot)
		})).ServeHTTP(rr, req)
		return rr.Code, reached
	}

	t.Run("the budget is exactly 10 per IP", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < budget; i++ {
			if code, reached := run(m, "203.0.113.7:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached := run(m, "203.0.113.7:5000"); code != http.StatusTooManyRequests || reached {
			t.Errorf("request %d: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("addresses inside one /64 share the bucket, a second /64 does not", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		addr := func(i int) string { return fmt.Sprintf("[2001:db8:1:2::%x]:5000", i+1) }
		for i := 0; i < budget; i++ {
			if code, _ := run(m, addr(i)); code != http.StatusTeapot {
				t.Fatalf("request %d from %s: got code %d, want %d", i+1, addr(i), code, http.StatusTeapot)
			}
		}
		if code, _ := run(m, addr(budget)); code != http.StatusTooManyRequests {
			t.Errorf("request %d from %s: got code %d, want %d",
				budget+1, addr(budget), code, http.StatusTooManyRequests)
		}
		// A neighbouring /64 is a different client, which is what makes the mask
		// observable rather than the limiter.
		if code, reached := run(m, "[2001:db8:1:3::1]:5000"); code != http.StatusTeapot || !reached {
			t.Errorf("second /64: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("disabled limiter never blocks", func(t *testing.T) {
		m := newTestMiddleware(nil, false)
		for i := 0; i < budget*2; i++ {
			if code, reached := run(m, "203.0.113.1:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: disabled limiter should never block, got code %d, handler reached %v",
					i+1, code, reached)
			}
		}
	})
}

// runROPC drives one request through LimitROPC and reports the status, whether the handler
// ran, and the response.
//
// failed is what the token handler found when it checked the credential: HandleTokenPost
// calls RecordCredentialFailure only where ValidateTokenRequest answered invalid_grant for a
// password grant. A case that drives requests without it is measuring ropc_ip, whatever it
// says it is measuring (#219).
func runROPC(m *RateLimiterMiddleware, grantType, username, clientId, ip string,
	failed bool) (int, bool, *httptest.ResponseRecorder) {

	form := url.Values{
		"grant_type": {grantType},
		"username":   {username},
		"client_id":  {clientId},
	}
	req := limiterRequest(http.MethodPost, "/auth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ip
	rr := httptest.NewRecorder()
	reached := false
	m.LimitROPC(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		if failed {
			m.RecordCredentialFailure(r)
		}
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rr, req)
	return rr.Code, reached, rr
}

// TestLimitROPC_PerIP verifies the password grant's per-IP tier, which stops one host
// spraying passwords across many accounts and is the tier that counts every request. It
// mirrors pwd_ip exactly, at the same 30 per minute per /64.
//
// The account tiers are in TestLimitROPC_AccountFailureBudget, since only a failed
// credential spends those. RFC 6749 section 4.3.2 makes protecting this endpoint against
// brute force a MUST, and before this the endpoint carried a single composite bucket that
// bounded neither account nor host (#107, #195, #219).
func TestLimitROPC_PerIP(t *testing.T) {
	const ipBudget = 30

	run := func(m *RateLimiterMiddleware, username, ip string) (int, bool) {
		code, reached, _ := runROPC(m, "password", username, "app", ip, false)
		return code, reached
	}

	t.Run("the per-IP budget is exactly 30, from varied usernames", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < ipBudget; i++ {
			// Distinct accounts so no account bucket trips.
			username := fmt.Sprintf("user%d@example.com", i)
			if code, reached := run(m, username, "198.51.100.7:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached := run(m, "last@example.com", "198.51.100.7:5000"); code != http.StatusTooManyRequests || reached {
			t.Errorf("request %d: got code %d, handler reached %v; want %d and false",
				ipBudget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("addresses inside one /64 share the bucket, a second /64 does not", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		addr := func(i int) string { return fmt.Sprintf("[2001:db8:1:2::%x]:5000", i+1) }
		for i := 0; i < ipBudget; i++ {
			if code, reached := run(m, fmt.Sprintf("user%d@example.com", i), addr(i)); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d from %s: got code %d, handler reached %v; want %d and true",
					i+1, addr(i), code, reached, http.StatusTeapot)
			}
		}
		if code, reached := run(m, "last@example.com", addr(ipBudget)); code != http.StatusTooManyRequests || reached {
			t.Fatalf("request %d from a fresh address in the same /64: got code %d, handler reached %v; want %d and false",
				ipBudget+1, code, reached, http.StatusTooManyRequests)
		}
		// A neighbouring /64 is a different client. Without this the case above would
		// also pass for a key that collapsed every IPv6 address into one bucket.
		if code, reached := run(m, "elsewhere@example.com", "[2001:db8:1:3::1]:5000"); code != http.StatusTeapot || !reached {
			t.Errorf("second /64: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("only the password grant is limited", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		// Well past both budgets, and recording a failure on every one of them, so a
		// limiter that reached either tier for these would refuse long before the end. The
		// other grants carry no resource-owner password, so this limiter has nothing to
		// bound on them; counting them would throttle every token refresh in the deployment
		// from one host.
		for _, grant := range []string{"refresh_token", "authorization_code", "client_credentials"} {
			for i := 0; i < ipBudget*2; i++ {
				code, reached, _ := runROPC(m, grant, "victim@example.com", "app", "203.0.113.7:5000", true)
				if code != http.StatusTeapot || !reached {
					t.Fatalf("%s request %d: got code %d, handler reached %v; want %d and true",
						grant, i+1, code, reached, http.StatusTeapot)
				}
			}
		}
	})

	t.Run("disabled limiter never blocks", func(t *testing.T) {
		m := newTestMiddleware(nil, false)
		for i := 0; i < ipBudget*4; i++ {
			if code, reached, _ := runROPC(m, "password", "victim@example.com", "app",
				"203.0.113.7:5000", true); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: disabled limiter should never block, got code %d, handler reached %v",
					i+1, code, reached)
			}
		}
	})
}

// TestLimitROPC_AccountFailureBudget verifies the password grant reaches the same two-tier
// account gate the browser form does, at the same budgets and on the same buckets.
//
// It replaces the composite ropc_<clientId>_<username>_<ip> key, and two cases here are the
// exact inverse of what the old key allowed, which is what shows this stage changed the key
// rather than only the budget: a second client id no longer buys a fresh allowance (#107),
// while a second /64 still does, because that is decision 17's tight tier doing its job
// rather than the ceiling failing.
//
// Every case stays under ropc_ip's 30 per minute, which is checked first: a case that
// crossed it would be measuring the per-IP tier while claiming to measure the account gate.
func TestLimitROPC_AccountFailureBudget(t *testing.T) {
	const tightBudget = 10
	const backstop = 100

	// One fixed host, so the tight tier is the one under test.
	const attacker = "203.0.113.7:5000"

	t.Run("the tight budget is exactly 10 failures", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < tightBudget; i++ {
			if code, reached, _ := runROPC(m, "password", "victim@example.com", "app", attacker, true); code != http.StatusTeapot || !reached {
				t.Fatalf("failure %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached, _ := runROPC(m, "password", "victim@example.com", "app", attacker, true); code != http.StatusTooManyRequests || reached {
			t.Errorf("failure %d: got code %d, handler reached %v; want %d and false",
				tightBudget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	// #107, inverted. The old composite key put client_id in the bucket, so an attacker
	// escaped the account ceiling RFC 6749 section 4.3.2 makes a MUST by naming a second
	// client, which costs nothing when registration is open. This is the case that fails if
	// the client id ever creeps back into the key.
	t.Run("a second client id does not buy a fresh budget for the same account", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < tightBudget; i++ {
			if code, _, _ := runROPC(m, "password", "victim@example.com", "app", attacker, true); code != http.StatusTeapot {
				t.Fatalf("failure %d: got code %d, want %d", i+1, code, http.StatusTeapot)
			}
		}
		if code, reached, _ := runROPC(m, "password", "victim@example.com", "other-app", attacker, true); code != http.StatusTooManyRequests || reached {
			t.Errorf("second client id: got code %d, handler reached %v; want %d and false",
				code, reached, http.StatusTooManyRequests)
		}
	})

	// The other half, and why the case above is not just the ceiling being coarse: a
	// different network is a different tight bucket, which is what stops an attacker who
	// knows an address from denying its owner the grant.
	t.Run("a second network does buy a fresh tight budget for the same account", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < tightBudget+1; i++ {
			runROPC(m, "password", "victim@example.com", "app", attacker, true)
		}
		if code, reached, _ := runROPC(m, "password", "victim@example.com", "app", "198.51.100.9:5000", true); code != http.StatusTeapot || !reached {
			t.Errorf("second network: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("ten case and whitespace variants of one username share the bucket", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		spellings := spellingsOf("victim", "example.com")
		for i := 0; i < tightBudget; i++ {
			if code, reached, _ := runROPC(m, "password", spellings[i%len(spellings)], "app", attacker, true); code != http.StatusTeapot || !reached {
				t.Fatalf("spelling %q (failure %d): got code %d, handler reached %v; want %d and true",
					spellings[i%len(spellings)], i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached, _ := runROPC(m, "password", spellings[tightBudget%len(spellings)], "app", attacker, true); code != http.StatusTooManyRequests || reached {
			t.Errorf("failure %d: got code %d, handler reached %v; want %d and false",
				tightBudget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("a successful grant spends nothing", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		// A machine-driven integration authenticating one account over and over. Under the
		// 5 per minute this replaces it was refused on the sixth request of every minute,
		// which is what made the old budget unusable and this one safe.
		for i := 0; i < 25; i++ { // under ropc_ip's 30, which counts every request
			if code, reached, _ := runROPC(m, "password", "service@example.com", "app", attacker, false); code != http.StatusTeapot || !reached {
				t.Fatalf("grant %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
	})

	// And the ceiling behind the tight tier, without which an attacker with a /48 owns
	// 65,536 buckets and the account-wide MUST is gone again.
	t.Run("failures spread across networks still reach the account-wide backstop", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		admitted := 0
		for net := 0; net < backstop/tightBudget; net++ {
			ip := fmt.Sprintf("[2001:db8:%x::1]:5000", net)
			for i := 0; i < tightBudget; i++ {
				if code, _, _ := runROPC(m, "password", "victim@example.com", "app", ip, true); code == http.StatusTeapot {
					admitted++
				}
			}
		}
		if admitted != backstop {
			t.Fatalf("%d failures admitted across %d networks, want exactly %d",
				admitted, backstop/tightBudget, backstop)
		}
		if code, reached, _ := runROPC(m, "password", "victim@example.com", "app", "[2001:db8:ff::1]:5000", true); code != http.StatusTooManyRequests || reached {
			t.Errorf("failure %d, from a fresh network: got code %d, handler reached %v; want %d and false",
				backstop+1, code, reached, http.StatusTooManyRequests)
		}
	})

	// The case decision 7 exists for, and the one a second set of limiter instances would
	// silently break while every other case here stayed green: one password guessed against
	// one account is one event whichever door it arrives at.
	t.Run("failures at the password form are visible to the grant, and back", func(t *testing.T) {
		t.Run("pwd spends, ropc is refused", func(t *testing.T) {
			m := newTestMiddleware(nil, true)
			for i := 0; i < tightBudget; i++ {
				if code, _, _ := runPwd(m, "victim@example.com", attacker, true); code != http.StatusTeapot {
					t.Fatalf("pwd failure %d: got code %d, want %d", i+1, code, http.StatusTeapot)
				}
			}
			if code, reached, _ := runROPC(m, "password", "victim@example.com", "app", attacker, true); code != http.StatusTooManyRequests || reached {
				t.Errorf("the grant after ten form failures: got code %d, handler reached %v; want %d and false",
					code, reached, http.StatusTooManyRequests)
			}
		})

		t.Run("ropc spends, pwd is refused", func(t *testing.T) {
			m := newTestMiddleware(nil, true)
			for i := 0; i < tightBudget; i++ {
				if code, _, _ := runROPC(m, "password", "victim@example.com", "app", attacker, true); code != http.StatusTeapot {
					t.Fatalf("grant failure %d: got code %d, want %d", i+1, code, http.StatusTeapot)
				}
			}
			if code, reached, _ := runPwd(m, "victim@example.com", attacker, true); code != http.StatusTooManyRequests || reached {
				t.Errorf("the form after ten grant failures: got code %d, handler reached %v; want %d and false",
					code, reached, http.StatusTooManyRequests)
			}
		})

		// The spellings differ on each side, which is the other half of sharing: the two
		// routes have to agree about which account a request is, not merely about the
		// budget. LimitPwd reads "email" and LimitROPC reads "username", so a normalization
		// that lived in one of them and not the other would split the bucket here.
		t.Run("across a respelled address", func(t *testing.T) {
			m := newTestMiddleware(nil, true)
			for i := 0; i < tightBudget; i++ {
				if code, _, _ := runPwd(m, "  Victim@Example.COM ", attacker, true); code != http.StatusTeapot {
					t.Fatalf("pwd failure %d: got code %d, want %d", i+1, code, http.StatusTeapot)
				}
			}
			if code, reached, _ := runROPC(m, "password", "VICTIM@example.com", "app", attacker, true); code != http.StatusTooManyRequests || reached {
				t.Errorf("the grant under another spelling: got code %d, handler reached %v; want %d and false",
					code, reached, http.StatusTooManyRequests)
			}
		})
	})

	t.Run("the refusal is the oauth shape, with Retry-After and no rate-limit headers", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		var rr *httptest.ResponseRecorder
		for i := 0; i < tightBudget+1; i++ {
			_, _, rr = runROPC(m, "password", "victim@example.com", "app", attacker, true)
		}
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("got code %d, want %d", rr.Code, http.StatusTooManyRequests)
		}
		// The gate is shared with the browser password form, whose refusal renders HTML.
		// A token endpoint answering a 429 in HTML is unparseable to every OAuth2 client,
		// so this is the case that fails if the shared tier picks the shape (#219).
		if got := rr.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		if got := rr.Header().Get("Retry-After"); got != "900" {
			t.Errorf("Retry-After = %q, want 900, the tight tier's 15 minute window", got)
		}
		var body map[string]string
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("body is not JSON: %v\nbody: %s", err, rr.Body.String())
		}
		if body["error"] != "invalid_request" {
			t.Errorf(`error = %q, want "invalid_request"`, body["error"])
		}
		assertNoRateLimitHeaders(t, rr, "ropc failures-only rejection")
	})
}
