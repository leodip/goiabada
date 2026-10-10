package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/oauth"
)

// testTemplateFS is the smallest tree RenderTemplate needs: a layout that includes the
// three blocks the real one includes, the error page the browser rejection renders, and the
// 500 page a credential tier whose store faulted answers with (#394).
//
// This focused fixture avoids coupling middleware behaviour to unrelated markup changes.
// What stands in here is only the templates' shape. What is genuinely under test is the
// middleware's half (the layout and template it names, the bind keys it fills) plus the half
// RenderTemplate itself owns and a stub renderer would fake: the Content-Type it sets and the
// status it takes from _httpStatus.
var testTemplateFS = fstest.MapFS{
	"layouts/no_menu_layout.html": &fstest.MapFile{Data: []byte(
		`<!DOCTYPE html><html><head><title>{{template "title" .}}</title>{{template "head" .}}</head>` +
			`<body>{{template "body" .}}</body></html>`)},
	"auth_error.html": &fstest.MapFile{Data: []byte(
		`{{define "title"}}{{.appName}}{{end}}{{define "head"}}{{end}}` +
			`{{define "body"}}<h1>{{.title}}</h1><p id="errorMsg">{{.error}}</p>{{end}}`)},
	"error.html": &fstest.MapFile{Data: []byte(
		`{{define "title"}}{{.appName}}{{end}}{{define "head"}}{{end}}` +
			`{{define "body"}}<p id="requestId">{{.requestId}}</p>{{end}}`)},
}

// auditEvent is one call the middleware made to its audit logger.
//
// requestId is what chi's id read off the context the call carried, recorded beside the event so
// the trip cases can assert that reportTrip audits under the request's own id rather than under
// some context it reached for (#328 seam 3). Empty when the context carried none.
type auditEvent struct {
	name      string
	details   map[string]interface{}
	requestId string
}

// stubAuditLogger records what the limiter audited. Hand-written rather than generated,
// which is the convention stubCeremonyStore already sets in this file for a one-method
// interface. The mutex is not decoration: the reservation cases in later stages drive the
// middleware from several goroutines at once.
type stubAuditLogger struct {
	mu     sync.Mutex
	events []auditEvent
}

func (s *stubAuditLogger) Log(ctx context.Context, name string, details map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, auditEvent{
		name: name, details: details, requestId: chimiddleware.GetReqID(ctx),
	})
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

// newTestMiddleware builds the middleware with a real render.Renderer over testTemplateFS and a
// throwaway audit logger, for the cases that do not look at what was audited.
func newTestMiddleware(ceremonyStore authContextGetter, enabled bool) *RateLimiter {
	m, _ := newAuditedTestMiddleware(ceremonyStore, enabled)
	return m
}

func newAuditedTestMiddleware(ceremonyStore authContextGetter, enabled bool) (*RateLimiter, *stubAuditLogger) {
	m, auditLog, _ := newMeteredTestMiddleware(ceremonyStore, enabled)
	return m, auditLog
}

// newMeteredTestMiddleware is newAuditedTestMiddleware with the registry its refusals are counted
// on, for the cases that read the metrics.
func newMeteredTestMiddleware(ceremonyStore authContextGetter, enabled bool) (*RateLimiter, *stubAuditLogger, *metrics.Registry) {
	auditLog := &stubAuditLogger{}
	httpHelper := render.New(testTemplateFS)
	reg := metrics.NewRegistry()
	return NewRateLimiter(ceremonyStore, httpHelper, httpHelper, auditLog, enabled, nil, reg), auditLog, reg
}

// limiterRequest builds the request a limited route actually receives. Settings are on the
// context because Settings is a global router.Use registered ahead of every
// per-route limiter, and the browser rejection renders a template, which reads settings off
// the context. A request built without them panics on the first 429, so this is the shape
// the reject path has to work in rather than test scaffolding.
//
// The request id is there for the same reason: chi's RequestID middleware is mounted at the root
// of both servers, ahead of every limiter tier, so a request reaching a limiter carries one and
// the trip it audits is correlated to it (#328).
func limiterRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	ctx := reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Goiabada"})
	ctx = context.WithValue(ctx, chimiddleware.RequestIDKey, limiterRequestId)
	return req.WithContext(ctx)
}

// limiterRequestId is the id every limiterRequest carries, so a case asserting on it names one
// constant rather than a literal the helper could drift away from.
const limiterRequestId = "goiabada/req-limiter-1"

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

// stubCeremonyStore stands in for the real ceremony.Store, which needs a session store
// and a cookie to answer. It reads the user id from the request's query string so
// one middleware instance can be driven with several users, which is what shows
// the OTP budget is keyed per user rather than globally. A non-nil err is
// returned for every request, standing for an unreadable auth context.
type stubCeremonyStore struct {
	err error
}

func (s stubCeremonyStore) GetAuthContext(r *http.Request) (*ceremony.AuthContext, error) {
	if s.err != nil {
		return nil, s.err
	}
	userId, _ := strconv.ParseInt(r.URL.Query().Get("userId"), 10, 64)
	return &ceremony.AuthContext{UserId: userId}, nil
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
func runPwd(m *RateLimiter, email, ip string, failed bool) (int, bool, *httptest.ResponseRecorder) {
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

	run := func(m *RateLimiter, email, ip string) (int, bool) {
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
		// Refused by ratelimit.AccountKey lowercasing and trimming, not by the limiter
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
		// Nothing below the middleware touches the response, so refuse writes this header
		// on both paths. Asserting it on the failures-only one is what would notice if
		// only the every-request path kept it.
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

// TestLimitForgotPwd_PerEmailAndPerIP verifies the forgot-password limiter bounds
// both a single address (mail-bombing) and a single source IP, and that neither
// budget can be escaped by respelling the address or by moving inside one's own
// /64 (#219). Same conventions as TestLimitPwd_PerIP: exact budgets, a
// 418 stub, and a form body rather than a query target.
func TestLimitForgotPwd_PerEmailAndPerIP(t *testing.T) {
	const emailBudget = 5
	const ipBudget = 20

	run := func(m *RateLimiter, email, ip string) (int, bool) {
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

	// The address typed into the form is recorded only as its digest, of the address as the
	// forgot-password lookup normalizes it, so the trip joins requested_password_reset's rows for
	// the same address (#522 decision 10). SHA-256 of "victim@example.com", computed outside
	// this code.
	t.Run("the trip records the address as its digest", func(t *testing.T) {
		m, auditLog := newAuditedTestMiddleware(nil, true)
		for i := 0; i < emailBudget+1; i++ {
			run(m, "Victim@Example.com", freshIP(i))
		}
		auditLog.mu.Lock()
		events := append([]auditEvent(nil), auditLog.events...)
		auditLog.mu.Unlock()
		want := map[string]interface{}{"limiter": "forgot_pwd_email",
			"email_digest": "ffbe8cff4f9f8d8b109460f975c343e942cd4c3ed191323eb83374ae2ea4de5f"}
		if len(events) != 1 || !reflect.DeepEqual(events[0].details, want) {
			t.Errorf("audited %v, want one event with details %v", events, want)
		}
	})

	t.Run("ten case and whitespace variants of one address share the per-email bucket", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		spellings := spellingsOf("victim", "example.com")
		// Refused by ratelimit.AccountKey lowercasing and trimming: without it each
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

	t.Run("an oversized address keeps its own bucket", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		// Nothing caps an account identifier's length on the way in, so any of these
		// can name a real account. Folding them into one bucket would let the flood
		// below spend the budget of whichever one does (#276). 320 octets of local part
		// alone is past the longest address RFC 5321 allows, so each is digested.
		oversized := func(i int) string {
			return fmt.Sprintf("%s%d@example.com", strings.Repeat("a", 64+1+255), i)
		}
		for i := 0; i < emailBudget+1; i++ {
			if code, reached := run(m, oversized(i), freshIP(i)); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d, each on its own oversized address: got code %d, handler "+
					"reached %v; want %d and true", i+1, code, reached, http.StatusTeapot)
			}
		}
		// The one address submitted twice is the one that spends a budget, and it spends
		// only its own.
		repeated := oversized(emailBudget + 1)
		for i := 0; i < emailBudget; i++ {
			if code, reached := run(m, repeated, freshIP(emailBudget+2+i)); code != http.StatusTeapot || !reached {
				t.Fatalf("repeat %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached := run(m, repeated, freshIP(0)); code != http.StatusTooManyRequests || reached {
			t.Errorf("repeat %d: got code %d, handler reached %v; want %d and false",
				emailBudget+1, code, reached, http.StatusTooManyRequests)
		}
		// And a different oversized address is untouched by it, which folding cost.
		if code, reached := run(m, oversized(emailBudget+2), freshIP(1)); code != http.StatusTeapot || !reached {
			t.Errorf("a second oversized address after the flood: got code %d, handler reached %v; "+
				"want %d and true", code, reached, http.StatusTeapot)
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

	run := func(m *RateLimiter, target, ip string) (int, bool) {
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
// The budget is exact because it is published policy: 30 requests per 5 minutes, which is 10
// activation operations at the three requests an activation now costs (the link's GET, the clean
// GET that renders the password form, and its POST), the reset tier's budget for the same chain
// (#207 decision 9).
//
// The handler stub writes 418 rather than 200 on purpose: a middleware that writes nothing
// produces exactly 200 with an empty body, so 418 is what tells "the handler ran" apart from
// "nothing was written", and from 429.
func TestLimitActivate_PerIP(t *testing.T) {
	const budget = 30

	run := func(m *RateLimiter, target, ip string) (int, bool) {
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

	t.Run("the budget is exactly 30 per IP", func(t *testing.T) {
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

// TestLimitRegister_PerIP verifies self-registration is bounded per client block, and that a
// distinct address per request buys nothing (#219).
//
// That last case is the one the IP tier exists for. The endpoint writes a pre_registrations row
// for each new address and mails each address given to it, and without verification it answers
// whether an address already has an account, all of which are harmful across distinct addresses.
// A limiter keyed on the submitted address alone would bucket the attacker's own choice of victim
// and bound none of it, which is why the per-address tier beside it is a second tier and not a
// replacement (TestLimitRegister_PerAddress).
//
// The budget is exact because it is published policy: 20 requests per 5 minutes. Every case
// submits a distinct address per request, so only the IP tier can trip.
//
// The handler stub writes 418 rather than 200 on purpose: a middleware that writes nothing
// produces exactly 200 with an empty body, so 418 is what tells "the handler ran" apart from
// "nothing was written", and from 429.
func TestLimitRegister_PerIP(t *testing.T) {
	const budget = 20

	run := func(m *RateLimiter, email, ip string) (int, bool, *httptest.ResponseRecorder) {
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
	candidate := func(i int) string { return fmt.Sprintf("candidate%d@example.com", i) }

	t.Run("a distinct address per request shares one host's bucket of exactly 20", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		// The enumeration bound itself: 21 addresses probed from one host, and the 21st is
		// refused. A per-address key alone would allow all of them.
		for i := 0; i < budget; i++ {
			if code, reached, _ := run(m, candidate(i), "203.0.113.7:5000"); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d for %s: got code %d, handler reached %v; want %d and true",
					i+1, candidate(i), code, reached, http.StatusTeapot)
			}
		}
		if code, reached, _ := run(m, candidate(budget), "203.0.113.7:5000"); code != http.StatusTooManyRequests || reached {
			t.Errorf("request %d with a fresh address: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("addresses inside one /64 share the bucket, a second /64 does not", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		addr := func(i int) string { return fmt.Sprintf("[2001:db8:1:2::%x]:5000", i+1) }
		for i := 0; i < budget; i++ {
			if code, _, _ := run(m, candidate(i), addr(i)); code != http.StatusTeapot {
				t.Fatalf("request %d from %s: got code %d, want %d", i+1, addr(i), code, http.StatusTeapot)
			}
		}
		if code, _, _ := run(m, candidate(budget), addr(budget)); code != http.StatusTooManyRequests {
			t.Errorf("request %d from %s: got code %d, want %d",
				budget+1, addr(budget), code, http.StatusTooManyRequests)
		}
		// A neighbouring /64 is a different client, which is what makes the mask observable
		// rather than the limiter.
		if code, reached, _ := run(m, candidate(budget+1), "[2001:db8:1:3::1]:5000"); code != http.StatusTeapot || !reached {
			t.Errorf("second /64: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("the refusal is the browser shape, with Retry-After and no rate-limit headers", func(t *testing.T) {
		m, auditLog := newAuditedTestMiddleware(nil, true)
		var rr *httptest.ResponseRecorder
		for i := 0; i < budget+1; i++ {
			_, _, rr = run(m, candidate(i), "203.0.113.7:5000")
		}
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("got code %d, want %d", rr.Code, http.StatusTooManyRequests)
		}
		if got := rr.Header().Get("Retry-After"); got != "300" {
			t.Errorf("Retry-After = %q, want 300, the tier's 5 minute window", got)
		}
		// A registration form is a browser route, so the refusal is the error page rather
		// than the plain text a status-code-only refusal would write.
		if got := rr.Header().Get("Content-Type"); got != "text/html; charset=UTF-8" {
			t.Errorf("Content-Type = %q, want text/html; charset=UTF-8", got)
		}
		assertNoRateLimitHeaders(t, rr, "registration rejection")

		auditLog.mu.Lock()
		events := append([]auditEvent(nil), auditLog.events...)
		auditLog.mu.Unlock()
		want := map[string]interface{}{"limiter": "register", "ip": "203.0.113.7"}
		if len(events) != 1 || !reflect.DeepEqual(events[0].details, want) {
			t.Errorf("audited %v, want one event with details %v", events, want)
		}
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

// TestLimitRegister_PerAddress verifies the second tier on self-registration: one address is
// bounded to forgot-password's per-address budget, 5 requests per 5 minutes, every request
// counted, keyed on the address normalized as the account key is (#207 decision 5). With
// verification a registration for an address that has an account mails that account a notice,
// so without this tier one host could mail any account holder 20 notices every 5 minutes, and
// many hosts without bound.
func TestLimitRegister_PerAddress(t *testing.T) {
	const budget = 5

	run := func(m *RateLimiter, email, ip string) (int, bool, *httptest.ResponseRecorder) {
		form := url.Values{"email": {email}}
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
	// A distinct IPv4 address per request, so only the per-address tier can trip.
	freshIP := func(i int) string { return fmt.Sprintf("203.0.113.%d:5000", i+1) }

	t.Run("the budget is exactly 5 per address, from varied IPs", func(t *testing.T) {
		m, auditLog := newAuditedTestMiddleware(nil, true)
		for i := 0; i < budget; i++ {
			if code, reached, _ := run(m, "holder@example.com", freshIP(i)); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		code, reached, rr := run(m, "holder@example.com", freshIP(budget))
		if code != http.StatusTooManyRequests || reached {
			t.Fatalf("request %d: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
		}
		if got := rr.Header().Get("Retry-After"); got != "300" {
			t.Errorf("Retry-After = %q, want 300, the tier's 5 minute window", got)
		}
		if got := rr.Header().Get("Content-Type"); got != "text/html; charset=UTF-8" {
			t.Errorf("Content-Type = %q, want text/html; charset=UTF-8", got)
		}

		auditLog.mu.Lock()
		events := append([]auditEvent(nil), auditLog.events...)
		auditLog.mu.Unlock()
		// The address typed into the form, as its digest only (#522 decision 10): SHA-256 of
		// "holder@example.com", computed outside this code.
		want := map[string]interface{}{"limiter": "register_email",
			"email_digest": "1a4c5ee1a381a1003aee056aea6df0740ba8744e0493228e5d9c573d4090c9ec"}
		if len(events) != 1 || !reflect.DeepEqual(events[0].details, want) {
			t.Errorf("audited %v, want one event with details %v", events, want)
		}
	})

	t.Run("case and whitespace variants of one address share the bucket", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		spellings := spellingsOf("holder", "example.com")
		for i := 0; i < budget; i++ {
			if code, reached, _ := run(m, spellings[i%len(spellings)], freshIP(i)); code != http.StatusTeapot || !reached {
				t.Fatalf("spelling %q (request %d): got code %d, handler reached %v; want %d and true",
					spellings[i%len(spellings)], i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached, _ := run(m, spellings[budget%len(spellings)], freshIP(budget)); code != http.StatusTooManyRequests || reached {
			t.Errorf("request %d: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("a second address still has its own bucket", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < budget+1; i++ {
			run(m, "holder@example.com", freshIP(i))
		}
		if code, reached, _ := run(m, "other@example.com", freshIP(budget+1)); code != http.StatusTeapot || !reached {
			t.Errorf("second address: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("disabled limiter never blocks", func(t *testing.T) {
		m := newTestMiddleware(nil, false)
		for i := 0; i < budget*2; i++ {
			if code, reached, _ := run(m, "holder@example.com", "203.0.113.1:5000"); code != http.StatusTeapot || !reached {
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

	run := func(m *RateLimiter, userId int, failed bool) (int, bool) {
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
		m := newTestMiddleware(stubCeremonyStore{err: ceremony.ErrNoAuthContext}, true)
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
		m := newTestMiddleware(stubCeremonyStore{}, true)
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
		m := newTestMiddleware(stubCeremonyStore{}, true)
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
		m := newTestMiddleware(stubCeremonyStore{}, true)
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

	// The switch governs the tiers keyed on an address or an email anyone can send; this one
	// counts a user already authenticated, whom no stranger can spend it for, so it holds with
	// the limiter off too (#542).
	t.Run("the limiter switched off still limits one-time codes", func(t *testing.T) {
		m := newTestMiddleware(stubCeremonyStore{}, false)
		for i := 0; i < budget; i++ {
			if code, reached := run(m, 42, true); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d of a budget of %d with the limiter off: got code %d, handler reached %v",
					i+1, budget, code, reached)
			}
		}
		if code, reached := run(m, 42, true); code != http.StatusTooManyRequests || reached {
			t.Fatalf("attempt %d with the limiter off: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
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
	return req.WithContext(reqctx.WithValidatedToken(req.Context(), oauth.JwtToken{Claims: map[string]interface{}{"sub": subject}}))
}

// runVerification drives one request through LimitEmailVerification and reports the status,
// whether the handler ran, and the response. failed is what the handler found when it
// compared the code, which is the only thing that spends this budget.
func runVerification(m *RateLimiter, subject string, failed bool) (int, bool, *httptest.ResponseRecorder) {
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
		// answers 500 before it compares anything, so the skipped limit costs nothing.
		// Returning here instead would write no response at all.
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

	// The switch governs the tiers keyed on an address or an email anyone can send; this one
	// counts a user already authenticated, whom no stranger can spend it for, so it holds with
	// the limiter off too (#542).
	t.Run("the limiter switched off still limits verification codes", func(t *testing.T) {
		m := newTestMiddleware(nil, false)
		for i := 0; i < budget; i++ {
			if code, reached, _ := runVerification(m, subject, true); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d of a budget of %d with the limiter off: got code %d, handler reached %v",
					i+1, budget, code, reached)
			}
		}
		if code, reached, _ := runVerification(m, subject, true); code != http.StatusTooManyRequests || reached {
			t.Fatalf("attempt %d with the limiter off: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
		}
	})
}

// runVerificationSend drives one request through LimitEmailVerificationSend and reports the
// status, whether the handler ran, and the response. A blank subject carries no token.
func runVerificationSend(m *RateLimiter, subject string) (int, bool, *httptest.ResponseRecorder) {
	req := limiterRequest(http.MethodPost, "/api/v1/account/email/verification/send", nil)
	if subject != "" {
		req = req.WithContext(reqctx.WithValidatedToken(req.Context(), oauth.JwtToken{Claims: map[string]interface{}{"sub": subject}}))
	}
	rr := httptest.NewRecorder()
	reached := false
	m.LimitEmailVerificationSend(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rr, req)
	return rr.Code, reached, rr
}

// TestLimitEmailVerificationSend_PerSubject is the verification mail's own tier (#404). The
// account chooses the address the mail goes to, so every send counts against the account,
// sent or not: 5 per hour, refused in the API's own envelope with the window as Retry-After,
// and audited once with the subject, as the other two account API tiers audit theirs.
func TestLimitEmailVerificationSend_PerSubject(t *testing.T) {
	const budget = 5
	const subject = "44444444-4444-4444-4444-444444444444"

	t.Run("the budget is exactly 5 requests, then one refusal in the API's shape", func(t *testing.T) {
		m, auditLog := newAuditedTestMiddleware(nil, true)
		for i := 0; i < budget; i++ {
			if code, reached, _ := runVerificationSend(m, subject); code != http.StatusTeapot || !reached {
				t.Fatalf("request %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		code, reached, rr := runVerificationSend(m, subject)
		if code != http.StatusTooManyRequests || reached {
			t.Fatalf("request %d: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
		}
		if got := rr.Header().Get("Retry-After"); got != "3600" {
			t.Errorf("Retry-After = %q, want the hour the tier counts over", got)
		}
		if got := rr.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want the account API's JSON envelope", got)
		}
		if len(auditLog.events) != 1 {
			t.Fatalf("got %d audit events, want 1", len(auditLog.events))
		}
		want := map[string]interface{}{"limiter": "email_verification_send", "logged_in_user": subject}
		if !reflect.DeepEqual(auditLog.events[0].details, want) {
			t.Errorf("audit details = %v, want %v", auditLog.events[0].details, want)
		}
	})

	t.Run("each subject has its own budget", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < budget; i++ {
			runVerificationSend(m, subject)
		}
		if code, _, _ := runVerificationSend(m, subject); code != http.StatusTooManyRequests {
			t.Fatalf("the exhausted subject got code %d, want %d", code, http.StatusTooManyRequests)
		}
		if code, reached, _ := runVerificationSend(m, "55555555-5555-5555-5555-555555555555"); code != http.StatusTeapot || !reached {
			t.Errorf("second subject: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("it is not the verification check's budget", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < budget; i++ {
			runVerificationSend(m, subject)
		}
		if code, reached, _ := runVerification(m, subject, true); code != http.StatusTeapot || !reached {
			t.Errorf("the verification check got code %d, handler reached %v, with only the send's budget spent",
				code, reached)
		}
	})

	t.Run("a request carrying no token reaches the handler", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < budget*4; i++ {
			if code, reached, _ := runVerificationSend(m, ""); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
	})

	// The switch governs the tiers keyed on an address or an email anyone can send; this one
	// counts a user already authenticated, whom no stranger can spend it for, so it holds with
	// the limiter off too (#542).
	t.Run("the limiter switched off still limits verification mail", func(t *testing.T) {
		m := newTestMiddleware(nil, false)
		for i := 0; i < budget; i++ {
			if code, reached, _ := runVerificationSend(m, subject); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d of a budget of %d with the limiter off: got code %d, handler reached %v",
					i+1, budget, code, reached)
			}
		}
		if code, reached, _ := runVerificationSend(m, subject); code != http.StatusTooManyRequests || reached {
			t.Fatalf("attempt %d with the limiter off: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
		}
	})
}

// accountPasswordRequest builds a request at one of the two routes LimitAccountPassword
// covers, carrying the validated token the account API's authentication middleware leaves on
// the context. target is what tells the two routes apart, and the cases below use it to show
// the bucket does not. A blank subject omits the token entirely.
func accountPasswordRequest(target, subject string) *http.Request {
	req := limiterRequest(http.MethodPut, target, nil)
	if subject == "" {
		return req
	}
	return req.WithContext(reqctx.WithValidatedToken(req.Context(), oauth.JwtToken{Claims: map[string]interface{}{"sub": subject}}))
}

// runAccountPassword drives one request through LimitAccountPassword and reports the status,
// whether the handler ran, and the response. failed is what the handler found when it
// verified the password, which is the only thing that spends this budget.
func runAccountPassword(m *RateLimiter, target, subject string, failed bool) (int, bool, *httptest.ResponseRecorder) {
	rr := httptest.NewRecorder()
	reached := false
	m.LimitAccountPassword(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		if failed {
			m.RecordCredentialFailure(r)
		}
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rr, accountPasswordRequest(target, subject))
	return rr.Code, reached, rr
}

const (
	accountPasswordRoute = "/api/v1/account/password"
	accountOTPRoute      = "/api/v1/account/otp"
)

// TestLimitAccountPassword_PerSubject is seam 1 for the account password check, which both
// routes performed with an unbounded bcrypt and no failure counter (#113, #219).
//
// The budget is asserted exactly, on both sides, because it is published policy in the
// reference documentation.
func TestLimitAccountPassword_PerSubject(t *testing.T) {
	const budget = 5
	const subject = "44444444-4444-4444-4444-444444444444"

	t.Run("the budget is exactly 5 failures", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < budget; i++ {
			if code, reached, _ := runAccountPassword(m, accountPasswordRoute, subject, true); code != http.StatusTeapot || !reached {
				t.Fatalf("failure %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		if code, reached, _ := runAccountPassword(m, accountPasswordRoute, subject, true); code != http.StatusTooManyRequests || reached {
			t.Errorf("failure %d: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
		}
	})

	t.Run("the route in the path does not key anything", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		// Split across the two routes this middleware covers. One bucket is the whole point:
		// they verify the same secret, so a key carrying the path would hand an attacker ten
		// guesses by alternating between them.
		for i := 0; i < budget; i++ {
			target := accountPasswordRoute
			if i%2 == 1 {
				target = accountOTPRoute
			}
			if code, _, _ := runAccountPassword(m, target, subject, true); code != http.StatusTeapot {
				t.Fatalf("failure %d at %s: got code %d, want %d", i+1, target, code, http.StatusTeapot)
			}
		}
		if code, _, _ := runAccountPassword(m, accountOTPRoute, subject, true); code != http.StatusTooManyRequests {
			t.Errorf("the OTP route after %d failures split across both: got code %d, want %d",
				budget, code, http.StatusTooManyRequests)
		}
		if code, _, _ := runAccountPassword(m, accountPasswordRoute, subject, true); code != http.StatusTooManyRequests {
			t.Errorf("the password route after %d failures split across both: got code %d, want %d",
				budget, code, http.StatusTooManyRequests)
		}
	})

	t.Run("a correct password spends nothing, and hands its slot back", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		// Well past the budget, every one of them verified. A tier that counted every request
		// would refuse the sixth, which is a user locked out of changing their own password
		// by having changed it.
		for i := 0; i < budget*4; i++ {
			if code, reached, _ := runAccountPassword(m, accountPasswordRoute, subject, false); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
		// And the full budget is still there, which a leaked reservation would have shrunk.
		for i := 0; i < budget; i++ {
			if code, _, _ := runAccountPassword(m, accountPasswordRoute, subject, true); code != http.StatusTeapot {
				t.Fatalf("failure %d after the successful run: got code %d, want %d",
					i+1, code, http.StatusTeapot)
			}
		}
		if code, _, _ := runAccountPassword(m, accountPasswordRoute, subject, true); code != http.StatusTooManyRequests {
			t.Errorf("failure %d: got code %d, want %d", budget+1, code, http.StatusTooManyRequests)
		}
	})

	t.Run("each subject has its own budget", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < budget+1; i++ {
			runAccountPassword(m, accountPasswordRoute, subject, true)
		}
		if code, _, _ := runAccountPassword(m, accountPasswordRoute, subject, true); code != http.StatusTooManyRequests {
			t.Fatalf("the exhausted subject got code %d, want %d", code, http.StatusTooManyRequests)
		}
		// Same middleware instance, a different account: a global key would refuse this.
		if code, reached, _ := runAccountPassword(m, accountPasswordRoute, "55555555-5555-5555-5555-555555555555", true); code != http.StatusTeapot || !reached {
			t.Errorf("second subject: got code %d, handler reached %v; want %d and true",
				code, reached, http.StatusTeapot)
		}
	})

	t.Run("a request carrying no token reaches the handler", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		// With no subject there is no bucket, and the handler answers 500 before it
		// verifies anything, so the skipped limit costs nothing. Returning here instead
		// would write no response at all.
		for i := 0; i < budget*4; i++ {
			if code, reached, _ := runAccountPassword(m, accountPasswordRoute, "", true); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
	})

	t.Run("a token whose subject is blank reaches the handler", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		for i := 0; i < budget*4; i++ {
			if code, reached, _ := runAccountPassword(m, accountOTPRoute, "   ", true); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d: got code %d, handler reached %v; want %d and true",
					i+1, code, reached, http.StatusTeapot)
			}
		}
	})

	t.Run("the refusal is the api shape, with Retry-After and no rate-limit headers", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		var rr *httptest.ResponseRecorder
		for i := 0; i < budget+1; i++ {
			_, _, rr = runAccountPassword(m, accountOTPRoute, subject, true)
		}
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("got code %d, want %d", rr.Code, http.StatusTooManyRequests)
		}
		var body struct {
			ErrorCode string `json:"error_code"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("the body is not the API error envelope: %v (%q)", err, rr.Body.String())
		}
		if body.ErrorCode != "TOO_MANY_REQUESTS" {
			t.Errorf("error_code = %q, want TOO_MANY_REQUESTS", body.ErrorCode)
		}
		if got := rr.Header().Get("Retry-After"); got != "900" {
			t.Errorf("Retry-After = %q, want 900, the 15 minute window in seconds", got)
		}
		assertNoRateLimitHeaders(t, rr, "the account password refusal")
	})

	// The switch governs the tiers keyed on an address or an email anyone can send; this one
	// counts a user already authenticated, whom no stranger can spend it for, so it holds with
	// the limiter off too (#542).
	t.Run("the limiter switched off still limits account password checks", func(t *testing.T) {
		m := newTestMiddleware(nil, false)
		for i := 0; i < budget; i++ {
			if code, reached, _ := runAccountPassword(m, accountPasswordRoute, subject, true); code != http.StatusTeapot || !reached {
				t.Fatalf("attempt %d of a budget of %d with the limiter off: got code %d, handler reached %v",
					i+1, budget, code, reached)
			}
		}
		if code, reached, _ := runAccountPassword(m, accountPasswordRoute, subject, true); code != http.StatusTooManyRequests || reached {
			t.Fatalf("attempt %d with the limiter off: got code %d, handler reached %v; want %d and false",
				budget+1, code, reached, http.StatusTooManyRequests)
		}
	})
}

// -----------------------------------------------------------------------------
// Seam 1, stage 2: what a rejection looks like, and that it leaves a trace.
//
// Every case below drives a real limiter past its budget and reads the response
// the caller would actually receive. Nothing asserts on a spy, because the defect
// these exist to prevent is a rejection wired up everywhere except where it is
// written: the shape a limiter reaches for by default is "Too Many Requests\n" as
// text/plain on every route, regardless of how much configuration surrounds it (#219).
// -----------------------------------------------------------------------------

// tripBrowser drives failed password checks at LimitPwd from one host until it is refused
// and returns the refusal. The tight account tier of 10 failures is what trips, since it is
// reached before the per-IP 30.
//
// Every request has to record a failure: since stage 3 the account tiers count nothing
// else, so a loop of plain requests would drive the per-IP tier instead and the cases below
// would silently be about a different limiter.
func tripBrowser(t *testing.T, m *RateLimiter) *httptest.ResponseRecorder {
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
func tripOAuth(t *testing.T, m *RateLimiter) *httptest.ResponseRecorder {
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
		t.Errorf("Content-Type = %q, want %q; a plain-text body is the default a refusal falls back to",
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

	// The catalog message, not the key: the embedded catalogs are served with no setup, so a
	// raw key in the body would mean the string is missing from active.en.toml.
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
func tripAPI(t *testing.T, m *RateLimiter) *httptest.ResponseRecorder {
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
		t.Errorf("Content-Type = %q, want application/json; a plain-text body is the default a refusal falls back to", got)
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
	if body.ErrorDescription != "Too many requests. Please wait and try again later." {
		t.Errorf("error_description = %q, want the standard rate-limit message", body.ErrorDescription)
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
		m, auditLog := newAuditedTestMiddleware(nil, true)
		refused := 0
		for i := 0; i < 25; i++ {
			if code, _, _ := runPwd(m, "victim@example.com", host, true); code == http.StatusTooManyRequests {
				refused++
			}
		}
		if refused < 10 {
			t.Fatalf("only %d of 25 requests were refused; the case needs a burst of rejections", refused)
		}
		if got := auditLog.count(audit.EventRateLimitExceeded); got != 1 {
			t.Errorf("got %d rate_limit_exceeded events for %d rejections on one key, want exactly 1",
				got, refused)
		}
	})

	t.Run("the event carries the limiter and the account", func(t *testing.T) {
		m, auditLog := newAuditedTestMiddleware(nil, true)
		for i := 0; i < 11; i++ {
			runPwd(m, "Victim@Example.com", host, true)
		}
		auditLog.mu.Lock()
		defer auditLog.mu.Unlock()
		if len(auditLog.events) != 1 {
			t.Fatalf("got %d events, want 1", len(auditLog.events))
		}
		e := auditLog.events[0]
		if e.name != audit.EventRateLimitExceeded {
			t.Errorf("event name = %q, want %q", e.name, audit.EventRateLimitExceeded)
		}
		// The digest of the normalized address, which is how EventAuthFailedPwd records the
		// same typed address, and never the address itself (#522 decision 10): SHA-256 of
		// "victim@example.com", computed outside this code. And the block it was refused for,
		// which is half of this tier's key: an administrator reading the event needs to know
		// which network spent the budget.
		want := map[string]interface{}{
			"limiter":      "pwd_account_net",
			"email_digest": "ffbe8cff4f9f8d8b109460f975c343e942cd4c3ed191323eb83374ae2ea4de5f",
			"ip":           "203.0.113.7",
		}
		if !reflect.DeepEqual(e.details, want) {
			t.Errorf("details = %#v, want %#v", e.details, want)
		}
		// reportTrip is the one production Log call site outside the handlers, and the fourth of
		// #328's four call shapes: it already took a context for its own Warn record, so the
		// property under test is that the audit call is given that same context rather than one
		// reached for. The stub read chi's id off whatever it was handed, so an empty value here
		// means the trip was audited under a context carrying no request (#328 seam 3).
		if e.requestId != limiterRequestId {
			t.Errorf("request id on the audited context = %q, want %q", e.requestId, limiterRequestId)
		}
	})

	t.Run("two keys produce two events", func(t *testing.T) {
		m, auditLog := newAuditedTestMiddleware(nil, true)
		for i := 0; i < 11; i++ {
			runPwd(m, "one@example.com", host, true)
		}
		for i := 0; i < 11; i++ {
			runPwd(m, "two@example.com", host, true)
		}
		// A gate keyed globally rather than per key would report the first account and
		// go silent for the second, which is the failure that makes the bound useless.
		if got := auditLog.count(audit.EventRateLimitExceeded); got != 2 {
			t.Errorf("got %d events for two rejected accounts, want 2", got)
		}
	})

	t.Run("no event when nothing is refused", func(t *testing.T) {
		m, auditLog := newAuditedTestMiddleware(nil, true)
		for i := 0; i < 10; i++ {
			runPwd(m, fmt.Sprintf("user%d@example.com", i), host, true)
		}
		if got := auditLog.count(audit.EventRateLimitExceeded); got != 0 {
			t.Errorf("got %d events with nothing refused, want 0", got)
		}
	})
}

// TestRejection_WarnsWithoutNamingTheUser pins decision 14. Nothing else observes the
// log line, so deleting it or restoring the address it used to interpolate would leave
// the stage green.
//
// The repository already settled the policy this asserts: httpmw.RequestLogger in
// this same package logs by allowlist "because a denylist fails open", and email is
// deliberately not on that list. The address is carried by the audit event instead, as its
// digest.
func TestRejection_WarnsWithoutNamingTheUser(t *testing.T) {
	t.Run("an account tier names the limiter and nothing else", func(t *testing.T) {
		buf := logtest.CaptureSlog(t)
		m := newTestMiddleware(nil, true)
		tripBrowser(t, m)

		out := buf.Text()
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
		buf := logtest.CaptureSlog(t)
		m := newTestMiddleware(nil, true)
		tripOAuth(t, m)

		out := buf.Text()
		if !strings.Contains(out, "limiter=dcr") || !strings.Contains(out, "ip=203.0.113.8") {
			t.Errorf("the warning line should carry the limiter and the client block:\n%s", out)
		}
	})
}

// builtLimiter is one of the six route-facing limiters whose body is written by a builder rather
// than by hand (#439 decision 1): the three per-IP ones and the three failures-per-subject ones. It
// holds what the route sends and everything its refusal is, as literals from the published budgets
// and the refusal shapes #219 settled rather than read back off a tier, so a builder handed the
// wrong tier, the wrong shape or the wrong audit identifier for one route fails here by name.
type builtLimiter struct {
	name    string
	limit   func(m *RateLimiter) func(http.Handler) http.Handler
	request func() *http.Request
	// failures is true for a failures-only tier, which only a credential failure the handler
	// records can spend.
	failures bool
	budget   int
	// contentType and retryAfter are the refusal's shape and the tier's window in seconds.
	contentType string
	retryAfter  string
	// audited is the whole details map of the one event a trip audits, and warned the whole
	// attribute set of the warning each refusal logs.
	audited map[string]interface{}
	warned  map[string]any
	// alwaysOn is true for a tier counting a user already authenticated, which limits with the
	// rate limiter switched off too (#542).
	alwaysOn bool
	// noSubject, set on a failures-per-subject limiter, builds a request with no subject to
	// key on and the ceremony store that goes with it. Such a request reaches the handler
	// however often it is sent.
	noSubject func() (authContextGetter, *http.Request)
}

func builtLimiters() []builtLimiter {
	const ip = "203.0.113.7"
	const subject = "11111111-1111-1111-1111-111111111111"
	ipRequest := func(method, target string) func() *http.Request {
		return func() *http.Request {
			req := limiterRequest(method, target, nil)
			req.RemoteAddr = ip + ":5000"
			return req
		}
	}
	ipWarned := func(limiter string) map[string]any {
		return map[string]any{"limiter": limiter, "ip": ip, "request_id": limiterRequestId}
	}
	subjectWarned := func(limiter string) map[string]any {
		return map[string]any{"limiter": limiter, "request_id": limiterRequestId}
	}
	noToken := func(target string) func() (authContextGetter, *http.Request) {
		return func() (authContextGetter, *http.Request) {
			return stubCeremonyStore{}, accountPasswordRequest(target, "")
		}
	}
	return []builtLimiter{
		{
			name: "LimitActivate", limit: func(m *RateLimiter) func(http.Handler) http.Handler { return m.LimitActivate },
			request: ipRequest(http.MethodGet, "/activate"), budget: 30,
			contentType: "text/html; charset=UTF-8", retryAfter: "300",
			audited: map[string]interface{}{"limiter": "activate", "ip": ip}, warned: ipWarned("activate"),
		},
		{
			name: "LimitResetPwd", limit: func(m *RateLimiter) func(http.Handler) http.Handler { return m.LimitResetPwd },
			request: ipRequest(http.MethodGet, "/reset-password"), budget: 30,
			contentType: "text/html; charset=UTF-8", retryAfter: "300",
			audited: map[string]interface{}{"limiter": "reset_pwd", "ip": ip}, warned: ipWarned("reset_pwd"),
		},
		{
			name: "LimitDCR", limit: func(m *RateLimiter) func(http.Handler) http.Handler { return m.LimitDCR },
			request: ipRequest(http.MethodPost, "/connect/register"), budget: 10,
			contentType: "application/json", retryAfter: "60",
			audited: map[string]interface{}{"limiter": "dcr", "ip": ip}, warned: ipWarned("dcr"),
		},
		{
			// The bucket is user_7, and the event records the user id itself, as an int64: the
			// identifier the audit records is not the bucket key, which is why the subject
			// function returns both.
			name: "LimitOtp", limit: func(m *RateLimiter) func(http.Handler) http.Handler { return m.LimitOtp },
			alwaysOn: true,
			request:  func() *http.Request { return limiterRequest(http.MethodPost, "/auth/otp?userId=7", nil) },
			failures: true, budget: 5,
			contentType: "text/html; charset=UTF-8", retryAfter: "900",
			audited: map[string]interface{}{"limiter": "otp", "user_id": int64(7)}, warned: subjectWarned("otp"),
			noSubject: func() (authContextGetter, *http.Request) {
				return stubCeremonyStore{err: ceremony.ErrNoAuthContext}, limiterRequest(http.MethodPost, "/auth/otp", nil)
			},
		},
		{
			name: "LimitEmailVerification", limit: func(m *RateLimiter) func(http.Handler) http.Handler { return m.LimitEmailVerification },
			alwaysOn: true,
			request:  func() *http.Request { return verificationRequest(subject) },
			failures: true, budget: 5,
			contentType: "application/json", retryAfter: "900",
			audited:   map[string]interface{}{"limiter": "email_verification", "logged_in_user": subject},
			warned:    subjectWarned("email_verification"),
			noSubject: noToken("/api/v1/account/email/verification"),
		},
		{
			name: "LimitAccountPassword", limit: func(m *RateLimiter) func(http.Handler) http.Handler { return m.LimitAccountPassword },
			alwaysOn: true,
			request:  func() *http.Request { return accountPasswordRequest(accountPasswordRoute, subject) },
			failures: true, budget: 5,
			contentType: "application/json", retryAfter: "900",
			audited:   map[string]interface{}{"limiter": "account_password", "logged_in_user": subject},
			warned:    subjectWarned("account_password"),
			noSubject: noToken(accountOTPRoute),
		},
	}
}

// runBuilt drives one request through a built limiter, recording a credential failure from
// inside the handler when failed is set, and reports whether the handler ran.
func runBuilt(m *RateLimiter, c builtLimiter, req *http.Request, failed bool) (*httptest.ResponseRecorder, bool) {
	rr := httptest.NewRecorder()
	reached := false
	c.limit(m)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		if failed {
			m.RecordCredentialFailure(r)
		}
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rr, req)
	return rr, reached
}

// TestBuiltLimiters_EachKeepsItsOwnRefusal holds the six limiters a builder writes to what each
// of them answered when it was written by hand (#439 decisions 1 and 2): the budget on both sides,
// the refusal shape its caller parses, Retry-After at its own window, the one audit event with
// exactly the identifier that route records, and a warning on every refusal that names a client
// block for a per-IP tier and nobody for a per-subject one. The per-route tests above cover the
// keys; this is the whole refusal, for all six at once, because a builder writes all six and
// one wrong argument at one call site is the defect it makes possible.
func TestBuiltLimiters_EachKeepsItsOwnRefusal(t *testing.T) {
	for _, c := range builtLimiters() {
		t.Run(c.name, func(t *testing.T) {
			t.Run("the budget, then one refusal in its route's shape", func(t *testing.T) {
				logs := logtest.CaptureSlog(t)
				m, auditLog := newAuditedTestMiddleware(stubCeremonyStore{}, true)

				for i := 0; i < c.budget; i++ {
					if rr, reached := runBuilt(m, c, c.request(), c.failures); rr.Code != http.StatusTeapot || !reached {
						t.Fatalf("request %d of a budget of %d: got code %d, handler reached %v; want %d and true",
							i+1, c.budget, rr.Code, reached, http.StatusTeapot)
					}
				}
				for i := 0; i < 2; i++ {
					rr, reached := runBuilt(m, c, c.request(), c.failures)
					if rr.Code != http.StatusTooManyRequests || reached {
						t.Fatalf("request %d: got code %d, handler reached %v; want %d and false",
							c.budget+1+i, rr.Code, reached, http.StatusTooManyRequests)
					}
					if got := rr.Header().Get("Content-Type"); got != c.contentType {
						t.Errorf("Content-Type = %q, want %q", got, c.contentType)
					}
					if got := rr.Header().Get("Cache-Control"); got != "no-store" {
						t.Errorf("Cache-Control = %q, want no-store", got)
					}
					if got := rr.Header().Get("Retry-After"); got != c.retryAfter {
						t.Errorf("Retry-After = %q, want %q", got, c.retryAfter)
					}
					assertNoRateLimitHeaders(t, rr, c.name+" rejection")
				}

				auditLog.mu.Lock()
				events := append([]auditEvent(nil), auditLog.events...)
				auditLog.mu.Unlock()
				if len(events) != 1 {
					t.Fatalf("got %d audit events for two refusals on one key, want exactly 1: %v", len(events), events)
				}
				if events[0].name != audit.EventRateLimitExceeded {
					t.Errorf("event name = %q, want %q", events[0].name, audit.EventRateLimitExceeded)
				}
				if !reflect.DeepEqual(events[0].details, c.audited) {
					t.Errorf("event details = %#v, want %#v", events[0].details, c.audited)
				}
				if events[0].requestId != limiterRequestId {
					t.Errorf("request id on the audited context = %q, want %q", events[0].requestId, limiterRequestId)
				}

				warnings := 0
				for _, logRecord := range logs.Records() {
					if logRecord.Message != "rate limit reached" {
						continue
					}
					warnings++
					if logRecord.Level != slog.LevelWarn {
						t.Errorf("the trip was logged at %v, want WARN", logRecord.Level)
					}
					if !reflect.DeepEqual(logRecord.Attrs, c.warned) {
						t.Errorf("warning attributes = %#v, want %#v", logRecord.Attrs, c.warned)
					}
				}
				if warnings != 2 {
					t.Errorf("got %d rate limit warnings for two refusals, want 2", warnings)
				}
			})

			if c.failures {
				t.Run("a handler that records no failure spends nothing", func(t *testing.T) {
					m := newTestMiddleware(stubCeremonyStore{}, true)
					for i := 0; i < 3*c.budget; i++ {
						if rr, reached := runBuilt(m, c, c.request(), false); rr.Code != http.StatusTeapot || !reached {
							t.Fatalf("request %d with no failure recorded: got code %d, handler reached %v; want %d and true",
								i+1, rr.Code, reached, http.StatusTeapot)
						}
					}
					// The slots the successes held were handed back, so the whole budget of
					// failures is still there.
					for i := 0; i < c.budget; i++ {
						if rr, reached := runBuilt(m, c, c.request(), true); rr.Code != http.StatusTeapot || !reached {
							t.Fatalf("failure %d after the successes: got code %d, handler reached %v; want %d and true",
								i+1, rr.Code, reached, http.StatusTeapot)
						}
					}
				})

				t.Run("a request with no subject reaches the handler", func(t *testing.T) {
					store, _ := c.noSubject()
					m := newTestMiddleware(store, true)
					for i := 0; i < 3*c.budget; i++ {
						_, req := c.noSubject()
						if rr, reached := runBuilt(m, c, req, true); rr.Code != http.StatusTeapot || !reached {
							t.Fatalf("request %d with no subject: got code %d, handler reached %v; want %d and true",
								i+1, rr.Code, reached, http.StatusTeapot)
						}
					}
				})
			}

			t.Run("the limiter switched off", func(t *testing.T) {
				m := newTestMiddleware(stubCeremonyStore{}, false)
				if c.alwaysOn {
					// A tier counting a user already authenticated holds whatever the switch says (#542).
					for i := 0; i < c.budget; i++ {
						if rr, reached := runBuilt(m, c, c.request(), c.failures); rr.Code != http.StatusTeapot || !reached {
							t.Fatalf("request %d of a budget of %d with the limiter off: got code %d, handler reached %v",
								i+1, c.budget, rr.Code, reached)
						}
					}
					if rr, reached := runBuilt(m, c, c.request(), c.failures); rr.Code != http.StatusTooManyRequests || reached {
						t.Fatalf("request %d with the limiter off: got code %d, handler reached %v; want %d and false",
							c.budget+1, rr.Code, reached, http.StatusTooManyRequests)
					}
					return
				}
				for i := 0; i < 3*c.budget; i++ {
					if rr, reached := runBuilt(m, c, c.request(), c.failures); rr.Code != http.StatusTeapot || !reached {
						t.Fatalf("request %d with the limiter off: got code %d, handler reached %v; want %d and true",
							i+1, rr.Code, reached, http.StatusTeapot)
					}
				}
			})
		})
	}
}

// TestRateLimiter_EveryTierLogsUnderAConventionalKey holds the one attribute key in this tree
// that no lint reads. reportTrip appends t.keyField, so the key at that slog call is a field
// value rather than a string literal, and sloglint's key-naming-case reads literals: it cannot
// resolve a runtime value, and reportTrip is listed in core/guard's slogSpreadSites for exactly this
// reason. The key is held here instead, which is the same answer decision 5 gives for a level --
// what the text cannot decide, a test pins at the site.
//
// Over every tier the production constructor builds, found by walking the struct rather than by
// listing them, because a listed set is green on the tier nobody added it to: the two keys a trip
// test can reach today are two of fifteen tiers, and the next tier is what this exists for (#320
// decision 3). The fifteen are ten request tiers and three failures-only ones, plus the two
// failures-only tiers of the password gate, which ratelimit.AccountLimiter counts and accountTiers
// names (#439).
func TestRateLimiter_EveryTierLogsUnderAConventionalKey(t *testing.T) {
	// Decision 3's vocabulary. Spelled out rather than imported: the lint's copy is unexported,
	// and this is deliberately the same rule applied to the one value the lint cannot see.
	conventional := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

	var tiers []foundTier
	collectTierKeyFields(reflect.ValueOf(newTestMiddleware(nil, true)), "middleware",
		&tiers, map[visitedValue]bool{})

	// The count is asserted because a walk that silently stopped matching would pass over an
	// empty set exactly as it passes over a conformant one. It counts instances rather than
	// distinct names, so a second tier carrying a name an earlier one already used is a
	// sixteenth tier here rather than a replacement for the fifteenth.
	if len(tiers) != 15 {
		t.Fatalf("walked %d tiers, expected the 15 the constructor builds: %v", len(tiers), tiers)
	}
	for _, found := range tiers {
		if found.keyField == "" {
			// An account tier's bucket names a person, so it is logged nowhere and carries no
			// key at all. That emptiness is its own invariant and newFailureTier holds it.
			continue
		}
		if !conventional.MatchString(found.keyField) {
			t.Errorf("tier %q at %s logs its bucket under %q, which is not a snake_case attribute "+
				"key; the record would carry a name nothing else in the tree spells that way",
				found.name, found.where, found.keyField)
		}
		if found.keyField == "request_id" || found.keyField == "request-id" || found.keyField == "err" {
			t.Errorf("tier %q at %s logs its bucket under the reserved key %q",
				found.name, found.where, found.keyField)
		}
	}
}

// TestCollectTierKeyFields_ReachesEveryContainerKind is the walk above held to its own claim,
// because the constructor cannot hold it to one: every tier the production middleware builds sits
// behind a pointer or a struct field, so a walk that reached nothing else would pass the test
// beside this one on all thirteen and be silent the day a tier arrives in a slice. Six kinds, a
// duplicated name and a cycle, in a shape built here rather than found.
//
// The duplicate is the half that is not about traversal: two tiers can carry one name, and a
// census keyed by name would report three where there are four, so an invalid key would be
// overwritten by the conformant one declared after it and the count would still be right.
func TestCollectTierKeyFields_ReachesEveryContainerKind(t *testing.T) {
	// Every field here is a container kind the walk must reach, read by reflection and never by
	// selector, so a field deleted for looking unused is a kind this test quietly stops covering.
	//
	//nolint:unused // reflection fixture, read by the walk under test, never by selector
	type holder struct {
		direct       tier
		behind       *tier
		inSlice      []tier
		inArray      [1]*tier
		inMap        map[string]*tier
		inMapKey     map[*tier]bool
		shortView    []tier
		longView     []tier
		anonymous    any
		aliasField   *tier
		aliasElement *tier
		itself       *holder
	}

	// One backing array under two views, the second reaching one element further. They share an
	// address and a type, so an identity taken from the header alone calls the longer one visited
	// and the tier only it holds is walked by nothing.
	backing := []tier{
		{name: "overlap_head", keyField: "session_identifier"},
		{name: "overlap_tail", keyField: "refreshTokenId"},
	}

	// itself points back at the value being walked, which is the shape ratelimit's own types
	// have: without the seen set the walk below does not terminate.
	subject := &holder{
		direct:    tier{name: "direct", keyField: "client_id"},
		behind:    &tier{name: "behind", keyField: "user_id"},
		inSlice:   []tier{{name: "in_slice", keyField: "clientId"}},
		inArray:   [1]*tier{{name: "in_array", keyField: "session_id"}},
		inMap:     map[string]*tier{"only": {name: "in_map", keyField: "code_id"}},
		inMapKey:  map[*tier]bool{{name: "in_map_key", keyField: "keyIdentifier"}: true},
		shortView: backing[:1],
		longView:  backing[:2],
		anonymous: &tier{name: "direct", keyField: "keyId"},
	}
	subject.itself = subject
	// The same two tiers a second time, by pointer. Neither is a new tier, so neither adds an
	// entry: one object reached two ways is one instance, and a walk that marked only the route
	// would report four tiers where the holder has two and fail the count beside it the day
	// anyone held a pointer to a tier the constructor already owns. Declared after the values
	// they alias, so the entry is recorded at the path that owns the tier.
	subject.aliasField = &subject.direct
	subject.aliasElement = &subject.inSlice[0]

	var found []foundTier
	collectTierKeyFields(reflect.ValueOf(subject), "holder", &found, map[visitedValue]bool{})

	keys := map[string]string{}
	for _, one := range found {
		keys[one.where] = one.name + "/" + one.keyField
	}
	want := map[string]string{
		"holder.direct":          "direct/client_id",
		"holder.behind":          "behind/user_id",
		"holder.inSlice[0]":      "in_slice/clientId",
		"holder.inArray[0]":      "in_array/session_id",
		"holder.inMap[0]":        "in_map/code_id",
		"holder.inMapKey[key 0]": "in_map_key/keyIdentifier",
		"holder.shortView[0]":    "overlap_head/session_identifier",
		"holder.longView[1]":     "overlap_tail/refreshTokenId",
		"holder.anonymous":       "direct/keyId",
	}
	if !reflect.DeepEqual(want, keys) {
		t.Errorf("the walk reached %v, expected %v; a kind it does not traverse holds a tier "+
			"whose key nothing here reads", keys, want)
	}
	// Nine entries for nine tiers, two of which are named "direct": the count is of instances,
	// and a census keyed by name would have eight, with the conformant key standing in for the
	// camelCase one beside it. The element the two views share is walked once, at the shorter
	// view where it was reached first, which is what stops a bounded walk double-counting.
	if len(found) != 9 {
		t.Errorf("the walk recorded %d tiers, expected 9: %v", len(found), found)
	}
}

// foundTier is one tier the walk reached, with the path it was reached by. A slice of these
// rather than a map keyed by name, because nothing stops two tiers carrying one name and
// collapsing them would let a later conformant key stand in for an earlier invalid one while the
// count above still read 13.
type foundTier struct {
	where     string
	name      string
	keyField  string
	countedBy countedBy
}

// visitedValue bounds the walk. A value that points back at itself, which ratelimit's do, is
// otherwise a walk with no end; the type rides along with the address because a pointer and a map
// header can hold the same one. A slice marks each element it reaches rather than its header, so
// the address here is an element's for those and the holder is the element type: two views of one
// backing array are the same value at every index they share and different values past that, and
// a mark on the header would call the whole of the longer one visited.
//
// instance separates the mark on a tier itself from the marks on the containers reached along the
// way, and the two have to be separate because they collide: a *tier and the tier it points at
// share an address, so one namespace would let the pointer's own mark answer for the tier and the
// tier would be recorded by nothing. With it, a tier reached twice -- as a field and through a
// pointer to that field, or as a slice element and through a pointer to that element -- is
// recorded once, which is what the count beside it claims to be counting.
//
// Being a map key is also why no field here is ever read by selector: the map's own equality reads
// all three, so dropping one for looking unused would silently merge two distinct visits into one.
//
//nolint:unused // map key, read whole by the map's equality, never by selector
type visitedValue struct {
	address  uintptr
	holder   reflect.Type
	instance bool
}

// collectTierKeyFields walks a value for the tier structs inside it and records each one's name
// against the attribute key it logs its bucket under. Reading an unexported field through reflect
// is allowed; only Interface and Set are not, and this needs neither. The walk stops at a tier,
// which since #439 holds only the HTTP half: the limiter a tier reports for sits beside it, in
// requestTier or failureTier, and the password gate's ratelimit.AccountLimiter beside its two
// tiers in accountTiers. The walk descends into those as it does into anything else and finds no
// tier there, since ratelimit cannot import this package.
//
// Every kind that can hold a tier is traversed, not the pointer and struct fields the constructor
// happens to use today: a tier behind a slice, an array, a map or an interface is as reachable
// from reportTrip as a named field is, and a walk that skipped one would be silent about exactly
// the tier nobody thought to look for, which is the failure this test exists to prevent.
func collectTierKeyFields(v reflect.Value, where string, into *[]foundTier, seen map[visitedValue]bool) {
	// once reports whether this is the first arrival at a value with an identity of its own, so
	// the three reference kinds are each walked at most one time.
	once := func() bool {
		if v.IsNil() {
			return false
		}
		mark := visitedValue{address: v.Pointer(), holder: v.Type()}
		if seen[mark] {
			return false
		}
		seen[mark] = true
		return true
	}

	switch v.Kind() {
	case reflect.Pointer:
		if once() {
			collectTierKeyFields(v.Elem(), where, into, seen)
		}
	case reflect.Interface:
		if !v.IsNil() {
			collectTierKeyFields(v.Elem(), where, into, seen)
		}
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(tier{}) {
			// One entry per tier, not per path to one. An addressable tier has an identity every
			// route to it agrees on, so a field and a pointer to that field are the same object
			// and the second arrival adds nothing. A tier that is not addressable is a copy --
			// out of a map value or an interface -- and is its own object however alike it looks.
			if v.CanAddr() {
				mark := visitedValue{address: v.UnsafeAddr(), holder: v.Type(), instance: true}
				if seen[mark] {
					return
				}
				seen[mark] = true
			}
			*into = append(*into, foundTier{where: where,
				name:      v.FieldByName("name").String(),
				keyField:  v.FieldByName("keyField").String(),
				countedBy: countedBy(v.FieldByName("countedBy").Int())})
			return
		}
		for i := 0; i < v.NumField(); i++ {
			collectTierKeyFields(v.Field(i), where+"."+v.Type().Field(i).Name, into, seen)
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			collectTierKeyFields(v.Index(i), where+"["+strconv.Itoa(i)+"]", into, seen)
		}
	case reflect.Slice:
		if v.IsNil() {
			return
		}
		// A slice is bounded per element rather than per header. Two views of one backing array
		// share a first element and a type, so a mark on the header would read the longer view
		// as already walked and never reach the tail that only it holds.
		stride := v.Type().Elem().Size()
		for i := 0; i < v.Len(); i++ {
			mark := visitedValue{address: v.Pointer() + uintptr(i)*stride, holder: v.Type().Elem()}
			if seen[mark] {
				continue
			}
			seen[mark] = true
			collectTierKeyFields(v.Index(i), where+"["+strconv.Itoa(i)+"]", into, seen)
		}
	case reflect.Map:
		if !once() {
			return
		}
		// Both halves of an entry. A map keyed by a tier or by a pointer to one holds it as
		// reachably as a value does, and reportTrip reads whichever the lookup returns.
		at := 0
		for iter := v.MapRange(); iter.Next(); at++ {
			collectTierKeyFields(iter.Key(), where+"[key "+strconv.Itoa(at)+"]", into, seen)
			collectTierKeyFields(iter.Value(), where+"["+strconv.Itoa(at)+"]", into, seen)
		}
	}
}

// TestLimitDCR_PerIP is LimitDCR's first test, which is half of #195's remainder. RFC
// 7591 section 3 permits rate limiting an unauthenticated registration request "to
// prevent a denial-of-service attack on the client registration endpoint"; the budget
// is exact because it is published policy.
func TestLimitDCR_PerIP(t *testing.T) {
	const budget = 10

	run := func(m *RateLimiter, ip string) (int, bool) {
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
func runROPC(m *RateLimiter, grantType, username, clientId, ip string,
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

	run := func(m *RateLimiter, username, ip string) (int, bool) {
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
		// from one host. implicit, PASSWORD and the empty grant pin the exact, case-sensitive
		// match against oidc.GrantTypePassword, the comparison the validator's grant table
		// applies too (#437).
		for _, grant := range []string{"refresh_token", "authorization_code", "client_credentials",
			"implicit", "PASSWORD", ""} {
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

// TestLimitROPC_AFormThatDoesNotParseIsAnsweredNotForwarded pins the limiter's answer to a token
// request whose form does not parse: the token endpoint's own 400 invalid_request, written here, with
// the handler never run. Forwarding it was the defect. net/http keeps the pairs that did parse and
// answers the handler's own ParseForm with nil, so the handler acted on part of the request: a
// password grant beside one malformed pair reached the password check with neither tier consulted,
// and a parameter whose second copy was malformed passed as sent once (#228, #437).
//
// Each case varies where the malformed bytes sit, so a limiter that judged the body alone, or the
// pairs it read rather than the parse's error, fails one of them. The end-to-end answer, the same
// whether the limiter is on or off, is TestInitRoutes_TokenFormThatDoesNotParse in internal/server.
func TestLimitROPC_AFormThatDoesNotParseIsAnsweredNotForwarded(t *testing.T) {
	const passwordGrant = "grant_type=password&username=victim%40example.com&password=guess"

	tests := []struct {
		name   string
		target string
		body   func(w http.ResponseWriter) io.Reader
	}{
		{"a malformed second copy of a parameter the endpoint reads", "/auth/token", func(http.ResponseWriter) io.Reader {
			return strings.NewReader("grant_type=client_credentials&client_id=app&client_id=%zz&client_secret=s")
		}},
		{"a malformed pair the endpoint ignores, beside a password grant", "/auth/token", func(http.ResponseWriter) io.Reader {
			return strings.NewReader(passwordGrant + "&junk=%zz")
		}},
		{"a malformed query beside a password grant in the body", "/auth/token?junk=%zz", func(http.ResponseWriter) io.Reader {
			return strings.NewReader(passwordGrant)
		}},
		{"a password grant cut one byte short by the request-body limit", "/auth/token", func(w http.ResponseWriter) io.Reader {
			return http.MaxBytesReader(w, io.NopCloser(strings.NewReader(passwordGrant)), int64(len(passwordGrant)-1))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := newTestMiddleware(nil, true)
			rr := httptest.NewRecorder()
			req := limiterRequest(http.MethodPost, test.target, test.body(rr))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			reached := false

			m.LimitROPC(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusTeapot)
			})).ServeHTTP(rr, req)

			if reached {
				t.Fatal("a form that does not parse reached the handler")
			}
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
			}
			for header, want := range map[string]string{
				"Content-Type": "application/json", "Cache-Control": "no-store", "Pragma": "no-cache",
			} {
				if got := rr.Header().Get(header); got != want {
					t.Errorf("%s = %q, want %q", header, got, want)
				}
			}
			var body map[string]string
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("body %q is not JSON: %v", rr.Body.String(), err)
			}
			want := map[string]string{"error": "invalid_request", "error_description": "The request body could not be parsed."}
			if !reflect.DeepEqual(body, want) {
				t.Errorf("body = %v, want %v", body, want)
			}
		})
	}

	// The control: the same bytes well formed are classified and forwarded, so what refused the cases
	// above is the parse failing, not the shape of the request.
	t.Run("the same password grant well formed reaches the handler", func(t *testing.T) {
		m := newTestMiddleware(nil, true)
		req := limiterRequest(http.MethodPost, "/auth/token", strings.NewReader(passwordGrant+"&junk=ok"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		reached := false
		m.LimitROPC(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusTeapot)
		})).ServeHTTP(rr, req)
		if !reached || rr.Code != http.StatusTeapot {
			t.Errorf("got code %d, handler reached %v; want %d and true", rr.Code, reached, http.StatusTeapot)
		}
	})

	// Off, the limiter parses nothing, so the handler is the first to parse and answers the failure
	// itself.
	t.Run("a disabled limiter forwards it to the handler, which parses it first", func(t *testing.T) {
		m := newTestMiddleware(nil, false)
		req := limiterRequest(http.MethodPost, "/auth/token", strings.NewReader(passwordGrant+"&junk=%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		var parseErr error
		m.LimitROPC(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			parseErr = r.ParseForm()
			w.WriteHeader(http.StatusTeapot)
		})).ServeHTTP(rr, req)
		if rr.Code != http.StatusTeapot || parseErr == nil {
			t.Errorf("got code %d, handler's ParseForm error %v; want %d and the parse error", rr.Code, parseErr, http.StatusTeapot)
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
	// The password grant spends the sign-in form's bucket, and its trip records the username as
	// that form's trip records the address: its digest, normalized as the grant's lookup
	// normalizes it (#522 decision 10). SHA-256 of "victim@example.com", computed outside this
	// code.
	t.Run("the trip records the username as its digest", func(t *testing.T) {
		m, auditLog := newAuditedTestMiddleware(nil, true)
		for i := 0; i < tightBudget+1; i++ {
			runROPC(m, "password", " Victim@Example.com", "app", attacker, true)
		}
		auditLog.mu.Lock()
		events := append([]auditEvent(nil), auditLog.events...)
		auditLog.mu.Unlock()
		want := map[string]interface{}{
			"limiter":      "pwd_account_net",
			"email_digest": "ffbe8cff4f9f8d8b109460f975c343e942cd4c3ed191323eb83374ae2ea4de5f",
			"ip":           "203.0.113.7",
		}
		if len(events) != 1 || !reflect.DeepEqual(events[0].details, want) {
			t.Errorf("audited %v, want one event with details %v", events, want)
		}
	})

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
