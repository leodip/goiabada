package middleware

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
)

// countingStore stands for the database the five credential tiers count in on PostgreSQL, MySQL and
// SQL Server. It keeps one count per key and applies the limiter's own admit rule to it, which is
// the contract of data.Database's ReserveRateLimitHit; the atomicity across handles behind that
// contract is the data tier's to prove, on every engine, and is not restated here. Windows are not
// modelled: every case here runs well inside one.
//
// It records every key a reservation was asked for and every refund, with whether the refund's
// context had already ended when it arrived.
type countingStore struct {
	mu       sync.Mutex
	hits     map[string]int
	reserved []string
	refunds  []storeRefund

	// reserveErr and refundErr, when set, are what every reservation and every refund answer.
	reserveErr error
	refundErr  error
}

type storeRefund struct {
	keyHash string
	ctxErr  error
}

func newCountingStore() *countingStore {
	return &countingStore{hits: map[string]int{}}
}

func (s *countingStore) ReserveRateLimitHit(ctx context.Context, keyHash string, current, previous, expiresAt time.Time,
	admit func(curr, prev int) bool) (bool, error) {

	s.mu.Lock()
	defer s.mu.Unlock()
	s.reserved = append(s.reserved, keyHash)
	if s.reserveErr != nil {
		return false, s.reserveErr
	}
	if !admit(s.hits[keyHash], 0) {
		return false, nil
	}
	s.hits[keyHash]++
	return true, nil
}

func (s *countingStore) RefundRateLimitHit(ctx context.Context, tx *sql.Tx, keyHash string, windowStart time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refunds = append(s.refunds, storeRefund{keyHash: keyHash, ctxErr: ctx.Err()})
	if s.refundErr != nil {
		return s.refundErr
	}
	if s.hits[keyHash] > 0 {
		s.hits[keyHash]--
	}
	return nil
}

func (s *countingStore) reservedKeys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := append([]string(nil), s.reserved...)
	sort.Strings(keys)
	return keys
}

func (s *countingStore) recordedRefunds() []storeRefund {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]storeRefund(nil), s.refunds...)
}

// sharedKey is the key a tier's bucket is counted under at rest, as #394 decision 3 states it: the
// SHA-256 of the tier name, a NUL and the key, in lowercase hex. Written from the decision rather
// than read off the limiter, so a tier counted under another name, or a key stored raw, fails here.
func sharedKey(tier, key string) string {
	sum := sha256.Sum256([]byte(tier + "\x00" + key))
	return hex.EncodeToString(sum[:])
}

// newSharedTestMiddleware is the middleware a server on PostgreSQL, MySQL or SQL Server builds: the
// credential tiers count in store, everything else in memory.
func newSharedTestMiddleware(store credentialCounter) (*RateLimiter, *stubAuditLogger) {
	auditLog := &stubAuditLogger{}
	httpHelper := render.New(testTemplateFS)
	return NewRateLimiter(stubCeremonyStore{}, httpHelper, httpHelper, auditLog, true, store, metrics.NewRegistry()), auditLog
}

const sharedTestSubject = "22222222-2222-2222-2222-222222222222"

// credentialRoute is one of the five routes whose credential check a shared tier bounds, and what a
// fault there answers in.
type credentialRoute struct {
	name  string
	limit func(m *RateLimiter) func(http.Handler) http.Handler
	// request builds the route's request, keyed on alice@example.com from 203.0.113.7 on the two
	// password routes, on user 7 at the OTP step, and on sharedTestSubject at the account API.
	request func() *http.Request
	// keys are the buckets the check spends, as decision 3 counts them.
	keys []string
	// shape is the 500's: the error page, RFC 6749's server_error, or the API envelope.
	shape rejectClass
	// faultTier is the tier the store fault is reported against: the first one the route asks.
	faultTier string
}

func credentialRoutes() []credentialRoute {
	const ip = "203.0.113.7"
	const email = "alice@example.com"
	passwordKeys := []string{
		sharedKey("pwd_account_net", ip+"|"+email),
		sharedKey("pwd_account", email),
	}
	return []credentialRoute{
		{
			name:  "LimitPwd",
			limit: func(m *RateLimiter) func(http.Handler) http.Handler { return m.LimitPwd },
			request: func() *http.Request {
				form := url.Values{"email": {email}}
				req := limiterRequest(http.MethodPost, "/auth/pwd", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.RemoteAddr = ip + ":5000"
				return req
			},
			keys: passwordKeys, shape: rejectBrowser, faultTier: "pwd_account_net",
		},
		{
			// The password grant spends the very buckets the form does, so the same two keys.
			name:  "LimitROPC",
			limit: func(m *RateLimiter) func(http.Handler) http.Handler { return m.LimitROPC },
			request: func() *http.Request {
				form := url.Values{"grant_type": {"password"}, "username": {email}, "client_id": {"c1"}}
				req := limiterRequest(http.MethodPost, "/auth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.RemoteAddr = ip + ":5000"
				return req
			},
			keys: passwordKeys, shape: rejectOAuth, faultTier: "pwd_account_net",
		},
		{
			name:      "LimitOtp",
			limit:     func(m *RateLimiter) func(http.Handler) http.Handler { return m.LimitOtp },
			request:   func() *http.Request { return limiterRequest(http.MethodPost, "/auth/otp?userId=7", nil) },
			keys:      []string{sharedKey("otp", "user_7")},
			shape:     rejectBrowser,
			faultTier: "otp",
		},
		{
			name:      "LimitEmailVerification",
			limit:     func(m *RateLimiter) func(http.Handler) http.Handler { return m.LimitEmailVerification },
			request:   func() *http.Request { return verificationRequest(sharedTestSubject) },
			keys:      []string{sharedKey("email_verification", sharedTestSubject)},
			shape:     rejectAPI,
			faultTier: "email_verification",
		},
		{
			name:      "LimitAccountPassword",
			limit:     func(m *RateLimiter) func(http.Handler) http.Handler { return m.LimitAccountPassword },
			request:   func() *http.Request { return accountPasswordRequest(accountPasswordRoute, sharedTestSubject) },
			keys:      []string{sharedKey("account_password", sharedTestSubject)},
			shape:     rejectAPI,
			faultTier: "account_password",
		},
	}
}

// runCredential drives one request through a route's limiter, recording a credential failure from
// inside the handler when failed is set, and reports whether the handler ran.
func runCredential(m *RateLimiter, route credentialRoute, req *http.Request, failed bool) (*httptest.ResponseRecorder, bool) {
	rr := httptest.NewRecorder()
	reached := false
	route.limit(m)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		if failed {
			m.RecordCredentialFailure(r)
		}
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rr, req)
	return rr, reached
}

// TestSharedCredentialTiers_CountInTheStoreUnderTheirDigestedKeys is #394 decision 1's line between
// the tiers: the five credential tiers, and only they, count in the store a server engine hands the
// limiter, each under decision 3's digest of its own name and key. The per-IP and mail tiers stay in
// this process, so a flood costs the database nothing.
func TestSharedCredentialTiers_CountInTheStoreUnderTheirDigestedKeys(t *testing.T) {
	for _, route := range credentialRoutes() {
		t.Run(route.name, func(t *testing.T) {
			store := newCountingStore()
			m, _ := newSharedTestMiddleware(store)

			rr, reached := runCredential(m, route, route.request(), true)
			if rr.Code != http.StatusTeapot || !reached {
				t.Fatalf("got code %d, handler reached %v; want %d and true", rr.Code, reached, http.StatusTeapot)
			}

			want := append([]string(nil), route.keys...)
			sort.Strings(want)
			if got := store.reservedKeys(); !reflect.DeepEqual(got, want) {
				t.Errorf("the store was asked for %v, want exactly the route's credential buckets %v", got, want)
			}
		})
	}

	t.Run("the per-IP and mail tiers never reach the store", func(t *testing.T) {
		store := newCountingStore()
		m, _ := newSharedTestMiddleware(store)

		for _, c := range builtLimiters() {
			if c.failures {
				continue
			}
			if rr, reached := runBuilt(m, c, c.request(), false); rr.Code != http.StatusTeapot || !reached {
				t.Fatalf("%s: got code %d, handler reached %v; want %d and true", c.name, rr.Code, reached, http.StatusTeapot)
			}
		}
		_, _, _ = runVerificationSend(m, sharedTestSubject)
		forgot := url.Values{"email": {"alice@example.com"}}
		for _, limit := range []func(http.Handler) http.Handler{m.LimitForgotPwd, m.LimitRegister} {
			req := limiterRequest(http.MethodPost, "/forgot-password", strings.NewReader(forgot.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)
		}

		if got := store.reservedKeys(); len(got) != 0 {
			t.Errorf("a per-pod tier asked the store for %v; only the five credential tiers count there", got)
		}
	})
}

// TestSharedCredentialTiers_TwoInstancesSpendOneBudget is the property the store exists for, at the
// middleware: two limiters over one store stand for two pods behind one Service, and failures
// alternated between them spend one budget, refused on the sixth with the tier's ordinary trip.
func TestSharedCredentialTiers_TwoInstancesSpendOneBudget(t *testing.T) {
	store := newCountingStore()
	pods := []*RateLimiter{}
	audits := []*stubAuditLogger{}
	for i := 0; i < 2; i++ {
		m, auditLog := newSharedTestMiddleware(store)
		pods = append(pods, m)
		audits = append(audits, auditLog)
	}

	for i := 0; i < 5; i++ {
		code, reached, _ := runAccountPassword(pods[i%2], accountPasswordRoute, sharedTestSubject, true)
		if code != http.StatusTeapot || !reached {
			t.Fatalf("failure %d of a budget of 5, on pod %d: got code %d, handler reached %v", i+1, i%2, code, reached)
		}
	}
	for i := 0; i < 2; i++ {
		code, reached, rr := runAccountPassword(pods[i], accountPasswordRoute, sharedTestSubject, true)
		if code != http.StatusTooManyRequests || reached {
			t.Fatalf("failure 6 on pod %d: got code %d, handler reached %v; want 429 and false; "+
				"each pod is counting a budget of its own", i, code, reached)
		}
		if got := rr.Header().Get("Retry-After"); got != "900" {
			t.Errorf("Retry-After = %q, want 900", got)
		}
	}
	for i, auditLog := range audits {
		if got := auditLog.count(audit.EventRateLimitExceeded); got != 1 {
			t.Errorf("pod %d audited %d trips, want 1: the gate stays per pod", i, got)
		}
	}
}

// TestSharedCredentialTiers_KeepTheirBudgetsAndSpendOnlyFailures holds the shared tiers to what the
// in-memory ones answer: the published budget on both sides, and a successful check that spends
// nothing once its charge is refunded.
func TestSharedCredentialTiers_KeepTheirBudgetsAndSpendOnlyFailures(t *testing.T) {
	budgets := map[string]int{
		"LimitPwd": 10, "LimitROPC": 10, "LimitOtp": 5, "LimitEmailVerification": 5, "LimitAccountPassword": 5,
	}
	for _, route := range credentialRoutes() {
		t.Run(route.name, func(t *testing.T) {
			store := newCountingStore()
			m, _ := newSharedTestMiddleware(store)
			budget := budgets[route.name]

			// One budget of successes, not more: the two password routes also carry a per-IP tier
			// of 30 a minute that every request spends, these included.
			for i := 0; i < budget; i++ {
				if rr, reached := runCredential(m, route, route.request(), false); rr.Code != http.StatusTeapot || !reached {
					t.Fatalf("success %d: got code %d, handler reached %v; want %d and true", i+1, rr.Code, reached, http.StatusTeapot)
				}
			}
			for i := 0; i < budget; i++ {
				if rr, reached := runCredential(m, route, route.request(), true); rr.Code != http.StatusTeapot || !reached {
					t.Fatalf("failure %d of %d after the successes: got code %d, handler reached %v",
						i+1, budget, rr.Code, reached)
				}
			}
			if rr, reached := runCredential(m, route, route.request(), true); rr.Code != http.StatusTooManyRequests || reached {
				t.Fatalf("failure %d: got code %d, handler reached %v; want 429 and false", budget+1, rr.Code, reached)
			}
		})
	}
}

// TestSharedCredentialTiers_AStoreFaultIsAServerFault is #394 decision 4 at the middleware: a count
// that cannot be read is answered as the fault it is, the 500 the route's caller parses, and not as
// a trip. A 429 would send a client into a backoff loop and fill the audit log with false trips
// during an outage, so there is no Retry-After, no "rate limit reached" warning and no audit event,
// and the one record is the Error the route's 500 owes, naming the shared tier that failed. The
// credential check is never reached, which is fail closed (#276).
func TestSharedCredentialTiers_AStoreFaultIsAServerFault(t *testing.T) {
	for _, route := range credentialRoutes() {
		t.Run(route.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			store := newCountingStore()
			store.reserveErr = errors.New("connection refused")
			m, auditLog := newSharedTestMiddleware(store)

			// Twice, so a fault that a second request turned into a trip would show.
			for i := 0; i < 2; i++ {
				rr, reached := runCredential(m, route, route.request(), true)
				if rr.Code != http.StatusInternalServerError || reached {
					t.Fatalf("request %d: got code %d, handler reached %v; want 500 and false", i+1, rr.Code, reached)
				}
				if got := rr.Header().Get("Retry-After"); got != "" {
					t.Errorf("Retry-After = %q on a fault, want it absent", got)
				}
				assertServerFaultShape(t, rr, route.shape)
			}

			if got := auditLog.count(audit.EventRateLimitExceeded); got != 0 {
				t.Errorf("a store fault audited %d rate-limit trips, want none", got)
			}
			errorRecords := 0
			for _, record := range logs.Records() {
				if record.Message == "rate limit reached" {
					t.Errorf("a store fault logged the trip warning %v", record.Attrs)
				}
				if record.Level < slog.LevelError {
					continue
				}
				errorRecords++
				text := fmt.Sprint(record.Attrs["error"])
				if !strings.Contains(text, "shared "+route.faultTier+" rate limit") ||
					!strings.Contains(text, "connection refused") {
					t.Errorf("the Error record's error is %q, want it to name the shared %s rate limit and the cause",
						text, route.faultTier)
				}
			}
			if errorRecords != 2 {
				t.Errorf("got %d Error records for two faulted requests, want exactly one each", errorRecords)
			}
		})
	}
}

// assertServerFaultShape checks the 500 is the one the route already answers a fault in: the error
// page for a browser form, RFC 6749 section 5.2's server_error for the token endpoint, and the API's
// INTERNAL_SERVER_ERROR envelope for the account API.
func assertServerFaultShape(t *testing.T, rr *httptest.ResponseRecorder, shape rejectClass) {
	t.Helper()
	switch shape {
	case rejectBrowser:
		if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
			t.Errorf("Content-Type = %q, want the error page", got)
		}
		if !strings.Contains(rr.Body.String(), `id="requestId">`+limiterRequestId) {
			t.Errorf("the body is not the error page carrying the request id:\n%s", rr.Body.String())
		}
	case rejectOAuth:
		var body map[string]string
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("body is not JSON: %v\nbody: %s", err, rr.Body.String())
		}
		if body["error"] != "server_error" {
			t.Errorf(`error = %q, want "server_error"`, body["error"])
		}
	case rejectAPI:
		var body struct {
			ErrorCode string `json:"error_code"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("body is not JSON: %v\nbody: %s", err, rr.Body.String())
		}
		if body.ErrorCode != "INTERNAL_SERVER_ERROR" {
			t.Errorf(`error_code = %q, want "INTERNAL_SERVER_ERROR"`, body.ErrorCode)
		}
	}
}

// TestSharedCredentialTiers_TheRefundOutlivesTheRequestsCancellation: a client that hangs up after a
// right credential does not leave its charge behind. The refund reaches the store on a context that
// has not ended, and the bucket is back where it was (#394 decision 4).
func TestSharedCredentialTiers_TheRefundOutlivesTheRequestsCancellation(t *testing.T) {
	for _, route := range credentialRoutes() {
		t.Run(route.name, func(t *testing.T) {
			store := newCountingStore()
			m, _ := newSharedTestMiddleware(store)

			req := route.request()
			ctx, cancel := context.WithCancel(req.Context())
			defer cancel()
			req = req.WithContext(ctx)

			route.limit(m)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cancel()
				w.WriteHeader(http.StatusTeapot)
			})).ServeHTTP(httptest.NewRecorder(), req)

			refunds := store.recordedRefunds()
			if len(refunds) != len(route.keys) {
				t.Fatalf("got %d refunds, want one per bucket reserved (%d)", len(refunds), len(route.keys))
			}
			for _, refund := range refunds {
				if refund.ctxErr != nil {
					t.Errorf("the refund of %s reached the store on an ended context: %v", refund.keyHash, refund.ctxErr)
				}
			}
			for _, key := range route.keys {
				if got := store.hits[key]; got != 0 {
					t.Errorf("bucket %s holds %d after a right credential, want 0", key, got)
				}
			}
		})
	}
}

// TestSharedCredentialTiers_AFailedRefundIsOneErrorAndTheResponseStands: a refund the store refuses
// leaves the charge in place, the refusing direction, records one Error, and changes nothing the
// client already has.
func TestSharedCredentialTiers_AFailedRefundIsOneErrorAndTheResponseStands(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	store := newCountingStore()
	store.refundErr = errors.New("connection reset")
	m, auditLog := newSharedTestMiddleware(store)

	code, reached, _ := runAccountPassword(m, accountPasswordRoute, sharedTestSubject, false)
	if code != http.StatusTeapot || !reached {
		t.Fatalf("got code %d, handler reached %v; want the handler's own %d", code, reached, http.StatusTeapot)
	}
	if got := store.hits[sharedKey("account_password", sharedTestSubject)]; got != 1 {
		t.Errorf("the bucket holds %d after a refused refund, want the charge kept (1)", got)
	}
	if got := auditLog.count(audit.EventRateLimitExceeded); got != 0 {
		t.Errorf("a refused refund audited %d trips, want none", got)
	}
	errorRecords := 0
	for _, record := range logs.Records() {
		if record.Level >= slog.LevelError {
			errorRecords++
			if text := fmt.Sprint(record.Attrs["error"]); !strings.Contains(text, "connection reset") {
				t.Errorf("the Error record's error is %q, want the refund's cause", text)
			}
		}
	}
	if errorRecords != 1 {
		t.Errorf("got %d Error records, want 1", errorRecords)
	}
}
