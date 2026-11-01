package middleware

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/clientauth"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// The rate limiter's side of the client authentication limit (#707 decisions 1, 5, 7 and 11): the
// client_auth tier, spent through ReserveSecretCheck, the port client authentication declares.
// Budgets and records are literals from the agreement: 200 failed secret checks per client per 60
// minutes, Retry-After 3600, the limiter named client_auth.

var _ clientauth.SecretCheckLimiter = (*RateLimiter)(nil)

// checkSecret is one secret check as client authentication makes it: a reservation for client,
// released at once with failed. It answers the reservation's error, nil when the check went ahead.
func checkSecret(m *RateLimiter, client string, failed bool) error {
	held, err := m.ReserveSecretCheck(context.Background(), client)
	if err != nil {
		return err
	}
	held.Release(context.Background(), failed)
	return nil
}

func requireLimitReached(t *testing.T, err error) {
	t.Helper()
	var limitReached *clientauth.LimitReachedError
	require.ErrorAs(t, err, &limitReached)
	assert.Equal(t, 3600*time.Second, limitReached.RetryAfter)
}

// The switch is off in each of these: the limit applies whatever it says (decision 5).
func TestClientAuthLimit_TwoHundredFailuresPerClientPerHour(t *testing.T) {
	m, _, _ := newMeteredTestMiddleware(nil, false)

	for i := 1; i <= 200; i++ {
		require.NoError(t, checkSecret(m, "client-a", true), "failed check %d is within the budget", i)
	}

	// The 201st is refused whatever its secret would have been: the right one is refused too.
	requireLimitReached(t, checkSecret(m, "client-a", false))
	requireLimitReached(t, checkSecret(m, "client-a", true))

	// Another client's budget is its own.
	require.NoError(t, checkSecret(m, "client-b", true))
	require.NoError(t, checkSecret(m, "client-b", false))
}

func TestClientAuthLimit_ARightSecretSpendsNothing(t *testing.T) {
	m, _, _ := newMeteredTestMiddleware(nil, false)

	for i := 0; i < 300; i++ {
		require.NoError(t, checkSecret(m, "client-a", false))
	}
	for i := 1; i <= 200; i++ {
		require.NoError(t, checkSecret(m, "client-a", true), "failed check %d after 300 right secrets", i)
	}
	requireLimitReached(t, checkSecret(m, "client-a", false))
}

// A check in flight holds its slot, so concurrent checks cannot all read a budget with one left.
func TestClientAuthLimit_AHeldReservationCountsAgainstTheBudget(t *testing.T) {
	m, _, _ := newMeteredTestMiddleware(nil, false)

	for i := 0; i < 199; i++ {
		require.NoError(t, checkSecret(m, "client-a", true))
	}
	held, err := m.ReserveSecretCheck(context.Background(), "client-a")
	require.NoError(t, err)
	_, err = m.ReserveSecretCheck(context.Background(), "client-a")
	requireLimitReached(t, err)

	held.Release(context.Background(), false)
	require.NoError(t, checkSecret(m, "client-a", true), "the refunded slot is free again")
}

// Every refusal writes the warning and is counted; the audit event is written once per client per
// window, and carries the client's identifier and the limiter.
func TestClientAuthLimit_ARefusalLeavesTheRateLimitersRecords(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	m, auditLog, reg := newMeteredTestMiddleware(nil, false)

	for i := 0; i < 200; i++ {
		require.NoError(t, checkSecret(m, "client-a", true))
	}
	require.Empty(t, auditLog.events, "nothing is audited within the budget")
	for i := 0; i < 3; i++ {
		requireLimitReached(t, checkSecret(m, "client-a", true))
	}

	warnings := 0
	for _, record := range logs.Records() {
		if record.Message == "rate limit reached" {
			warnings++
			assert.Equal(t, slog.LevelWarn, record.Level)
			assert.Equal(t, "client_auth", record.Attrs["limiter"])
		}
	}
	assert.Equal(t, 3, warnings, "one warning per refusal")

	auditLog.mu.Lock()
	events := append([]auditEvent(nil), auditLog.events...)
	auditLog.mu.Unlock()
	require.Len(t, events, 1, "one audit event per client per window")
	assert.Equal(t, audit.EventRateLimitExceeded, events[0].name)
	assert.Equal(t, map[string]interface{}{"limiter": "client_auth", "client_identifier": "client-a"}, events[0].details)

	assert.Equal(t, everyLimiterAtZeroBut(t, reg, map[string]string{"client_auth": "3"}), refusalCounts(t, reg))

	// A second client's trip is audited too.
	for i := 0; i < 201; i++ {
		_ = checkSecret(m, "client-b", true)
	}
	assert.Equal(t, 2, auditLog.count(audit.EventRateLimitExceeded))
}

// On PostgreSQL, MySQL and SQL Server the tier counts in the database, under the digest of its name
// and the client's identifier, so every replica spends one budget (decision 11).
func TestClientAuthLimit_CountsInTheSharedStore(t *testing.T) {
	store := newCountingStore()
	one, _ := newSharedTestMiddleware(store)
	two, _ := newSharedTestMiddleware(store)

	for i := 0; i < 100; i++ {
		require.NoError(t, checkSecret(one, "client-a", true))
		require.NoError(t, checkSecret(two, "client-a", true))
	}
	requireLimitReached(t, checkSecret(one, "client-a", false))
	requireLimitReached(t, checkSecret(two, "client-a", false))

	for _, key := range store.reservedKeys() {
		require.Equal(t, sharedKey("client_auth", "client-a"), key)
	}
	assert.Len(t, store.reservedKeys(), 202)

	// A right secret is refunded from the store.
	require.NoError(t, checkSecret(one, "client-b", false))
	refunds := store.recordedRefunds()
	require.Len(t, refunds, 1)
	assert.Equal(t, sharedKey("client_auth", "client-b"), refunds[0].keyHash)
}

// A count the store cannot read is a fault: an error that is no limit, no warning, no audit event
// and no refusal counted (the assumed fault rule of #707).
func TestClientAuthLimit_AStoreFaultIsNoRefusal(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	store := newCountingStore()
	store.reserveErr = errors.New("connection refused")
	m, auditLog := newSharedTestMiddleware(store)

	held, err := m.ReserveSecretCheck(context.Background(), "client-a")
	require.Error(t, err)
	assert.Nil(t, held)
	assert.Contains(t, err.Error(), "connection refused")
	var limitReached *clientauth.LimitReachedError
	assert.NotErrorAs(t, err, &limitReached)

	assert.Zero(t, auditLog.count(audit.EventRateLimitExceeded))
	for _, record := range logs.Records() {
		assert.NotEqual(t, "rate limit reached", record.Message)
	}
}

// A refund the store does not take is logged as an Error, as every credential reservation's is.
func TestClientAuthLimit_AFailedRefundIsLogged(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	store := newCountingStore()
	store.refundErr = errors.New("connection reset")
	m, _ := newSharedTestMiddleware(store)

	require.NoError(t, checkSecret(m, "client-a", false))

	errorRecords := 0
	for _, record := range logs.Records() {
		if record.Level >= slog.LevelError {
			errorRecords++
			assert.Contains(t, fmt.Sprint(record.Attrs["error"]), "connection reset")
		}
	}
	assert.Equal(t, 1, errorRecords)
}

// WriteOAuthRateLimitRefusal is the token endpoint's 429, as its limiters answer it.
func TestWriteOAuthRateLimitRefusal(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteOAuthRateLimitRefusal(rr, limiterRequest(http.MethodPost, "/auth/token", nil), time.Hour)

	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	assert.Equal(t, "3600", rr.Header().Get("Retry-After"))
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.JSONEq(t, `{"error":"invalid_request","error_description":"Too many requests. Please wait and try again later."}`,
		strings.TrimSpace(rr.Body.String()))
}
