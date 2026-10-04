package datatests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The shared credential budget (#394 decisions 1 to 4). Two limiters on two database handles
// stand for two pods: whatever one spends, the other sees, and between them they admit one
// budget, not two. The limiters read the real clock, so they run in day-long windows, which a
// run of a few seconds straddles about once a year; the window arithmetic itself is walked on
// a fake clock in the ratelimit package's unit tier. The data methods below it are driven with
// explicit windows instead, which is how a roll, a refund across it and the sweep are reached
// on every engine without waiting for one.

// sharedTestWindow is long enough that a test reading the real clock stays in one window.
const sharedTestWindow = 24 * time.Hour

// newSharedTier names a tier no other test or run has written, so counts start at zero on the
// server engines, whose database outlives a test.
func newSharedTier() string {
	return "test_" + fake.LetterN(16)
}

// counterKeyHash is the digest the shared limiter keys the table with: SHA-256 over the tier
// name, a NUL and the key, in lowercase hex. Written out here from the rule rather than taken
// from the package, so the test reads the row the rule names.
func counterKeyHash(tier, key string) string {
	sum := sha256.Sum256([]byte(tier + "\x00" + key))
	return hex.EncodeToString(sum[:])
}

// currentSharedWindow is the start of the window the real clock is in, aligned to the epoch.
func currentSharedWindow() time.Time {
	return time.Unix(0, 0).UTC().Add(time.Since(time.Unix(0, 0)).Truncate(sharedTestWindow))
}

// TestSharedFailureLimiter_TwoHandlesAdmitExactlyOneBudgetBetweenThem is the property the table
// exists for. Forty callers, twenty through each handle, reserve against one key at once and
// hold what they get, so nothing is ever refunded and the charge taken at reservation is the
// only thing standing between the budget and the forty. A store that read, decided and then
// wrote, or that counted per handle, admits more.
func TestSharedFailureLimiter_TwoHandlesAdmitExactlyOneBudgetBetweenThem(t *testing.T) {
	second := secondDatabase(t)
	ctx := context.Background()

	const budget = 10
	tier := newSharedTier()
	podA := ratelimit.NewSharedFailureLimiter(database, tier, budget, sharedTestWindow)
	podB := ratelimit.NewSharedFailureLimiter(second, tier, budget, sharedTestWindow)
	key := fake.Email()

	const callersPerPod = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	var held []*ratelimit.Reservation
	var failures []error
	start := make(chan struct{})
	for i := 0; i < 2*callersPerPod; i++ {
		pod := podA
		if i%2 == 1 {
			pod = podB
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, err := pod.Reserve(ctx, key)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures = append(failures, err)
			}
			if r != nil {
				held = append(held, r)
			}
		}()
	}
	close(start)
	wg.Wait()

	require.Empty(t, failures, "no reservation may fail: the store answers every one")
	assert.Len(t, held, budget, "two pods admitted %d of %d concurrent reservations, want exactly the budget of %d",
		len(held), 2*callersPerPod, budget)

	for _, pod := range []*ratelimit.FailureLimiter{podA, podB} {
		r, err := pod.Reserve(ctx, key)
		require.NoError(t, err)
		assert.Nil(t, r, "a reservation past the budget was admitted")
	}

	// Every check turned out right: the refunds hand the whole budget back.
	for _, r := range held {
		require.NoError(t, r.Release(ctx, false))
	}
	curr, _, err := database.GetRateLimitCounts(ctx, nil, counterKeyHash(tier, key),
		currentSharedWindow(), currentSharedWindow().Add(-sharedTestWindow))
	require.NoError(t, err)
	assert.Equal(t, 0, curr, "the refunds left hits behind")
}

// TestSharedFailureLimiter_ASuccessSpendsNothingOnceReleasedOnEitherHandle: successes through
// both handles, many times the budget, spend none of it; failures through either spend it for
// both.
func TestSharedFailureLimiter_ASuccessSpendsNothingOnceReleasedOnEitherHandle(t *testing.T) {
	second := secondDatabase(t)
	ctx := context.Background()

	tier := newSharedTier()
	pods := []*ratelimit.FailureLimiter{
		ratelimit.NewSharedFailureLimiter(database, tier, 3, sharedTestWindow),
		ratelimit.NewSharedFailureLimiter(second, tier, 3, sharedTestWindow),
	}
	key := fake.Email()

	for i := 0; i < 10; i++ {
		r, err := pods[i%2].Reserve(ctx, key)
		require.NoError(t, err)
		require.NotNil(t, r, "successful check #%d refused: a success spends nothing", i+1)
		require.NoError(t, r.Release(ctx, false))
	}
	for i := 0; i < 3; i++ {
		r, err := pods[i%2].Reserve(ctx, key)
		require.NoError(t, err)
		require.NotNil(t, r, "failure #%d refused, want admitted: the budget is 3", i+1)
		require.NoError(t, r.Release(ctx, true))
	}
	for i, pod := range pods {
		r, err := pod.Reserve(ctx, key)
		require.NoError(t, err)
		assert.Nil(t, r, "handle %d admitted a fourth failure against a shared budget of 3", i+1)
	}
}

// TestSharedAccountLimiter_TheBackstopIsOneCeilingAcrossHandles is NIST SP 800-63B's
// account-wide ceiling held across pods: failures from fresh networks, alternating handles,
// meet one backstop.
func TestSharedAccountLimiter_TheBackstopIsOneCeilingAcrossHandles(t *testing.T) {
	second := secondDatabase(t)
	ctx := context.Background()

	tightTier, backstopTier := newSharedTier(), newSharedTier()
	pods := []*ratelimit.AccountLimiter{
		ratelimit.NewAccountLimiter(
			ratelimit.NewSharedFailureLimiter(database, tightTier, 2, sharedTestWindow),
			ratelimit.NewSharedFailureLimiter(database, backstopTier, 3, sharedTestWindow)),
		ratelimit.NewAccountLimiter(
			ratelimit.NewSharedFailureLimiter(second, tightTier, 2, sharedTestWindow),
			ratelimit.NewSharedFailureLimiter(second, backstopTier, 3, sharedTestWindow)),
	}
	account := fake.Email()

	for i := 0; i < 3; i++ {
		network := fake.IPv4Address() + "|" + account
		r, refusal, err := pods[i%2].Reserve(ctx, network, account)
		require.NoError(t, err)
		require.Equal(t, ratelimit.Admitted, refusal, "failure #%d from a fresh network", i+1)
		require.NoError(t, r.Release(ctx, true))
	}

	network := fake.IPv4Address() + "|" + account
	for i, pod := range pods {
		r, refusal, err := pod.Reserve(ctx, network, account)
		require.NoError(t, err)
		assert.Nil(t, r)
		assert.Equal(t, ratelimit.RefusedBackstop, refusal,
			"handle %d: a fourth failure against an account-wide budget of 3", i+1)
	}
	// The refused attempt from the fresh network spent nothing on its tight tier.
	curr, _, err := database.GetRateLimitCounts(ctx, nil, counterKeyHash(tightTier, network),
		currentSharedWindow(), currentSharedWindow().Add(-sharedTestWindow))
	require.NoError(t, err)
	assert.Equal(t, 0, curr, "a backstop refusal left its tight charge behind")
}

// rateLimitWindows are three consecutive windows far from the real clock, so no limiter reading
// it touches these rows.
func rateLimitWindows() (w0, w1, w2 time.Time) {
	w0 = time.Date(2031, 3, 1, 9, 0, 0, 0, time.UTC)
	return w0, w0.Add(15 * time.Minute), w0.Add(30 * time.Minute)
}

// newCounterKeyHash is a key digest no other test has written.
func newCounterKeyHash() string {
	return counterKeyHash(newSharedTier(), fake.Email())
}

// admitAll admits every reservation and records the counts it was last shown.
type admitAll struct{ curr, prev int }

func (a *admitAll) admit(curr, prev int) bool {
	a.curr, a.prev = curr, prev
	return true
}

// TestRateLimitCounters_TheWindowRollsAndThePreviousIsRead: hits charged in one window are the
// current count while it lasts and the previous count through the next, which is what the
// decayed rate is computed from.
func TestRateLimitCounters_TheWindowRollsAndThePreviousIsRead(t *testing.T) {
	ctx := context.Background()
	w0, w1, w2 := rateLimitWindows()
	keyHash := newCounterKeyHash()
	seen := &admitAll{}

	for i := 0; i < 2; i++ {
		ok, err := database.ReserveRateLimitHit(ctx, keyHash, w0, w0.Add(-15*time.Minute), w2, seen.admit)
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, [2]int{i, 0}, [2]int{seen.curr, seen.prev},
			"reservation #%d in the first window was shown (curr, prev)", i+1)
	}

	ok, err := database.ReserveRateLimitHit(ctx, keyHash, w1, w0, w1.Add(30*time.Minute), seen.admit)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, [2]int{0, 2}, [2]int{seen.curr, seen.prev},
		"the first reservation of the next window was shown (curr, prev): the previous window's two hits")

	curr, prev, err := database.GetRateLimitCounts(ctx, nil, keyHash, w1, w0)
	require.NoError(t, err)
	assert.Equal(t, [2]int{1, 2}, [2]int{curr, prev})

	// Two windows on, neither row is the current or the previous one.
	curr, prev, err = database.GetRateLimitCounts(ctx, nil, keyHash, w2.Add(15*time.Minute), w2)
	require.NoError(t, err)
	assert.Equal(t, [2]int{0, 0}, [2]int{curr, prev})
}

// TestRateLimitCounters_ARefusalWritesNothing: admit is asked before the charge, and a refusal
// leaves the count where it was.
func TestRateLimitCounters_ARefusalWritesNothing(t *testing.T) {
	ctx := context.Background()
	w0, _, w2 := rateLimitWindows()
	keyHash := newCounterKeyHash()
	underTwo := func(curr, prev int) bool { return curr+prev < 2 }

	for i, want := range []bool{true, true, false, false} {
		ok, err := database.ReserveRateLimitHit(ctx, keyHash, w0, w0.Add(-15*time.Minute), w2, underTwo)
		require.NoError(t, err)
		assert.Equal(t, want, ok, "reservation #%d against a budget of 2", i+1)
	}
	curr, _, err := database.GetRateLimitCounts(ctx, nil, keyHash, w0, w0.Add(-15*time.Minute))
	require.NoError(t, err)
	assert.Equal(t, 2, curr, "the refusals charged the window")

	// A key refused at its first reservation has no hits at all.
	other := newCounterKeyHash()
	ok, err := database.ReserveRateLimitHit(ctx, other, w0, w0.Add(-15*time.Minute), w2,
		func(int, int) bool { return false })
	require.NoError(t, err)
	assert.False(t, ok)
	curr, prev, err := database.GetRateLimitCounts(ctx, nil, other, w0, w0.Add(-15*time.Minute))
	require.NoError(t, err)
	assert.Equal(t, [2]int{0, 0}, [2]int{curr, prev})
}

// TestRateLimitCounters_ARefundComesOutOfTheWindowItNames: a charge taken just before a window
// rolls is refunded from that window after the roll, and the new window's count is untouched.
// A refund never takes a count below zero.
func TestRateLimitCounters_ARefundComesOutOfTheWindowItNames(t *testing.T) {
	ctx := context.Background()
	w0, w1, w2 := rateLimitWindows()
	keyHash := newCounterKeyHash()
	seen := &admitAll{}

	for i := 0; i < 2; i++ {
		_, err := database.ReserveRateLimitHit(ctx, keyHash, w0, w0.Add(-15*time.Minute), w2, seen.admit)
		require.NoError(t, err)
	}
	_, err := database.ReserveRateLimitHit(ctx, keyHash, w1, w0, w1.Add(30*time.Minute), seen.admit)
	require.NoError(t, err)

	require.NoError(t, database.RefundRateLimitHit(ctx, nil, keyHash, w0))
	curr, prev, err := database.GetRateLimitCounts(ctx, nil, keyHash, w1, w0)
	require.NoError(t, err)
	assert.Equal(t, [2]int{1, 1}, [2]int{curr, prev}, "the refund after the roll came out of (curr, prev)")

	require.NoError(t, database.RefundRateLimitHit(ctx, nil, keyHash, w0))
	require.NoError(t, database.RefundRateLimitHit(ctx, nil, keyHash, w0))
	curr, prev, err = database.GetRateLimitCounts(ctx, nil, keyHash, w1, w0)
	require.NoError(t, err)
	assert.Equal(t, [2]int{1, 0}, [2]int{curr, prev}, "a refund past zero went below it")

	// A refund for a window that was never charged writes nothing and is no error.
	require.NoError(t, database.RefundRateLimitHit(ctx, nil, keyHash, w2))
	curr, _, err = database.GetRateLimitCounts(ctx, nil, keyHash, w2, w1)
	require.NoError(t, err)
	assert.Equal(t, 0, curr)
}

// TestRateLimitCounters_TheSweepRemovesOnlyRowsPastTwoWindows: a row is swept once both windows
// that read it are over, and not before.
func TestRateLimitCounters_TheSweepRemovesOnlyRowsPastTwoWindows(t *testing.T) {
	ctx := context.Background()
	w0, w1, w2 := rateLimitWindows()
	old, live := newCounterKeyHash(), newCounterKeyHash()
	seen := &admitAll{}

	_, err := database.ReserveRateLimitHit(ctx, old, w0, w0.Add(-15*time.Minute), w2, seen.admit)
	require.NoError(t, err)
	_, err = database.ReserveRateLimitHit(ctx, live, w1, w0, w1.Add(30*time.Minute), seen.admit)
	require.NoError(t, err)

	// Inside the second window after w0 both rows are still read.
	require.NoError(t, database.DeleteExpiredRateLimitCounters(ctx, nil, w2.Add(-time.Second)))
	_, prev, err := database.GetRateLimitCounts(ctx, nil, old, w1, w0)
	require.NoError(t, err)
	assert.Equal(t, 1, prev, "the sweep removed a row its next window still reads")

	// Past w0's two windows the old row goes and the newer one stays.
	require.NoError(t, database.DeleteExpiredRateLimitCounters(ctx, nil, w2.Add(time.Second)))
	_, prev, err = database.GetRateLimitCounts(ctx, nil, old, w1, w0)
	require.NoError(t, err)
	assert.Equal(t, 0, prev, "the sweep left a row past its two windows")
	_, prev, err = database.GetRateLimitCounts(ctx, nil, live, w2, w1)
	require.NoError(t, err)
	assert.Equal(t, 1, prev, "the sweep removed a row whose next window is still running")
}

func TestRateLimitCounters_AnEmptyKeyHashIsRefused(t *testing.T) {
	ctx := context.Background()
	w0, _, w2 := rateLimitWindows()

	_, err := database.ReserveRateLimitHit(ctx, "", w0, w0.Add(-15*time.Minute), w2, func(int, int) bool { return true })
	assert.Error(t, err)
	assert.Error(t, database.RefundRateLimitHit(ctx, nil, "", w0))
	_, _, err = database.GetRateLimitCounts(ctx, nil, "", w0, w0.Add(-15*time.Minute))
	assert.Error(t, err)
}
