package datatests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
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

// TestSharedAccountLimiter_TheBackstopIsOneCeilingAcrossHandles is the account-wide backstop
// held across pods: failures from fresh networks, alternating handles, meet one budget. The
// budget is a rate per window, not NIST SP 800-63B Section 3.2.2's consecutive-failure limit;
// ratelimit/shared.go records the deviation.
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

// A reservation's window can end while it is still in flight: it read the clock before the
// boundary and its transaction runs after it, so a reservation charging the window that has just
// ended overlaps one charging the window that has just begun. The newer one reads the older
// window as its previous count, so the two have to be serialized between them as surely as two
// in the same window are, or both take the last slot (#394, review round 1). The three tests
// below hold one of the two in its transaction, after its charge and before its commit, and send
// the other through the second handle, which is another pod.

// rolloverBudget is the budget the rollover tests count against, with no decay, so the arithmetic
// they assert is the sum of the two windows.
const rolloverBudget = 5

func underRolloverBudget(curr, prev int) bool { return curr+prev < rolloverBudget }

// heldReservation is a reservation stopped inside its transaction. Its admission rule is asked
// twice, once by the read before the transaction and once under the transaction's locks; the
// second ask signals locked and then waits for release, so the charge it has just taken is held,
// uncommitted, until the test lets it go.
type heldReservation struct {
	locked  chan struct{}
	release chan struct{}
	done    chan reservationResult
}

type reservationResult struct {
	admitted bool
	err      error
}

func holdReservation(ctx context.Context, db data.Database, keyHash string, current, previous, expiresAt time.Time) *heldReservation {

	h := &heldReservation{
		locked:  make(chan struct{}),
		release: make(chan struct{}),
		done:    make(chan reservationResult, 1),
	}
	asks := 0
	go func() {
		admitted, err := db.ReserveRateLimitHit(ctx, keyHash, current, previous, expiresAt,
			func(curr, prev int) bool {
				asks++
				if asks == 2 {
					close(h.locked)
					select {
					case <-h.release:
					case <-ctx.Done():
					}
				}
				return underRolloverBudget(curr, prev)
			})
		h.done <- reservationResult{admitted, err}
	}()
	return h
}

// reserveAsync runs one reservation on its own goroutine and answers on the channel it returns.
func reserveAsync(ctx context.Context, db data.Database, keyHash string, current, previous, expiresAt time.Time) chan reservationResult {

	done := make(chan reservationResult, 1)
	go func() {
		admitted, err := db.ReserveRateLimitHit(ctx, keyHash, current, previous, expiresAt, underRolloverBudget)
		done <- reservationResult{admitted, err}
	}()
	return done
}

// seedRolloverWindow spends budget-1 slots in w0, so one slot is left.
func seedRolloverWindow(t *testing.T, ctx context.Context, keyHash string) {
	t.Helper()
	w0, _, w2 := rateLimitWindows()
	for i := 0; i < rolloverBudget-1; i++ {
		ok, err := database.ReserveRateLimitHit(ctx, keyHash, w0, w0.Add(-15*time.Minute), w2, underRolloverBudget)
		require.NoError(t, err)
		require.True(t, ok, "setup: seed reservation #%d", i+1)
	}
}

// TestRateLimitCounters_TheNewerWindowWaitsForTheOlderWindowsLastSlot: the older window's last
// slot is charged and held; a reservation in the newer window, on the other handle, must wait
// for that charge and count it, so it is refused. Reading the older window's last committed
// count instead admits both, a rate of six against a budget of five.
func TestRateLimitCounters_TheNewerWindowWaitsForTheOlderWindowsLastSlot(t *testing.T) {
	second := secondDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	w0, w1, w2 := rateLimitWindows()
	keyHash := newCounterKeyHash()
	seedRolloverWindow(t, ctx, keyHash)

	older := holdReservation(ctx, database, keyHash, w0, w0.Add(-15*time.Minute), w2)
	select {
	case <-older.locked:
	case <-ctx.Done():
		t.Fatal("the older reservation never reached its admission under the lock")
	}

	newer := reserveAsync(ctx, second, keyHash, w1, w0, w1.Add(30*time.Minute))
	var newerResult reservationResult
	answeredWhileHeld := false
	select {
	case newerResult = <-newer:
		answeredWhileHeld = true
	case <-time.After(500 * time.Millisecond):
	}
	close(older.release)
	olderResult := <-older.done
	if !answeredWhileHeld {
		newerResult = <-newer
	}

	require.NoError(t, olderResult.err)
	require.NoError(t, newerResult.err)
	assert.True(t, olderResult.admitted, "the older window's last slot was refused")
	assert.False(t, newerResult.admitted,
		"the newer window admitted a reservation while the older window's last slot was charged and held")

	curr, prev, err := database.GetRateLimitCounts(ctx, nil, keyHash, w1, w0)
	require.NoError(t, err)
	assert.LessOrEqual(t, curr+prev, rolloverBudget,
		"the two windows hold (curr, prev) = (%d, %d) against a budget of %d", curr, prev, rolloverBudget)
}

// TestRateLimitCounters_TheOlderWindowCannotChargeOnceTheNewerHasAdmitted is the other order: the
// newer window's reservation has read the older window's count and charged the newer one, and
// holds it. A reservation still placed in the older window must not then take a slot there,
// because the newer window's admission was decided without it; it waits for the newer
// reservation and is told its window has moved on, writing nothing.
func TestRateLimitCounters_TheOlderWindowCannotChargeOnceTheNewerHasAdmitted(t *testing.T) {
	second := secondDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	w0, w1, w2 := rateLimitWindows()
	keyHash := newCounterKeyHash()
	seedRolloverWindow(t, ctx, keyHash)

	newer := holdReservation(ctx, database, keyHash, w1, w0, w1.Add(30*time.Minute))
	select {
	case <-newer.locked:
	case <-ctx.Done():
		t.Fatal("the newer reservation never reached its admission under the lock")
	}

	older := reserveAsync(ctx, second, keyHash, w0, w0.Add(-15*time.Minute), w2)
	var olderResult reservationResult
	answeredWhileHeld := false
	select {
	case olderResult = <-older:
		answeredWhileHeld = true
	case <-time.After(500 * time.Millisecond):
	}
	close(newer.release)
	newerResult := <-newer.done
	if !answeredWhileHeld {
		olderResult = <-older
	}

	require.NoError(t, newerResult.err)
	assert.True(t, newerResult.admitted, "the newer window's reservation was refused with one slot left")
	assert.False(t, olderResult.admitted,
		"the older window took a slot after the newer window had admitted against its count")
	require.ErrorIs(t, olderResult.err, data.ErrRateLimitWindowMoved,
		"the older window's reservation was not told its window had moved on")

	curr, prev, err := database.GetRateLimitCounts(ctx, nil, keyHash, w1, w0)
	require.NoError(t, err)
	assert.Equal(t, [2]int{1, rolloverBudget - 1}, [2]int{curr, prev},
		"the two windows hold (curr, prev) against a budget of %d", rolloverBudget)
}

// TestRateLimitCounters_ConcurrentReservationsAcrossARolloverAdmitOneBudget: forty reservations
// at once, half placed in the older window and half in the newer, alternating handles, against
// one key with a budget of five and no decay. Whatever the interleaving, the two windows end
// holding no more than the budget between them, and exactly what was admitted.
func TestRateLimitCounters_ConcurrentReservationsAcrossARolloverAdmitOneBudget(t *testing.T) {
	second := secondDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	w0, w1, w2 := rateLimitWindows()
	keyHash := newCounterKeyHash()

	const callers = 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	var failures []error
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		db := database
		if i%2 == 1 {
			db = second
		}
		current, previous, expiresAt := w0, w0.Add(-15*time.Minute), w2
		if (i/2)%2 == 1 {
			current, previous, expiresAt = w1, w0, w1.Add(30*time.Minute)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := db.ReserveRateLimitHit(ctx, keyHash, current, previous, expiresAt, underRolloverBudget)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && !errors.Is(err, data.ErrRateLimitWindowMoved) {
				failures = append(failures, err)
			}
			if ok {
				admitted++
			}
		}()
	}
	close(start)
	wg.Wait()

	require.Empty(t, failures, "no reservation may fail but by finding its window moved on")
	curr, prev, err := database.GetRateLimitCounts(ctx, nil, keyHash, w1, w0)
	require.NoError(t, err)
	assert.LessOrEqual(t, curr+prev, rolloverBudget,
		"%d reservations across a rollover left (curr, prev) = (%d, %d) against a budget of %d",
		callers, curr, prev, rolloverBudget)
	assert.Equal(t, admitted, curr+prev, "the counts are not what was admitted")
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
	require.Error(t, err)
	require.Error(t, database.RefundRateLimitHit(ctx, nil, "", w0))
	_, _, err = database.GetRateLimitCounts(ctx, nil, "", w0, w0.Add(-15*time.Minute))
	assert.Error(t, err)
}
