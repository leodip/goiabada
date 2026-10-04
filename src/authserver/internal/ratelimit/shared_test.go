package ratelimit

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"
)

// countingStore stands in for the database at the one boundary a shared limiter crosses. It
// counts per (digest, window) and asks admit the way the data layer does, under one mutex, so
// the unit tier can walk a shared limiter through windows on the fake clock. That the real
// store is atomic across handles is the data tier's to prove, on every engine.
//
// reserveErr and refundErr make a call fail; blockReserve and blockRefund make it wait for its
// context, which is a store too slow to answer.
type countingStore struct {
	mu   sync.Mutex
	hits map[string]int

	reserveErr   error
	refundErr    error
	blockReserve bool
	blockRefund  bool

	reserves []storeCall
	refunds  []storeCall
}

// storeCall is what one call handed the store, and what its context said when it arrived.
type storeCall struct {
	keyHash   string
	current   time.Time
	previous  time.Time
	expiresAt time.Time
	ctxErr    error
	deadline  time.Time
	hasDL     bool
}

func newCountingStore() *countingStore {
	return &countingStore{hits: map[string]int{}}
}

func counterKey(keyHash string, window time.Time) string {
	return keyHash + "@" + window.UTC().Format(time.RFC3339Nano)
}

func (s *countingStore) ReserveRateLimitHit(ctx context.Context, keyHash string, current, previous,
	expiresAt time.Time, admit func(curr, prev int) bool) (bool, error) {

	call := storeCall{keyHash: keyHash, current: current, previous: previous, expiresAt: expiresAt, ctxErr: ctx.Err()}
	call.deadline, call.hasDL = ctx.Deadline()
	s.mu.Lock()
	s.reserves = append(s.reserves, call)
	s.mu.Unlock()

	if s.blockReserve {
		<-ctx.Done()
		return false, ctx.Err()
	}
	if s.reserveErr != nil {
		return false, s.reserveErr
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !admit(s.hits[counterKey(keyHash, current)], s.hits[counterKey(keyHash, previous)]) {
		return false, nil
	}
	s.hits[counterKey(keyHash, current)]++
	return true, nil
}

func (s *countingStore) RefundRateLimitHit(ctx context.Context, _ *sql.Tx, keyHash string, windowStart time.Time) error {
	call := storeCall{keyHash: keyHash, current: windowStart, ctxErr: ctx.Err()}
	call.deadline, call.hasDL = ctx.Deadline()
	s.mu.Lock()
	s.refunds = append(s.refunds, call)
	s.mu.Unlock()

	if s.blockRefund {
		<-ctx.Done()
		return ctx.Err()
	}
	if s.refundErr != nil {
		return s.refundErr
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if k := counterKey(keyHash, windowStart); s.hits[k] > 0 {
		s.hits[k]--
	}
	return nil
}

// newSharedAt builds a shared limiter reading the fake clock. Only the clock is replaced: the
// anchor stays the Unix epoch, which is the property under test wherever a window is named.
func newSharedAt(c *clock, store *countingStore, tier string, limit int, window time.Duration) *FailureLimiter {
	f := NewSharedFailureLimiter(store, tier, limit, window)
	f.rl.now = c.now
	return f
}

// newClockAt is the fake clock at a given instant, for the tests whose point is where a
// window starts relative to the epoch rather than relative to the limiter.
func newClockAt(t time.Time) *clock { return &clock{t: t} }

func TestSharedFailureLimiter_KeysTheStoreByTheDigestOfTierAndKey(t *testing.T) {
	store := newCountingStore()
	f := newSharedAt(newClock(), store, "pwd_account", 5, 15*time.Minute)

	reserve(t, f, "victim@example.com")

	// printf 'pwd_account\0victim@example.com' | sha256sum
	const want = "c9487502c98d31f7b0f61b6586d68a11b2dc9b04f1eafa4d66652b9a13a5b96b"
	if len(store.reserves) != 1 {
		t.Fatalf("%d calls reached the store, want 1", len(store.reserves))
	}
	if got := store.reserves[0].keyHash; got != want {
		t.Errorf("the store was keyed by %q, want %q: the SHA-256 of the tier, a NUL and the key, "+
			"so no address or IP block is written to the table", got, want)
	}
}

func TestSharedFailureLimiter_TwoTiersNeverShareARow(t *testing.T) {
	store := newCountingStore()
	c := newClock()
	a := newSharedAt(c, store, "otp", 1, 15*time.Minute)
	b := newSharedAt(c, store, "account_password", 1, 15*time.Minute)

	if !fail(t, a, "user_1") {
		t.Fatal("setup: the first otp failure was refused")
	}
	if !fail(t, b, "user_1") {
		t.Error("a tier with a budget of 1 refused its first failure because another tier spent " +
			"the same key: the tier belongs in the digest")
	}
}

// TestSharedFailureLimiter_WindowsAreAlignedToTheEpoch builds the limiter seven and a half
// minutes into a quarter hour. A limiter anchored at its own construction, as the in-memory
// ones are, would start its window there; every pod has to agree where a window begins, so the
// shared one starts it at the quarter hour since the epoch.
func TestSharedFailureLimiter_WindowsAreAlignedToTheEpoch(t *testing.T) {
	c := newClockAt(time.Date(2026, 1, 1, 0, 7, 30, 0, time.UTC))
	store := newCountingStore()
	f := newSharedAt(c, store, "pwd_account", 5, 15*time.Minute)

	reserve(t, f, "victim@example.com")

	call := store.reserves[0]
	if want := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC); !call.current.Equal(want) {
		t.Errorf("current window = %v, want %v", call.current, want)
	}
	if want := time.Date(2025, 12, 31, 23, 45, 0, 0, time.UTC); !call.previous.Equal(want) {
		t.Errorf("previous window = %v, want %v", call.previous, want)
	}
	// Two windows after the current one began, no rate reads the row any more.
	if want := time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC); !call.expiresAt.Equal(want) {
		t.Errorf("expiresAt = %v, want %v", call.expiresAt, want)
	}
}

func TestSharedFailureLimiter_OnlyAFailureSpendsTheBudget(t *testing.T) {
	c := newClockAt(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	f := newSharedAt(c, newCountingStore(), "pwd_account", 5, testWindow)

	for i := 1; i <= 20; i++ {
		r := reserve(t, f, "k")
		if r == nil {
			t.Fatalf("Reserve #%d refused after %d successful checks, want admitted: a success spends nothing", i, i-1)
		}
		release(t, r, false)
	}
	for i := 1; i <= 5; i++ {
		if !fail(t, f, "k") {
			t.Fatalf("failure #%d refused, want admitted: the budget is 5 failures", i)
		}
	}
	if reserve(t, f, "k") != nil {
		t.Error("Reserve after 5 failures admitted, want refused: the budget is 5")
	}
}

// TestSharedFailureLimiter_AHeldReservationCountsAgainstTheBudget is the in-flight protection
// across pods: a slot is charged when it is reserved, so a reservation another pod holds is
// spent as far as this one is concerned.
func TestSharedFailureLimiter_AHeldReservationCountsAgainstTheBudget(t *testing.T) {
	c := newClockAt(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	store := newCountingStore()
	podA := newSharedAt(c, store, "otp", 2, testWindow)
	podB := newSharedAt(c, store, "otp", 2, testWindow)

	held := reserve(t, podA, "user_1")
	if held == nil || reserve(t, podB, "user_1") == nil {
		t.Fatal("setup: two reservations against a budget of 2 were not both admitted")
	}
	if reserve(t, podA, "user_1") != nil {
		t.Fatal("a third reservation was admitted with two held, want refused")
	}
	release(t, held, false)
	if reserve(t, podB, "user_1") == nil {
		t.Error("Reserve refused after a slot was refunded, want admitted")
	}
}

// TestSharedFailureLimiter_ThePreviousWindowDecays is the in-memory limiter's arithmetic, over
// epoch-aligned windows: five failures in one window, then the predicate a hundredth and a
// fifth of the way into the next. The rates are 4.95 and 4.0, the values
// TestLimiter_PredicateAtTheBoundary walks.
func TestSharedFailureLimiter_ThePreviousWindowDecays(t *testing.T) {
	c := newClockAt(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	f := newSharedAt(c, newCountingStore(), "otp", 5, testWindow)

	for i := 0; i < 5; i++ {
		if !fail(t, f, "k") {
			t.Fatalf("setup: failure #%d refused", i+1)
		}
	}

	c.advance(testWindow + testWindow/100)
	if reserve(t, f, "k") != nil {
		t.Error("Reserve admitted at rate 4.95: round(4.95)+1 is 6, over the budget of 5")
	}

	c.advance(testWindow/5 - testWindow/100)
	if r := reserve(t, f, "k"); r == nil {
		t.Error("Reserve refused at rate 4.0, want admitted: round(4.0)+1 is 5, within the budget")
	}

	// Two windows after the failures, nothing recorded is recent enough to count.
	c.advance(testWindow)
	for i := 1; i <= 4; i++ {
		if reserve(t, f, "k") == nil {
			t.Fatalf("Reserve #%d refused two windows after the failures, want admitted", i)
		}
	}
}

// TestSharedFailureLimiter_RefundsTheWindowItCharged reserves a second before a window ends and
// releases a second after: the refund has to come out of the window the charge went into, or
// the charge stays there and the refund lowers a count it never raised.
func TestSharedFailureLimiter_RefundsTheWindowItCharged(t *testing.T) {
	c := newClockAt(time.Date(2026, 1, 1, 0, 14, 59, 0, time.UTC))
	store := newCountingStore()
	f := newSharedAt(c, store, "pwd_account", 5, 15*time.Minute)

	r := reserve(t, f, "victim@example.com")
	c.advance(2 * time.Second)
	release(t, r, false)

	if len(store.refunds) != 1 {
		t.Fatalf("%d refunds reached the store, want 1", len(store.refunds))
	}
	if want := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC); !store.refunds[0].current.Equal(want) {
		t.Errorf("the refund came out of the window starting %v, want %v, where it was charged",
			store.refunds[0].current, want)
	}
	if store.refunds[0].keyHash != store.reserves[0].keyHash {
		t.Error("the refund was keyed differently from the charge")
	}
}

func TestSharedFailureLimiter_AFailureIsNotRefunded(t *testing.T) {
	store := newCountingStore()
	f := newSharedAt(newClock(), store, "otp", 5, testWindow)

	release(t, reserve(t, f, "k"), true)

	if len(store.refunds) != 0 {
		t.Errorf("%d refunds reached the store for a wrong credential, want 0: the charge is the failure", len(store.refunds))
	}
}

// TestSharedFailureLimiter_FailsClosedOnAStoreError: a store that cannot answer refuses the
// check, and says it was a fault rather than a refusal, so the caller can answer it as one.
func TestSharedFailureLimiter_FailsClosedOnAStoreError(t *testing.T) {
	store := newCountingStore()
	store.reserveErr = errors.New("connection refused")
	f := newSharedAt(newClock(), store, "pwd_account", 5, testWindow)

	r, err := f.Reserve(context.Background(), "victim@example.com")
	if r != nil {
		t.Error("Reserve admitted while the store failed, want refused: the limiter must fail closed")
	}
	if !errors.Is(err, store.reserveErr) {
		t.Errorf("Reserve error = %v, want one wrapping the store's", err)
	}
}

func TestSharedFailureLimiter_EachStoreCallIsBoundedAtFiveSeconds(t *testing.T) {
	f := NewSharedFailureLimiter(newCountingStore(), "otp", 5, testWindow)
	if f.bound != 5*time.Second {
		t.Errorf("store call bound = %v, want 5s", f.bound)
	}
}

// TestSharedFailureLimiter_ASlowStoreIsRefusedAtTheBound: a store that never answers is a
// refused check once the bound has passed, not a request held for as long as the client waits.
// The bound is shortened here so the test does not take five seconds; the constant is pinned
// above.
func TestSharedFailureLimiter_ASlowStoreIsRefusedAtTheBound(t *testing.T) {
	store := newCountingStore()
	store.blockReserve = true
	f := newSharedAt(newClock(), store, "pwd_account", 5, testWindow)
	f.bound = 50 * time.Millisecond

	done := make(chan struct{})
	var r *Reservation
	var err error
	go func() {
		defer close(done)
		r, err = f.Reserve(context.Background(), "victim@example.com")
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Reserve was still waiting on the store five seconds later, a hundred times its bound")
	}
	if r != nil {
		t.Error("Reserve admitted when the store did not answer, want refused")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Reserve error = %v, want one reporting the bound was reached", err)
	}
}

// TestSharedFailureLimiter_TheRefundOutlivesTheRequestsCancellation: a client that hangs up
// after a correct password must not leave the charge behind, so the refund runs detached from
// the request's cancellation, under the store's own bound.
func TestSharedFailureLimiter_TheRefundOutlivesTheRequestsCancellation(t *testing.T) {
	store := newCountingStore()
	f := newSharedAt(newClock(), store, "pwd_account", 5, testWindow)

	r := reserve(t, f, "victim@example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := time.Now()
	if err := r.Release(ctx, false); err != nil {
		t.Fatalf("Release under a cancelled request returned %v, want the refund made", err)
	}

	if len(store.refunds) != 1 {
		t.Fatalf("%d refunds reached the store, want 1", len(store.refunds))
	}
	call := store.refunds[0]
	if call.ctxErr != nil {
		t.Errorf("the refund reached the store with its context already %v, want it detached "+
			"from the request's cancellation", call.ctxErr)
	}
	if !call.hasDL || call.deadline.After(before.Add(5*time.Second+time.Second)) {
		t.Errorf("the refund's context has deadline %v (set: %v), want one within the 5-second bound",
			call.deadline, call.hasDL)
	}
}

func TestSharedFailureLimiter_ASlowRefundIsReportedAtTheBound(t *testing.T) {
	store := newCountingStore()
	f := newSharedAt(newClock(), store, "pwd_account", 5, testWindow)
	r := reserve(t, f, "victim@example.com")

	store.blockRefund = true
	f.bound = 50 * time.Millisecond
	err := r.Release(context.Background(), false)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Release error = %v, want one reporting the bound was reached", err)
	}
}

func TestSharedFailureLimiter_AFailedRefundIsReported(t *testing.T) {
	store := newCountingStore()
	f := newSharedAt(newClock(), store, "pwd_account", 5, testWindow)
	r := reserve(t, f, "victim@example.com")

	store.refundErr = errors.New("connection reset")
	if err := r.Release(context.Background(), false); !errors.Is(err, store.refundErr) {
		t.Errorf("Release error = %v, want one wrapping the store's", err)
	}
}

// TestSharedFailureLimiter_TheGateFollowsTheEpochWindows: the audit gate rolls when its limiter
// does, and a shared limiter's windows start at the quarter hour, not at its construction.
func TestSharedFailureLimiter_TheGateFollowsTheEpochWindows(t *testing.T) {
	c := newClockAt(time.Date(2026, 1, 1, 0, 7, 30, 0, time.UTC))
	f := newSharedAt(c, newCountingStore(), "pwd_account", 5, 15*time.Minute)
	g := f.Gate()

	if !g.First("k") {
		t.Fatal("the first sighting of a key was not reported")
	}
	c.advance(7 * time.Minute) // 00:14:30
	if g.First("k") {
		t.Error("a second sighting in the same window was reported")
	}
	c.advance(time.Minute) // 00:15:30, a new window since the epoch
	if !g.First("k") {
		t.Error("the first sighting after the quarter hour was not reported: the gate is not " +
			"following the epoch-aligned windows")
	}
}

// TestAccountLimiter_ABackstopStoreFailureRefundsTheTightSlot: the tight tier charged its slot
// when it reserved it, so a backstop that cannot answer has to hand that charge back, or every
// fault strands one failure on the owner's network.
func TestAccountLimiter_ABackstopStoreFailureRefundsTheTightSlot(t *testing.T) {
	c := newClock()
	tightStore, backstopStore := newCountingStore(), newCountingStore()
	backstopStore.reserveErr = errors.New("connection refused")
	a := NewAccountLimiter(
		newSharedAt(c, tightStore, "pwd_account_net", 2, 15*time.Minute),
		newSharedAt(c, backstopStore, "pwd_account", 5, time.Hour),
	)

	r, refusal, err := a.Reserve(context.Background(), "203.0.113.7|victim@example.com", "victim@example.com")
	if r != nil {
		t.Error("Reserve admitted while the backstop failed, want refused")
	}
	if refusal != RefusedBackstop {
		t.Errorf("Reserve named %v, want RefusedBackstop, the tier whose store failed", refusal)
	}
	if !errors.Is(err, backstopStore.reserveErr) {
		t.Errorf("Reserve error = %v, want one wrapping the backstop store's", err)
	}
	if len(tightStore.refunds) != 1 || tightStore.refunds[0].keyHash != tightStore.reserves[0].keyHash {
		t.Errorf("the tight tier's charge was refunded %d times, want once", len(tightStore.refunds))
	}
}

func TestAccountLimiter_ATightStoreFailureNeverReachesTheBackstop(t *testing.T) {
	c := newClock()
	tightStore, backstopStore := newCountingStore(), newCountingStore()
	tightStore.reserveErr = errors.New("connection refused")
	a := NewAccountLimiter(
		newSharedAt(c, tightStore, "pwd_account_net", 2, 15*time.Minute),
		newSharedAt(c, backstopStore, "pwd_account", 5, time.Hour),
	)

	r, refusal, err := a.Reserve(context.Background(), "203.0.113.7|victim@example.com", "victim@example.com")
	if r != nil || refusal != RefusedTight || !errors.Is(err, tightStore.reserveErr) {
		t.Errorf("Reserve = (%v, %v, %v), want (nil, RefusedTight, the tight store's error)", r, refusal, err)
	}
	if len(backstopStore.reserves) != 0 {
		t.Error("the backstop was reserved against after the tight tier failed")
	}
}

// TestAccountReservation_ReleasesBothTiersWhenOneFails: a refund that fails on one tier still
// refunds the other, and the failure is reported.
func TestAccountReservation_ReleasesBothTiersWhenOneFails(t *testing.T) {
	c := newClock()
	tightStore, backstopStore := newCountingStore(), newCountingStore()
	a := NewAccountLimiter(
		newSharedAt(c, tightStore, "pwd_account_net", 2, 15*time.Minute),
		newSharedAt(c, backstopStore, "pwd_account", 5, time.Hour),
	)
	r, _, err := a.Reserve(context.Background(), "203.0.113.7|victim@example.com", "victim@example.com")
	if err != nil || r == nil {
		t.Fatalf("setup: Reserve = (%v, %v)", r, err)
	}

	backstopStore.refundErr = errors.New("connection reset")
	if err := r.Release(context.Background(), false); !errors.Is(err, backstopStore.refundErr) {
		t.Errorf("Release error = %v, want one wrapping the backstop store's", err)
	}
	if len(tightStore.refunds) != 1 {
		t.Errorf("the tight tier was refunded %d times after the backstop's refund failed, want once", len(tightStore.refunds))
	}
}
