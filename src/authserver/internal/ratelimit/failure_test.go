package ratelimit

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// newFailureAt builds a failures-only limiter on the fake clock, the way newAt builds a
// Limiter: anchored at the clock's current instant and reading it from then on.
func newFailureAt(c *clock, limit int, window time.Duration) *FailureLimiter {
	f := NewFailureLimiter(limit, window)
	f.rl.now = c.now
	f.rl.anchor = c.t
	return f
}

// fail runs one credential check that is found wrong: reserve, then charge on release. It
// reports whether the check was admitted at all.
func fail(f *FailureLimiter, key string) bool {
	if !f.Reserve(key) {
		return false
	}
	f.Release(key, true)
	return true
}

func TestFailureLimiter_OnlyAFailureSpendsTheBudget(t *testing.T) {
	c := newClock()
	f := newFailureAt(c, 5, testWindow)

	// Well past the budget, every one of them a credential found right. A limiter that
	// charged on Reserve, or on any Release, would refuse the sixth.
	for i := 1; i <= 20; i++ {
		if !f.Reserve("k") {
			t.Fatalf("Reserve #%d refused after %d successful checks, want admitted: a success spends nothing", i, i-1)
		}
		f.Release("k", false)
	}

	for i := 1; i <= 5; i++ {
		if !fail(f, "k") {
			t.Fatalf("failure #%d refused, want admitted: the budget is 5 failures", i)
		}
	}
	if f.Reserve("k") {
		t.Error("Reserve after 5 failures admitted, want refused: the budget is 5")
	}
	if !f.Reserve("other") {
		t.Error("Reserve on another key refused, want admitted: one key's failures are not another's")
	}
}

func TestFailureLimiter_FailuresAgeOutWithTheWindow(t *testing.T) {
	c := newClock()
	f := newFailureAt(c, 5, testWindow)

	for i := 0; i < 5; i++ {
		fail(f, "k")
	}
	if f.Reserve("k") {
		t.Fatal("setup: 5 failures did not exhaust a budget of 5")
	}

	// Two whole windows on, nothing recorded is recent enough to count.
	c.advance(2 * testWindow)
	if !f.Reserve("k") {
		t.Error("Reserve refused two windows after the last failure, want admitted")
	}
}

// TestFailureLimiter_AHeldReservationCountsAgainstTheBudget is the in-flight count seen one
// caller at a time: a slot reserved and not yet released is spent as far as the next caller
// is concerned, and handing it back without a failure returns it.
func TestFailureLimiter_AHeldReservationCountsAgainstTheBudget(t *testing.T) {
	c := newClock()
	f := newFailureAt(c, 5, testWindow)

	for i := 1; i <= 5; i++ {
		if !f.Reserve("k") {
			t.Fatalf("Reserve #%d refused with %d held, want admitted: the budget is 5", i, i-1)
		}
	}
	if f.Reserve("k") {
		t.Fatal("Reserve #6 admitted with 5 held, want refused: a held reservation counts")
	}

	f.Release("k", false)
	if !f.Reserve("k") {
		t.Error("Reserve refused after a slot was handed back uncharged, want admitted")
	}
	if f.Reserve("k") {
		t.Error("Reserve admitted with 5 held again, want refused")
	}
}

// TestFailureLimiter_FailsClosedOnAStoreError reaches the one branch no request can: the
// in-process store cannot fail. A limiter that answered true on a store error would leave
// every other case green while admitting every credential check for the duration of a
// storage fault (#219, #439).
func TestFailureLimiter_FailsClosedOnAStoreError(t *testing.T) {
	c := newClock()
	f := newFailureAt(c, 5, testWindow)
	f.rl.store = erroringStore{getErr: errors.New("counter unavailable")}

	if f.Reserve("anyone@example.com") {
		t.Error("Reserve admitted while the store could not be read, want refused: the limiter must fail closed")
	}
}

// TestFailureLimiter_ConcurrentReservationsAdmitExactlyTheBudget is the race the mutex and
// the in-flight count exist for. A limiter that reads the recorded count, lets the
// credential be checked and only then charges admits every caller that reads before the
// first charge: measured at 141 of 1000 against a budget of 10 before the in-flight count
// existed. Every caller here holds its reservation, so nothing is ever charged and the
// in-flight count is the only thing standing between the budget and the thousand.
func TestFailureLimiter_ConcurrentReservationsAdmitExactlyTheBudget(t *testing.T) {
	// The real clock, for the reason TestLimiter_ConcurrentAllowChargesExactlyTheBudget gives.
	f := NewFailureLimiter(10, testWindow)

	const callers = 1000
	var wg sync.WaitGroup
	admitted := make([]bool, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			admitted[i] = f.Reserve("k")
		}(i)
	}
	close(start)
	wg.Wait()

	got := 0
	for _, ok := range admitted {
		if ok {
			got++
		}
	}
	if got != 10 {
		t.Errorf("%d of %d concurrent callers admitted, want exactly 10: a reservation is "+
			"claimed atomically with reading what is spent", got, callers)
	}
}
