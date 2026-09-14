package ratelimit

import (
	"sync"
	"testing"
	"time"
)

// TestGate_ReportsOncePerParentWindow drives two gates off one clock: one taken from a
// limiter anchored at t0, and one from a limiter anchored at t0+30s. They roll thirty
// seconds apart, which is what proves a gate takes its parent's phase rather than its
// own construction instant.
func TestGate_ReportsOncePerParentWindow(t *testing.T) {
	c := newClock()

	parent := newAt(c, 5, testWindow)

	// Taken ten seconds after the parent was built: if Gate used its own construction
	// instant, its windows would start at 10s and 70s rather than 0s and 60s.
	c.advance(10 * time.Second)
	aligned := parent.Gate()

	// The contrast: a limiter anchored at t0+30s, whose gate's windows start at 30s
	// and 90s.
	c.advance(20 * time.Second)
	contrast := newAt(c, 1, testWindow).Gate()

	check := func(at string, g *Gate, name string, want bool) {
		t.Helper()
		if got := g.First("k"); got != want {
			t.Errorf("at %s: %s gate First = %v, want %v", at, name, got, want)
		}
	}

	// Both gates are mid-window here, and neither has reported yet.
	c.advance(10 * time.Second) // t0+40s
	check("40s", aligned, "aligned", true)
	check("40s", aligned, "aligned", false)
	check("40s", contrast, "contrast", true)
	check("40s", contrast, "contrast", false)

	// A tenth of a second before the aligned gate's boundary, still the same window.
	c.advance(19900 * time.Millisecond) // t0+59.9s
	check("59.9s", aligned, "aligned", false)
	check("59.9s", contrast, "contrast", false)

	// Just past it. A gate of budget 1 built as a sliding limiter would answer false
	// here -- one hit in the previous window decays to 0.998, which rounds to 1 -- so
	// this assertion is the whole reason Gate is fixed-window (#276).
	c.advance(200 * time.Millisecond) // t0+60.1s
	check("60.1s", aligned, "aligned", true)
	check("60.1s", aligned, "aligned", false)
	check("60.1s", contrast, "contrast", false) // thirty seconds into its own window

	// The contrast rolls thirty seconds later, and the aligned gate does not.
	c.advance(30 * time.Second) // t0+90.1s
	check("90.1s", contrast, "contrast", true)
	check("90.1s", contrast, "contrast", false)
	check("90.1s", aligned, "aligned", false)

	// And the aligned gate rolls again on its parent's minute.
	c.advance(30 * time.Second) // t0+120.1s
	check("120.1s", aligned, "aligned", true)
	check("120.1s", aligned, "aligned", false)
}

// TestGate_ConcurrentFirstReportsExactlyOnce is the Gate half of what
// TestLimiter_ConcurrentAllowChargesExactlyTheBudget does for Allow. First is a compound
// read-and-record, and reportTrip calls it from whichever request happened to trip the
// tier, so several can arrive at once on one key. Without the lock held across the read
// and the write, two callers both see a count of zero and the audit guarantee becomes "at
// least one event per key per window" rather than exactly one (#276).
func TestGate_ConcurrentFirstReportsExactlyOnce(t *testing.T) {
	g := New(1, testWindow).Gate()

	// First calls now() with the lock held, so replacing the clock widens the critical
	// section: this is the package's own unexported hook being used for the reason it
	// exists, determinism rather than a real interval to measure. Releasing the callers
	// against the untouched clock does not catch a missing lock -- the body is a map
	// read and a map write, a few nanoseconds during which the scheduler has to land a
	// second caller, and it does not.
	//
	// This case asserts the outcome and is a probabilistic witness of the cause: with
	// the unlock moved above now(), it caught the mutation in four of six runs, and it
	// misses the two later truncations of the same critical section entirely, passing a
	// hundred consecutive runs against each. What pins the cause is
	// TestGate_FirstHoldsItsLockAcrossTheWholeReadAndRecord below, which fails on every
	// run of all three. Both are kept: one says the lock is held, the other says holding
	// it produces exactly one report (#276).
	base := g.now()
	g.now = func() time.Time {
		time.Sleep(time.Millisecond)
		return base
	}

	const callers = 32
	var wg sync.WaitGroup
	reported := make([]bool, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			reported[i] = g.First("k")
		}(i)
	}
	close(start)
	wg.Wait()

	got := 0
	for _, first := range reported {
		if first {
			got++
		}
	}
	if got != 1 {
		t.Errorf("%d of %d concurrent callers were told they were first, want exactly 1: "+
			"read-and-record is atomic", got, callers)
	}
}

// parkingStore is a memStore that suspends its first caller inside the write. It is how
// the case below reaches the far end of First's critical section: the store's add is the
// last thing First does under the lock, so a caller parked there has executed the whole
// compound operation bar the unlock.
//
// Only add parks. Parking in get would put the check between the read and the record and
// leave the record itself unpinned, which is one of the two truncations the previous
// version of this test missed.
type parkingStore struct {
	*memStore
	once    sync.Once
	parked  chan struct{}
	release chan struct{}
}

func newParkingStore(window time.Duration) *parkingStore {
	return &parkingStore{
		memStore: newMemStore(window),
		parked:   make(chan struct{}),
		release:  make(chan struct{}),
	}
}

func (s *parkingStore) add(key string, current time.Time) {
	s.once.Do(func() {
		close(s.parked)
		<-s.release
	})
	s.memStore.add(key, current)
}

// TestGate_FirstHoldsItsLockAcrossTheWholeReadAndRecord pins the cause the case above
// can only witness. A concurrency test that asserts an outcome depends on the scheduler
// to interleave two callers, so it answers "the race did not happen this time" rather
// than "the race cannot happen": moving First's unlock above now() leaves the outcome
// case passing four runs in six.
//
// Suspending a caller inside First and asking TryLock whether the mutex is held removes
// the scheduler from the question. Where the caller is suspended is the whole of what
// this proves, and the first version of this test got it wrong: it parked inside now(),
// which First calls one statement after taking the lock, so it pinned the entrance to
// the critical section and nothing after it. An unlock moved below now(), or below the
// store read, left this case and the outcome case above green in a hundred consecutive
// runs each. Both are real defects -- two callers read a count of zero and both are told
// they are first -- and neither was observable.
//
// So the park is at the far end instead, inside the store's write, which is the last
// thing First does under the lock. The mutex must still be held there, whatever the
// unlock's position, unless it was released somewhere above -- which is exactly the
// family of truncations worth catching (#276).
func TestGate_FirstHoldsItsLockAcrossTheWholeReadAndRecord(t *testing.T) {
	g := New(1, testWindow).Gate()
	store := newParkingStore(testWindow)
	g.store = store

	reported := make(chan bool, 1)
	go func() { reported <- g.First("k") }()

	<-store.parked
	locked := !g.mu.TryLock()
	if !locked {
		// Taken, so release it: leaving it held would deadlock the parked caller's
		// own deferred unlock and hang the test rather than failing it.
		g.mu.Unlock()
	}
	close(store.release)
	first := <-reported

	if !locked {
		t.Error("Gate.mu was free while a caller was inside First's record: the read and the " +
			"record are not one critical section, so two callers can both be told they are first")
	}
	if !first {
		t.Error("the only caller was not told it was first")
	}
}

// TestGate_CountsSeparatelyFromItsLimiter pins that gating a key spends none of the
// limiter's budget: the gate reports on rejections, it does not cause them.
func TestGate_CountsSeparatelyFromItsLimiter(t *testing.T) {
	c := newClock()
	l := newAt(c, 1, testWindow)
	g := l.Gate()

	if !g.First("k") {
		t.Fatal("setup: the gate's first report was refused")
	}
	if !l.Allow("k") {
		t.Error("Allow refused after the gate reported on the same key: the gate has its own counts")
	}
}
