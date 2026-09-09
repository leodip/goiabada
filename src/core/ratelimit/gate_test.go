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
	// second caller, and it does not. With the pause, a correct Gate lets exactly one
	// caller through the pause at a time, while an unlocked one has every caller inside
	// it at once, all reading a count of zero. The pause is not what the case asserts,
	// so a slow machine only makes it more certain, never flaky.
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
