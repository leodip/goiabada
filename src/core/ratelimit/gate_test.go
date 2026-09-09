package ratelimit

import (
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
