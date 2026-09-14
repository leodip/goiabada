package ratelimit

import (
	"errors"
	"sync"
	"testing"
	"time"
)

const testWindow = time.Minute

// clock is the fake the package's own tests drive time with. A Limiter's now field is
// unexported precisely so that nothing above this package can do this (#276).
type clock struct{ t time.Time }

func newClock() *clock {
	// A fixed instant rather than time.Now, so a failure reports the same numbers
	// whenever it is read.
	return &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

// newAt builds a limiter anchored at the fake clock's current instant and reading it
// from then on, which is what New does with time.Now.
func newAt(c *clock, limit int, window time.Duration, opts ...Option) *Limiter {
	l := New(limit, window, opts...)
	l.now = c.now
	l.anchor = c.t
	return l
}

// erroringStore is the only way to reach the fail-closed paths: the in-process store
// cannot produce an error.
type erroringStore struct {
	getErr error
	addErr error
}

func (s erroringStore) Get(_ string, _, _ time.Time) (int, int, error) {
	return 0, 0, s.getErr
}

func (s erroringStore) Add(_ string, _ time.Time) error {
	return s.addErr
}

func mustRate(t *testing.T, l *Limiter, key string, want float64) {
	t.Helper()
	got, err := l.Rate(key)
	if err != nil {
		t.Fatalf("Rate(%q) returned an error: %v", key, err)
	}
	// Exact comparison. Every expected value here is the correctly rounded quotient
	// of two exactly representable numbers, so it is the same float64 the literal
	// parses to; a tolerance would hide a formula that is subtly wrong.
	if got != want {
		t.Errorf("Rate(%q) = %v, want %v", key, got, want)
	}
}

func TestLimiter_BudgetExactOnBothSides(t *testing.T) {
	c := newClock()
	l := newAt(c, 5, testWindow)

	for i := 1; i <= 5; i++ {
		if !l.Allow("k") {
			t.Fatalf("Allow #%d refused, want admitted: the budget is 5", i)
		}
	}
	if l.Allow("k") {
		t.Error("Allow #6 admitted, want refused: the budget is 5")
	}
	if l.Allow("k") {
		t.Error("Allow #7 admitted, want refused: a refusal charges nothing and stays refused")
	}
}

func TestLimiter_DecayAcrossTheBoundary(t *testing.T) {
	c := newClock()
	l := newAt(c, 5, testWindow)

	for i := 0; i < 5; i++ {
		if !l.Allow("k") {
			t.Fatalf("setup: Allow #%d refused", i+1)
		}
	}
	mustRate(t, l, "k", 5)

	// The values httprate produced across a boundary, which this package reproduces.
	c.advance(testWindow + testWindow/4)
	mustRate(t, l, "k", 3.75)
	c.advance(testWindow / 4)
	mustRate(t, l, "k", 2.5)
	c.advance(testWindow / 4)
	mustRate(t, l, "k", 1.25)

	// Two windows on, nothing the store holds is recent enough to count.
	c.advance(2 * testWindow)
	mustRate(t, l, "k", 0)
}

func TestLimiter_PredicateAtTheBoundary(t *testing.T) {
	c := newClock()
	l := newAt(c, 5, testWindow)

	for i := 0; i < 5; i++ {
		if !l.Allow("k") {
			t.Fatalf("setup: Allow #%d refused", i+1)
		}
	}

	// One percent into the next window the decayed rate is 4.95, which rounds to 5,
	// so one more would be a sixth against a budget of five.
	c.advance(testWindow + testWindow/100)
	mustRate(t, l, "k", 4.95)
	if l.Allow("k") {
		t.Error("Allow admitted at rate 4.95: round(4.95)+1 is 6, over the budget of 5")
	}

	// Half a window in, the rate is 2.5, which rounds away from zero to 3; 3+1 is
	// within the budget.
	c.advance(testWindow/2 - testWindow/100)
	mustRate(t, l, "k", 2.5)
	if !l.Allow("k") {
		t.Fatal("Allow refused at rate 2.5: round(2.5)+1 is 4, within the budget of 5")
	}
	// The admitted hit is charged to the current window, undecayed.
	mustRate(t, l, "k", 3.5)
}

// heldKeys is the number of keys the in-process store is still holding, across both
// windows. Reading the store's maps is a side channel anywhere else; inside the package
// that owns the bound, it is the only way to prove eviction happens at all.
func heldKeys(t *testing.T, l *Limiter) int {
	t.Helper()
	s, ok := l.store.(*memStore)
	if !ok {
		t.Fatalf("store is %T, want *memStore", l.store)
	}
	return len(s.curr) + len(s.prev)
}

// testKey returns 100 distinct two-letter keys.
func testKey(i int) string {
	return string(rune('a'+i/26)) + string(rune('a'+i%26))
}

func TestLimiter_Eviction(t *testing.T) {
	t.Run("one roll keeps the previous window's keys", func(t *testing.T) {
		c := newClock()
		l := newAt(c, 5, testWindow)
		for i := 0; i < 100; i++ {
			l.Allow(testKey(i))
		}

		c.advance(testWindow)
		if !l.Allow("fresh") {
			t.Fatal("setup: Allow refused an unused key")
		}
		if got := heldKeys(t, l); got != 101 {
			t.Errorf("store holds %d keys after one roll, want 101: the previous window still counts", got)
		}
	})

	t.Run("two rolls drop them", func(t *testing.T) {
		c := newClock()
		l := newAt(c, 5, testWindow)
		for i := 0; i < 100; i++ {
			l.Allow(testKey(i))
		}

		c.advance(2 * testWindow)
		if !l.Allow("fresh") {
			t.Fatal("setup: Allow refused an unused key")
		}
		if got := heldKeys(t, l); got != 1 {
			t.Errorf("store holds %d keys two windows on, want 1: memory is bounded by the last two windows", got)
		}
	})
}

func TestLimiter_KeysAreIsolated(t *testing.T) {
	c := newClock()
	l := newAt(c, 5, testWindow)

	for i := 0; i < 5; i++ {
		l.Allow("a")
	}
	if l.Allow("a") {
		t.Fatal("setup: key a is not exhausted")
	}
	if !l.Allow("b") {
		t.Error("Allow refused key b, want admitted: one key's spending is not another's")
	}
}

func TestLimiter_FailsClosedOnAStoreError(t *testing.T) {
	boom := errors.New("counter unavailable")

	t.Run("Get fails", func(t *testing.T) {
		c := newClock()
		l := newAt(c, 5, testWindow, WithStore(erroringStore{getErr: boom}))

		if l.Allow("k") {
			t.Error("Allow admitted while the store could not be read, want refused")
		}
		if _, err := l.Rate("k"); !errors.Is(err, boom) {
			t.Errorf("Rate returned err %v, want %v: the caller decides what to do about it", err, boom)
		}
	})

	t.Run("Add fails", func(t *testing.T) {
		c := newClock()
		l := newAt(c, 5, testWindow, WithStore(erroringStore{addErr: boom}))

		if l.Allow("k") {
			t.Error("Allow admitted a hit it could not charge, want refused")
		}
		if err := l.Add("k"); !errors.Is(err, boom) {
			t.Errorf("Add returned err %v, want %v", err, boom)
		}
	})
}

func TestLimiter_ConcurrentAllowChargesExactlyTheBudget(t *testing.T) {
	// The real clock: a thousand goroutines cannot cross a one-minute boundary, and
	// sharing the fake would put a second race in the test.
	l := New(10, testWindow)

	const callers = 1000
	var wg sync.WaitGroup
	admitted := make([]bool, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			admitted[i] = l.Allow("k")
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
		t.Errorf("%d of %d concurrent callers admitted, want exactly 10: check-and-charge is atomic", got, callers)
	}
}
