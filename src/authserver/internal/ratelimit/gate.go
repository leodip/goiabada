package ratelimit

import (
	"sync"
	"time"
)

// Gate answers "is this the first time this key has come up in this window", once per
// window, and is what the audit gate on a rejection needs: one event per key per
// window rather than one per rejected request.
//
// It is deliberately not a Limiter of budget 1. A sliding limiter with one hit in the
// previous window answers a rate of 1-f at fraction f into the current one, and
// round(1-f)+1 > 1 holds for every f up to a half, so it goes on refusing through the
// first half of the window however it is aligned -- a rejection twenty seconds into the
// next minute would never be reported. Gate is fixed-window instead: it reads the
// current window's count, ignores the previous window's entirely, and answers true
// exactly once per window (#276).
//
// A Gate shares its parent limiter's window, phase and clock, so it rolls at the same
// instant the limiter it reports on does. That is what makes the guarantee exact rather
// than "at most one per window and at most two per window length in the worst phase",
// which is what two independently anchored limiters could promise (#219, #276).
//
// A Gate always counts in an in-process store, even when its parent was built with
// WithStore: the injectable store exists to reach a Limiter's fail-closed paths, and an
// audit gate has none to reach. Gate is safe for concurrent use.
type Gate struct {
	window time.Duration
	anchor time.Time
	now    func() time.Time
	store  gateStore
	mu     sync.Mutex
}

// gateStore is what a Gate asks of a store: memStore's unexported half, which answers
// without an error because a Gate has no failure path to reach.
//
// It is an interface rather than *memStore for one reason, and it is a testing reason.
// First is a compound read-and-record whose whole correctness is that one mutex covers
// all of it, and a concurrency test that asserts the outcome only reports that the race
// did not happen this time. Checking the lock directly needs a caller suspended inside
// the section, and now() sits one statement into it, so parking there pins the entrance
// and says nothing about the read and the record after it: an unlock moved below now(),
// or below the read, leaves both Gate concurrency cases green in a hundred runs. A store
// that parks inside the write puts the check at the last instant of the section instead,
// where an unlock anywhere above it is visible (#276).
//
// Production is always a memStore, because Gate() is the only constructor and it builds
// one; nothing outside this package can substitute, the interface being unexported.
type gateStore interface {
	get(key string, current, previous time.Time) (curr, prev int)
	add(key string, current time.Time)
}

// Gate returns a fresh gate over this limiter's window, phase and clock. Its counts are
// its own: gating a key does not spend any of the limiter's budget.
func (l *Limiter) Gate() *Gate {
	return &Gate{
		window: l.window,
		anchor: l.anchor,
		now:    l.now,
		store:  newMemStore(l.window),
	}
}

// First reports whether key has not yet been seen in the current window, and records it
// when it has not. Every later call in the same window answers false.
func (g *Gate) First(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	current := g.anchor.Add(now.Sub(g.anchor).Truncate(g.window))
	previous := current.Add(-g.window)

	// The previous window's count is read and discarded: whether a key came up before
	// the boundary has no bearing on whether this is the first time since it.
	curr, _ := g.store.get(key, current, previous)
	if curr > 0 {
		return false
	}
	g.store.add(key, current)
	return true
}
