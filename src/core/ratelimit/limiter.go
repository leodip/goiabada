// Package ratelimit provides the sliding-window request counter and the client-IP
// canonicaliser the middleware rate limiter is built on.
//
// A Limiter divides time into fixed windows anchored at its own construction instant
// and keeps a count per key for the current window and the previous one. The rate it
// answers with is the current window's count plus the previous window's, decayed
// linearly by how far into the current window the request arrived:
//
//	rate = prev*(window-elapsed)/window + curr
//
// A key is admitted while round(rate)+1 is within the limit. That is the arithmetic
// and the predicate go-chi/httprate applied, reproduced here so that retiring it
// changed no budget, no key and no admit-or-refuse decision at any tier (#276).
// The tiers, budgets and keys themselves are #219's and are not this package's to
// decide; it only counts.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Limiter counts hits per key over a sliding window and answers whether one more
// would exceed the limit. It is safe for concurrent use.
type Limiter struct {
	limit  int
	window time.Duration

	// anchor fixes the phase of every window: they start at anchor + k*window. It is
	// the construction instant, not a wall-clock boundary, so two limiters built a
	// moment apart roll at different instants. Gate exists because the audit gate
	// must not be one of those (#276).
	anchor time.Time

	store Store

	// now is time.Now in production. Only this package's own tests replace it: the
	// alternative, an exported clock option, is a public test hook on a
	// security-relevant type, and nothing above this package needs to move time.
	now func() time.Time

	// ceiling: one mutex serialises every key of this limiter, so a tier admits one
	// check-and-charge at a time per process. That is httprate's own shape, and the
	// limited routes are login forms and a token grant rather than a hot path.
	// Revisit when a profile shows contention here contributing measurably to the
	// latency of a limited route; sharding the store by key is the next shape (#276).
	mu sync.Mutex
}

// Option configures a Limiter at construction.
type Option func(*Limiter)

// WithStore replaces the in-process store. It exists so that a test can inject a
// store which fails, which is the only way to reach the fail-closed paths: the
// in-process store cannot produce an error.
func WithStore(s Store) Option {
	return func(l *Limiter) { l.store = s }
}

// New returns a Limiter admitting limit hits per key per window, anchored at this
// instant.
func New(limit int, window time.Duration, opts ...Option) *Limiter {
	l := &Limiter{
		limit:  limit,
		window: window,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(l)
	}
	l.anchor = l.now()
	if l.store == nil {
		l.store = newMemStore(window)
	}
	return l
}

// Allow reports whether one more hit on key is within the budget, and charges it when
// it is. It is the check-and-charge the every-request tiers need, atomic because the
// whole of it happens under the limiter's mutex.
//
// It answers false when the store fails: a limiter that cannot count refuses rather
// than admits (#276).
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.allowLocked(key)
}

// Rate returns the decayed hit count for key without charging anything. The
// failures-only tier reads it to decide whether a request may be reserved, and applies
// its own predicate to the result.
func (l *Limiter) Rate(key string) (float64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	current, previous, elapsed := l.windows(l.now())
	curr, prev, err := l.store.Get(key, current, previous)
	if err != nil {
		return 0, err
	}
	return l.rate(curr, prev, elapsed), nil
}

// Add charges one hit against key without checking the budget. The failures-only tier
// calls it to record a failure it has already decided to count.
func (l *Limiter) Add(key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	current, _, _ := l.windows(l.now())
	return l.store.Add(key, current)
}

// allowLocked is Allow's body, split out so that it can be called with the lock held
// or, under a mutation, without it. The caller holds l.mu.
func (l *Limiter) allowLocked(key string) bool {
	current, previous, elapsed := l.windows(l.now())
	curr, prev, err := l.store.Get(key, current, previous)
	if err != nil {
		return false
	}
	if int(math.Round(l.rate(curr, prev, elapsed)))+1 > l.limit {
		return false
	}
	return l.store.Add(key, current) == nil
}

// windows returns the start of the window now falls in, the start of the one before
// it, and how far into the current window now is.
//
// now is always at or after the anchor: both come from the same clock, and the anchor
// is taken when the limiter is built. Production reads time.Now, whose monotonic
// reading makes Sub immune to a wall-clock step, and the tests' clock only advances.
func (l *Limiter) windows(now time.Time) (current, previous time.Time, elapsed time.Duration) {
	current = l.anchor.Add(now.Sub(l.anchor).Truncate(l.window))
	return current, current.Add(-l.window), now.Sub(current)
}

// rate decays the previous window's count by how far into the current window the
// request arrived, and adds the current window's.
func (l *Limiter) rate(curr, prev int, elapsed time.Duration) float64 {
	return float64(prev)*float64(l.window-elapsed)/float64(l.window) + float64(curr)
}
