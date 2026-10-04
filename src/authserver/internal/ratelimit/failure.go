package ratelimit

import (
	"context"
	"math"
	"sync"
	"time"
)

// FailureLimiter is a budget only a failed credential check can spend.
//
// A Limiter's Allow charges every request it admits, before the handler knows whether the
// credential was right, which costs a legitimate sign-in from the same allowance an
// attacker spends and is what makes a tight budget unsafe. Counting failures only is what
// lets the budgets built on this sit one to two orders of magnitude below the request
// budgets they replaced: a user who signs in, verifies a code or changes a password
// successfully never touches the counter (#219).
//
// It counts in one of two places. NewFailureLimiter counts in this process's memory, which
// is what a single replica needs. NewSharedFailureLimiter counts in the database, so every
// replica sharing it spends one budget; shared.go says how.
//
// In memory, the mutex and inFlight are not bookkeeping. The limiter serializes
// check-and-charge inside Allow, but this type cannot use Allow: it must decide before the
// credential is checked and charge only afterwards. Rate only reads, so a gate written as
// read, check credential, charge admits every caller that reads before anyone charges:
// measured at 141 of 1000 overlapping callers against a budget of 10, and the sample varies
// between runs because it is scheduler-dependent, which is the finding. The attacker picks
// the concurrency.
//
// A FailureLimiter is safe for concurrent use.
type FailureLimiter struct {
	// rl holds the window, its phase and the clock, and in memory the counts too. A shared
	// limiter's rl is anchored at the Unix epoch and its store is never written: the counts
	// are the database's.
	rl    *Limiter
	limit int
	mu    sync.Mutex
	// inFlight counts the reservations currently held per key, in memory only. It
	// self-cleans: the entry is deleted at zero, so it holds only what is genuinely in
	// flight.
	inFlight map[string]int

	// shared is the database a shared limiter counts in, nil in memory.
	shared sharedStore
	// tier is the shared limiter's name, digested with every key so two tiers never share a
	// row.
	tier string
	// bound is how long one call to the shared store may take, the wait for a pool
	// connection included. storeCallBound in production; only this package's tests shorten
	// it, for the clock's reason (#394).
	bound time.Duration
}

// NewFailureLimiter returns a FailureLimiter admitting limit failures per key per window,
// counted in this process and anchored at this instant.
func NewFailureLimiter(limit int, window time.Duration) *FailureLimiter {
	return &FailureLimiter{
		rl:       New(limit, window),
		limit:    limit,
		inFlight: map[string]int{},
	}
}

// Gate returns a fresh gate over this limiter's window, phase and clock, as Limiter.Gate
// does. Gating a key spends none of the failure budget.
func (f *FailureLimiter) Gate() *Gate {
	return f.rl.Gate()
}

// Reservation is one credential check's slot on a FailureLimiter, held from Reserve until the
// check's verdict is known. Release it exactly once.
type Reservation struct {
	limiter *FailureLimiter
	key     string
	// window is the start of the window a shared limiter charged, which is the window its
	// refund comes out of. Zero in memory.
	window time.Time
}

// Reserve claims one slot against key's budget, atomically with reading what is already
// recorded, and returns it when another credential check may proceed. A nil Reservation is a
// refusal. Every Reservation returned must be released once.
//
// An error means the count could not be read, and comes with no Reservation: the limiter
// fails closed, so the credential check never runs without its answer (#276). In memory that
// branch is unreachable, since the in-process store cannot fail, but the direction has to be
// stated because it is the one an error path gets wrong. ctx bounds a shared limiter's store
// call; the in-memory limiter does not read it.
func (f *FailureLimiter) Reserve(ctx context.Context, key string) (*Reservation, error) {
	if f.shared != nil {
		return f.reserveShared(ctx, key)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// The predicate is the limiter's own, round(rate)+1 > limit, plus the in-flight count.
	// It is applied here rather than by calling Allow because Allow charges what it admits,
	// and this type charges only once the credential has been found wrong.
	rate, err := f.rl.Rate(key)
	if err != nil {
		return nil, err
	}
	if int(math.Round(rate))+f.inFlight[key]+1 > f.limit {
		return nil, nil
	}
	f.inFlight[key]++
	return &Reservation{limiter: f, key: key}, nil
}

// Release hands the slot back, charging it when the credential was wrong.
//
// An error is a shared limiter's refund that did not reach the store, and the charge then
// stays: the refusing direction. In memory it is always nil.
func (r *Reservation) Release(ctx context.Context, failed bool) error {
	if r.limiter.shared != nil {
		return r.releaseShared(ctx, failed)
	}
	r.limiter.releaseInMemory(r.key, failed)
	return nil
}

// releaseInMemory charges first when the credential was wrong, then drops the slot.
//
// Add charges without checking, which is what this path wants: the decision was taken at
// Reserve. Its error is dropped for the same reason the slot is handed back regardless --
// the in-process store cannot fail, and a failed charge here has no caller left to answer.
// Charging before dropping the slot keeps recorded plus in-flight from ever dipping below
// what has been spent; the transient double-count that produces refuses one extra caller
// rather than admitting one, which is the safe direction.
func (f *FailureLimiter) releaseInMemory(key string, failed bool) {
	if failed {
		_ = f.rl.Add(key)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if n := f.inFlight[key]; n <= 1 {
		delete(f.inFlight, key)
	} else {
		f.inFlight[key] = n - 1
	}
}
