package ratelimit

import (
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
// The mutex and inFlight are not bookkeeping. The limiter serializes check-and-charge inside
// Allow, but this type cannot use Allow: it must decide before the credential is checked and
// charge only afterwards. Rate only reads, so a gate written as read, check credential,
// charge admits every caller that reads before anyone charges: measured at 141 of 1000
// overlapping callers against a budget of 10, and the sample varies between runs because it
// is scheduler-dependent, which is the finding. The attacker picks the concurrency.
//
// A FailureLimiter is safe for concurrent use.
type FailureLimiter struct {
	rl    *Limiter
	limit int
	mu    sync.Mutex
	// inFlight counts the reservations currently held per key. It self-cleans: the entry
	// is deleted at zero, so it holds only what is genuinely in flight.
	inFlight map[string]int
}

// NewFailureLimiter returns a FailureLimiter admitting limit failures per key per window,
// anchored at this instant.
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

// Reserve claims one slot against key's budget, atomically with reading what is already
// recorded, and reports whether another credential check may proceed. Every true must be
// matched by one Release.
//
// The predicate is the limiter's own, round(rate)+1 > limit, plus the in-flight count. It is
// applied here rather than by calling Allow because Allow charges what it admits, and this
// type charges only once the credential has been found wrong.
//
// Returns false when Rate errors, so the limiter fails closed. That branch is unreachable
// in production, since the in-process store cannot fail, but the direction has to be stated
// because it is the one an error path gets wrong.
func (f *FailureLimiter) Reserve(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	rate, err := f.rl.Rate(key)
	if err != nil {
		return false
	}
	if int(math.Round(rate))+f.inFlight[key]+1 > f.limit {
		return false
	}
	f.inFlight[key]++
	return true
}

// Release hands the slot back, charging it first when the credential was wrong.
//
// Add charges without checking, which is what this path wants: the decision was taken at
// Reserve. Its error is dropped for the same reason the slot is handed back regardless --
// the in-process store cannot fail, and a failed charge here has no caller left to answer.
// Charging before dropping the slot keeps recorded plus in-flight from ever dipping below
// what has been spent; the transient double-count that produces refuses one extra caller
// rather than admitting one, which is the safe direction.
func (f *FailureLimiter) Release(key string, failed bool) {
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
