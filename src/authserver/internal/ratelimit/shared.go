package ratelimit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"math"
	"time"

	"github.com/leodip/goiabada/core/errs"
)

// A shared FailureLimiter counts in the database, so every replica sharing it spends one budget.
// What follows records #394's decisions 1 to 4 so they are not re-derived.
//
// WHICH TIERS. Only the five failures-only tiers, the credential-guessing limits, count here.
// They are the security controls, the ones a standard puts a number on: NIST SP 800-63B's
// ceiling of 100 consecutive failures per account and RFC 6749 Section 4.3.2's MUST that the
// password grant resist brute force. Per process, N replicas make that ceiling 100*N, and every
// rollout refills it. They are also the cheap tiers to share: a credential check already depends
// on the database, and a couple of short statements sit beside a bcrypt. The per-IP tiers exist
// to refuse a flood for free and the mail tiers bound a nuisance, so both stay in memory, per
// pod, where a database write would turn a flood into database load; a deployment wanting those
// shared puts a request limit at its gateway. Rejected: a database store for every tier, which puts
// a write on every request of a flood; dividing budgets by a replica count, which breaks under
// autoscaling and rollouts and cannot divide a budget of 5; Redis, a new runtime dependency on the
// login path.
//
// WHERE. On PostgreSQL, MySQL and SQL Server, with no setting (the server's sharedCredentialCounts
// chooses); SQLite cannot have a second replica and counts in memory. A memory default behind a
// switch was rejected, because every multi-replica operator who never found the switch would keep
// the defect, and the database adds no requirement a deployment does not already meet.
//
// HOW A ROW IS KEYED. By the SHA-256 of the tier name, a NUL and the key, never the key: the
// table only has to count an email address or an IP block, not hold one. A window starts at a
// multiple of its length since the Unix epoch, so every pod places a request in the same window;
// pods' wall clocks decide it, and NTP skew moves a boundary by a fraction of a second against
// windows of minutes. The warning line and the audit event keep the readable key; the audit gate
// stays in each process, so a trip is audited at most once per key, per window, per replica. Raw
// keys were rejected: the table would hold addresses and IP blocks only to count them. Every
// instance sweeps rows whose two windows have passed at every poll, outside the cleanup claim,
// because an unauthenticated caller can create them.
//
// HOW A SLOT IS HELD. A reservation is a charge: Reserve increments the current window when the
// decayed rate, the in-memory limiter's arithmetic, admits one more, atomically across every pod
// (data.Database's ReserveRateLimitHit says how). A wrong credential keeps the charge; a right
// one is refunded from the window it was charged in. So a successful check spends nothing once
// it completes, and the in-flight protection #219 measured holds across pods rather than per
// pod. A pod that dies between the two leaves one charge behind, which decays with its window:
// the refusing direction. A separate table of leased reservations was rejected: twice the table and
// the statements, and a lease length to tune, for nothing the charge and its refund lack.
//
// WHEN THE STORE CANNOT ANSWER. Each call is bounded at storeCallBound, the wait for a pool
// connection included, and reaching it is a failure. Reserve then returns an error and no
// slot, so the credential is never checked without the count's answer, and the caller answers
// a fault rather than a trip: the 500 its route gives any fault, in the shape its caller parses,
// with the one Error record that 500 owes, and no Retry-After, rate-limit warning or audit event.
// A 429 would send a client into a backoff loop and report an outage as an attack. The refund
// runs detached from the request's cancellation, so a client hanging up after a right password
// does not leave the charge behind; when it fails anyway the charge stays, which is the refusing
// direction again.

// sharedStore is what a shared limiter asks of the database.
type sharedStore interface {
	ReserveRateLimitHit(ctx context.Context, keyHash string, current, previous, expiresAt time.Time,
		admit func(curr, prev int) bool) (bool, error)
	RefundRateLimitHit(ctx context.Context, tx *sql.Tx, keyHash string, windowStart time.Time) error
}

// storeCallBound is how long one call to the shared store may take: two orders of magnitude above
// the two short statements a reservation costs, and finite, so a slow database cannot hold a
// sign-in for as long as the client is willing to wait.
const storeCallBound = 5 * time.Second

// NewSharedFailureLimiter returns a FailureLimiter admitting limit failures per key per window,
// counted in store under tier's name, so every limiter built over the same database and tier
// spends one budget. Windows are aligned to the Unix epoch rather than to this instant.
func NewSharedFailureLimiter(store sharedStore, tier string, limit int, window time.Duration) *FailureLimiter {
	rl := New(limit, window)
	rl.anchor = time.Unix(0, 0).UTC()
	return &FailureLimiter{
		rl:     rl,
		limit:  limit,
		shared: store,
		tier:   tier,
		bound:  storeCallBound,
	}
}

// reserveShared is Reserve over the database.
func (f *FailureLimiter) reserveShared(ctx context.Context, key string) (*Reservation, error) {
	current, previous, elapsed := f.rl.windows(f.rl.now())
	admit := func(curr, prev int) bool {
		return int(math.Round(f.rl.rate(curr, prev, elapsed)))+1 <= f.limit
	}

	ctx, cancel := context.WithTimeout(ctx, f.bound)
	defer cancel()

	keyHash := f.keyHash(key)
	admitted, err := f.shared.ReserveRateLimitHit(ctx, keyHash, current, previous,
		current.Add(2*f.rl.window), admit)
	if err != nil {
		return nil, errs.Wrapf(err, "unable to reserve against the shared %s rate limit", f.tier)
	}
	if !admitted {
		return nil, nil
	}
	return &Reservation{limiter: f, key: key, window: current}, nil
}

// releaseShared keeps the charge for a wrong credential and refunds it, from the window it was
// charged in, for a right one.
func (r *Reservation) releaseShared(ctx context.Context, failed bool) error {
	if failed {
		return nil
	}

	f := r.limiter
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), f.bound)
	defer cancel()

	if err := f.shared.RefundRateLimitHit(ctx, nil, f.keyHash(r.key), r.window); err != nil {
		return errs.Wrapf(err, "unable to refund the shared %s rate limit", f.tier)
	}
	return nil
}

// keyHash is the digest a key is counted under: the SHA-256 of the tier name, a NUL and the key,
// in lowercase hex. The NUL keeps the pair unambiguous, since no tier name carries one.
func (f *FailureLimiter) keyHash(key string) string {
	sum := sha256.Sum256([]byte(f.tier + "\x00" + key))
	return hex.EncodeToString(sum[:])
}
