package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// AccountLimiter is the two-tier budget a password check passes through: a tight budget per
// (account, client block) and a loose account-wide backstop, charged from the same failure
// event. One AccountLimiter serves every route that checks the same secret, because a
// password guessed against one account is one event wherever it arrives.
//
// One tier alone cannot do this. A limiter consulted before the credential is checked cannot
// know the incoming password is the right one, so a single account-wide budget lets anyone
// who knows an address refuse its owner by spending it, and tightening that budget makes
// the denial cheaper rather than dearer. Splitting it means an ordinary single-source
// attacker burns only their own network's bucket while the owner signs in normally, and the
// account-wide ceiling RFC 6749 Section 4.3.2 makes a MUST still exists.
//
// Residual, accepted: an attacker producing failures from as many distinct blocks as the
// backstop's budget over the tight one still exhausts the backstop and denies the owner for
// the rest of its window. That is the price of having an account-wide ceiling at all (#219).
//
// The budgets and windows are the caller's: this type only composes the two tiers.
type AccountLimiter struct {
	tight    *FailureLimiter
	backstop *FailureLimiter
}

// NewAccountLimiter composes the tight per-(network, account) tier and the account-wide
// backstop into one limiter that reserves and charges them together.
func NewAccountLimiter(tight, backstop *FailureLimiter) *AccountLimiter {
	return &AccountLimiter{tight: tight, backstop: backstop}
}

// Refusal names which tier of an AccountLimiter refused a reservation, so the caller can
// report the trip against that tier and answer with its window.
type Refusal int

const (
	// Admitted means both tiers reserved a slot, to be handed back by one Release.
	Admitted Refusal = iota
	// RefusedTight means the per-(network, account) tier refused; nothing is held.
	RefusedTight
	// RefusedBackstop means the account-wide tier refused; nothing is held.
	RefusedBackstop
)

// Reserve claims a slot on both tiers, or on neither. The tight slot is handed back when the
// backstop refuses, so a refusal never strands one: in-flight slots do not decay, and a slot
// kept here would lock that network out of the account until the process restarted, long
// after the backstop's window had passed (#439).
func (a *AccountLimiter) Reserve(networkKey, accountKey string) Refusal {
	if !a.tight.Reserve(networkKey) {
		return RefusedTight
	}
	if !a.backstop.Reserve(accountKey) {
		a.tight.Release(networkKey, false)
		return RefusedBackstop
	}
	return Admitted
}

// Release charges or drops both tiers together, which is what keeps them counting the same
// events. It matches one Reserve that answered Admitted.
func (a *AccountLimiter) Release(networkKey, accountKey string, failed bool) {
	a.backstop.Release(accountKey, failed)
	a.tight.Release(networkKey, failed)
}

// AccountKey buckets by the account an identifier names rather than by the
// spelling submitted. Deliberately stricter than the strictest engine: mysql and mssql
// compare email case-insensitively and postgres and sqlite do not, so without this the
// same account has one bucket on two engines and 2^18 on the other two (#219).
//
// The handlers that look the account up normalize identically, so the limiter and the
// account it protects cannot disagree about who the request is.
//
// The result is bounded in length, because it becomes a map key the limiter's store
// retains for two windows and it is read straight off an unauthenticated form. None of
// the routes keyed on it caps its body, so without the bound net/http's 10 MiB form limit
// is the only ceiling on what one accepted request can make the process hold, and the
// forgot-password route accepts twenty per client block per window. httprate retained 8
// bytes whatever arrived because it hashed every key to a uint64; this package stores exact
// keys, which is what stops two accounts sharing a bucket, and digesting the overlong tail
// here is what that costs (#276). It also bounds the key a trip puts in the warning line
// and the audit event.
//
// A long identifier is digested rather than folded into one shared bucket. Two accounts
// landing on one key is the cross-account leak this function exists to prevent, and
// nothing bounds an account identifier's length on the way in: self-registration and the
// setup program validate the shape without a length and users.email is TEXT on sqlite,
// so a real account can sit past any threshold chosen here, and a shared bucket would
// then spend that account's budget on strangers' submissions (#276).
//
// A bounded key over an unbounded set of identifiers cannot be injective, so what the
// digest buys is not injectivity but unreachability. The exact branch is injective, the
// prefix test above keeps the two branches disjoint, and putting two accounts in one
// bucket through the digest branch means producing a SHA-256 collision. The width is the
// reason that holds: a 64-bit hash collides at around 2^32 attempts, which is constructible
// and is the shared-bucket defect again in a different shape, while SHA-256 puts a collision
// between two identifiers an attacker is free to choose at around 2^128. Aiming at one
// particular account is harder still, and it is the case that would matter: making some
// other submission land in that account's bucket is a second preimage of its digest, around
// 2^256, not any colliding pair (#276).
func AccountKey(identifier string) string {
	normalized := strings.ToLower(strings.TrimSpace(identifier))
	// The prefix test is what keeps the two branches from sharing a namespace. Without
	// it a short submission can be spelled as a digest key -- "<sha256>" and sixty-four
	// hex characters is seventy-two octets, well inside the bound -- and lands in the
	// bucket of whichever long identifier digests to it, no SHA-256 collision required.
	// Digesting such a submission instead means the exact branch never emits a key
	// carrying the prefix, so the two branches cannot meet (#276).
	if len(normalized) > maxAccountIdentifierLen || strings.HasPrefix(normalized, oversizedAccountKeyPrefix) {
		// Over a 10 MiB form value this copies and digests what net/http has already
		// parsed and allocated; what matters is that nothing of that size is retained.
		sum := sha256.Sum256([]byte(normalized))
		return oversizedAccountKeyPrefix + hex.EncodeToString(sum[:])
	}
	return normalized
}

// maxAccountIdentifierLen is where exact keying stops and the digest begins. It is a
// legibility threshold rather than a security boundary: correctness does not depend on
// its value, because wherever it sits the exact branch stays injective, the two branches
// stay disjoint, and a collision inside the digest branch stays out of reach, so two
// accounts cannot be made to share a bucket. It is set at the longest address RFC
// 5321 sections 4.5.3.1.1 and 4.5.3.1.2 allow for a local-part and a domain, plus the
// '@', so every address a deployment could plausibly hold stays readable in the warning
// line and the audit event rather than arriving there as 64 hex characters.
const maxAccountIdentifierLen = 64 + 1 + 255

// oversizedAccountKeyPrefix marks a digested key, so a reader of an audit event can tell
// one from an address. It is also reserved: AccountKey digests any submission spelled to
// start with it, however short. The digest keys it marks are written to the warning line
// and to the audit event, so without that a reader of either could spend a long account's
// rate-limit budget by submitting its key straight back, never having known the identifier
// behind it (#276).
const oversizedAccountKeyPrefix = "<sha256>"
