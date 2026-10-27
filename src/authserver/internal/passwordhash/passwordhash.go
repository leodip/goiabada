// Package passwordhash hashes a user's password with bcrypt and checks one, and holds the dummy
// hash the enumeration-safe sign-in paths compare against. It belongs to the auth server because the
// auth server is the only process that ever sees a password; the admin console talks to it over
// HTTP and must not compile bcrypt at all (#360).
package passwordhash

import (
	"sync"

	"github.com/leodip/goiabada/core/errs"
	"golang.org/x/crypto/bcrypt"
)

// MaxPasswordBytes is the longest password bcrypt operates on, in bytes: golang.org/x/crypto's
// GenerateFromPassword refuses anything longer with bcrypt.ErrPasswordTooLong rather than truncate
// it. Bytes and not characters, so a password of accented or other non-ASCII characters reaches it
// sooner. Every path that hashes a password it did not choose checks this bound first, so the
// refusal names the input rather than surfacing as a hashing failure (#409).
const MaxPasswordBytes = 72

// DummyHash returns a pre-computed bcrypt hash that a refusal compares the typed password against,
// so it costs one comparison as a wrong password does and the response time says nothing about the
// account. Its two callers, the sign-in form (authflow.PasswordSubmission) and the password grant
// (protocolvalidation.TokenValidator), each compare against it in two cases: an address naming no
// account, so the time does not say which emails have accounts; and an account with no password
// yet, whose empty stored hash bcrypt would refuse without doing any work, so the time does not
// say whether its user has set one. Both refuse whatever the comparison says, so its plaintext
// signs no one in (#681).
//
// It is selected through the same gate as Hash's cost, so the two stay a pair: a race build
// under go test compares against a bcrypt.MinCost dummy, and every other build and run against
// the default-cost one (#691). The selection is made on the first call rather than at package
// init, because go test registers the flag the gate looks for after packages initialise.
func DummyHash() string {
	return selectedDummyHash()
}

var selectedDummyHash = sync.OnceValue(func() string {
	if raceBuildTestRun() {
		return raceBuildDummyHash
	}
	return defaultDummyHash
})

// defaultDummyHash is the dummy every build compares against outside a race build under go test.
// The hash was generated using bcrypt.DefaultCost (10) for the string "dummy_password_for_timing_safe_comparison".
const defaultDummyHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// Hash returns the bcrypt hash of password. The cost is bcrypt.DefaultCost everywhere except a
// race build running under go test, where it is bcrypt.MinCost: the detector multiplies what a
// comparison costs until bcrypt dominates the race tier, and the rounds' count is invisible to it
// (#691). A password longer than MaxPasswordBytes is refused with an error wrapping
// bcrypt.ErrPasswordTooLong, never truncated.
func Hash(password string) (string, error) {
	cost := bcrypt.DefaultCost
	if raceBuildTestRun() {
		cost = raceBuildHashCost
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", errs.Wrap(err, "unable to hash")
	}
	return string(hash), nil
}

// Verify reports whether password matches hashedPassword, compared whole. bcrypt keys on at most
// MaxPasswordBytes bytes, so on its own it would match a stored password of exactly that length
// with anything appended; a password longer than MaxPasswordBytes is therefore refused before
// comparing. No stored hash is of a longer one, because Hash refuses those, so the refusal costs no
// one a sign-in. The comparisons against DummyHash take the same refusal, so they say nothing about
// which accounts exist (#550).
func Verify(hashedPassword string, password string) bool {
	if len(password) > MaxPasswordBytes {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
