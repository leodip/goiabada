// Package passwordhash hashes a user's password with bcrypt and checks one, and holds the dummy
// hash the enumeration-safe sign-in paths compare against. It belongs to the auth server because the
// auth server is the only process that ever sees a password; the admin console talks to it over
// HTTP and must not compile bcrypt at all (#360).
package passwordhash

import (
	"github.com/leodip/goiabada/core/errs"
	"golang.org/x/crypto/bcrypt"
)

// MaxPasswordBytes is the longest password bcrypt operates on, in bytes: golang.org/x/crypto's
// GenerateFromPassword refuses anything longer with bcrypt.ErrPasswordTooLong rather than truncate
// it. Bytes and not characters, so a password of accented or other non-ASCII characters reaches it
// sooner. Every path that hashes a password it did not choose checks this bound first, so the
// refusal names the input rather than surfacing as a hashing failure (#409).
const MaxPasswordBytes = 72

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
