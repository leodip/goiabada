// Package passwordhash holds the bcrypt half of what used to be core/hashutil: hashing a user's
// password and checking one, plus the dummy hash the enumeration-safe login path compares against.
// It belongs to the auth server because the auth server is the only process that ever sees a
// password; the admin console talks to it over HTTP and must not compile bcrypt at all (#360).
package passwordhash

import (
	"github.com/leodip/goiabada/core/errs"
	"golang.org/x/crypto/bcrypt"
)

// DummyHash is a pre-computed bcrypt hash used for timing-safe user enumeration protection.
// When a user lookup fails (user doesn't exist), we still perform a bcrypt comparison against
// this dummy hash to ensure the response time is similar to when a user does exist.
// This prevents attackers from determining whether an email exists based on response timing.
// The hash was generated using bcrypt.DefaultCost (10) for the string "dummy_password_for_timing_safe_comparison".
const DummyHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// MaxPasswordBytes is the longest password bcrypt operates on, in bytes: golang.org/x/crypto's
// GenerateFromPassword refuses anything longer with bcrypt.ErrPasswordTooLong rather than truncate
// it. Bytes and not characters, so a password of accented or other non-ASCII characters reaches it
// sooner. Every path that hashes a password it did not choose checks this bound first, so the
// refusal names the input rather than surfacing as a hashing failure (#409).
const MaxPasswordBytes = 72

// Hash returns the bcrypt hash of password at bcrypt.DefaultCost. A password longer than
// MaxPasswordBytes is refused with an error wrapping bcrypt.ErrPasswordTooLong, never truncated.
func Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", errs.Wrap(err, "unable to hash")
	}
	return string(hash), nil
}

// Verify reports whether password matches hashedPassword. bcrypt reads only the first
// MaxPasswordBytes bytes when it compares, so a longer password matches the hash of its own
// 72-byte prefix; no stored hash is of a longer one, because Hash refuses those.
func Verify(hashedPassword string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
