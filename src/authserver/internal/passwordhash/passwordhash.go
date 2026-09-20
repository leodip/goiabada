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

// The maximum length for password is 72 bytes
func Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", errs.Wrap(err, "unable to hash")
	}
	return string(hash), nil
}

func Verify(hashedPassword string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
