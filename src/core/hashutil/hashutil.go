package hashutil

import (
	"crypto/sha256"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// DummyPasswordHash is a pre-computed bcrypt hash used for timing-safe user enumeration protection.
// When a user lookup fails (user doesn't exist), we still perform a bcrypt comparison against
// this dummy hash to ensure the response time is similar to when a user does exist.
// This prevents attackers from determining whether an email exists based on response timing.
// The hash was generated using bcrypt.DefaultCost (10) for the string "dummy_password_for_timing_safe_comparison".
const DummyPasswordHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// HashString can hash strings of any length
func HashString(s string) (string, error) {
	h := sha256.New()
	_, err := h.Write([]byte(s))
	if err != nil {
		return "", errors.Wrap(err, "unable to hash")
	}
	bs := h.Sum(nil)
	hex := fmt.Sprintf("%x", bs)
	return hex, nil
}

func VerifyStringHash(hashedString string, s string) bool {
	hash, err := HashString(s)
	if err != nil {
		return false
	}
	return hash == hashedString
}

// The maximum length for password is 72 bytes
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.Wrap(err, "unable to hash")
	}
	return string(hash), nil
}

func VerifyPasswordHash(hashedPassword string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
