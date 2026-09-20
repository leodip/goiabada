// Package hashutil hashes a string with SHA-256 and checks one against its hash. It stays in core
// while the rest of what this package held moved to authserver/internal/passwordhash, because both
// processes reach it independently: the auth server hashes authorization, verification and reset
// codes to locate rows, and the admin console hashes the nonce it sends and re-checks it (#360).
package hashutil

import (
	"crypto/sha256"
	"fmt"

	"github.com/leodip/goiabada/core/errs"
)

// HashString can hash strings of any length
func HashString(s string) (string, error) {
	h := sha256.New()
	_, err := h.Write([]byte(s))
	if err != nil {
		return "", errs.Wrap(err, "unable to hash")
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
