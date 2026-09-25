// Package hashutil hashes a string with SHA-256. It stays in core while the rest of what this
// package held moved to authserver/internal/passwordhash, because both processes reach it
// independently: the auth server hashes authorization, verification and reset codes to locate rows,
// and the admin console hashes the nonce it sends, and again to check the ID token's (#360, #427).
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
