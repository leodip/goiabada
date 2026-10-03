// Package hashutil hashes a string with SHA-256. It is in core because both processes reach it
// independently: the auth server hashes authorization, verification and reset codes to locate rows,
// and the admin console hashes the nonce it sends, and again to check the ID token's. Password
// hashing is the auth server's alone, in authserver/internal/passwordhash (#360, #427).
package hashutil

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashString is the lowercase hex SHA-256 of s. It returns no error because SHA-256 over a byte
// slice has none to give: hash.Hash's Write never fails, and the error it used to wrap was one no
// caller could reach (#433, #442).
func HashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
