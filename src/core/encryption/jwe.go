package encryption

import (
	"crypto/sha256"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/pkg/errors"
)

// The encrypted id_token_hint scheme (see the docs at
// integration/endpoints.mdx, "Encrypting the ID token hint"):
//
//	alg = dir      key management: the derived key IS the content-encryption key
//	enc = A256GCM  content encryption: AES-256-GCM
//	key = SHA-256(UTF-8 client_secret)   (always 32 bytes)
//
// This implements OpenID Connect Core 1.0 §2 (an encrypted ID Token is a Nested
// JWT: the signed ID Token wrapped in a JWE) together with RP-Initiated Logout's
// symmetrically-encrypted id_token_hint, which is keyed off the client_id so the
// OP knows whose secret to derive the key from.
//
// idTokenHintKeyAlgorithms and idTokenHintContentEncryption are a strict,
// single-element allowlist passed to the JWE parser. Pinning the accepted alg
// and enc (rather than trusting the values in the JWE header) prevents
// algorithm-substitution and downgrade attacks: a caller cannot swap in a
// weaker content cipher, an asymmetric key-management alg, or "none".
var (
	idTokenHintKeyAlgorithms     = []jose.KeyAlgorithm{jose.DIRECT}
	idTokenHintContentEncryption = []jose.ContentEncryption{jose.A256GCM}
)

// DeriveIDTokenHintKey derives the 32-byte AES-256 key used to decrypt an
// encrypted id_token_hint from the client secret (SHA-256 of the UTF-8 client
// secret). Exported so tests and tooling derive the key exactly the way the
// decrypt path does.
func DeriveIDTokenHintKey(clientSecret string) []byte {
	sum := sha256.Sum256([]byte(clientSecret))
	return sum[:]
}

// DecryptIDTokenHintJWE decrypts a compact-serialized JWE id_token_hint with a
// key derived from the client secret and returns the plaintext, which is the
// inner signed ID Token (a compact JWS) to be validated by the caller. Only the
// dir + A256GCM scheme is accepted; any other alg/enc is rejected at parse time.
func DecryptIDTokenHintJWE(compactJWE string, clientSecret string) (string, error) {
	if len(compactJWE) == 0 {
		return "", errors.WithStack(errors.New("id_token_hint is empty"))
	}
	if len(clientSecret) == 0 {
		return "", errors.WithStack(errors.New("client secret is empty"))
	}

	object, err := jose.ParseEncryptedCompact(compactJWE, idTokenHintKeyAlgorithms, idTokenHintContentEncryption)
	if err != nil {
		return "", errors.Wrap(err, "id_token_hint is not a valid JWE (expected dir/A256GCM)")
	}

	plaintext, err := object.Decrypt(DeriveIDTokenHintKey(clientSecret))
	if err != nil {
		return "", errors.Wrap(err, "id_token_hint decryption failed")
	}

	return string(plaintext), nil
}
