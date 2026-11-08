package integration

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/leodip/goiabada/authserver/internal/fake"
)

// testCodeVerifier is a PKCE code_verifier that satisfies RFC 7636 section 4.1, which the token
// endpoint has enforced since #244: 43 to 128 characters of ALPHA, DIGIT, "-", ".", "_" and "~". It
// is 51 characters. A test that needs several distinct verifiers appends a suffix of the same
// alphabet, and one that needs a well-formed verifier that does not match a stored challenge appends
// one to the verifier the challenge came from.
const testCodeVerifier = "code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"

// testCodeChallenge is testCodeVerifier's S256 challenge (RFC 7636 section 4.2), so a ceremony
// started with it issues a code the verifier redeems.
var testCodeChallenge = func() string {
	sum := sha256.Sum256([]byte(testCodeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}()

// randomCodeChallenge is a fresh S256 challenge for an authorization request whose code is never
// redeemed: the challenge of a random verifier, so the authorization endpoint, which holds a
// challenge to the canonical base64url form of a SHA-256 hash (#714), accepts it.
func randomCodeChallenge() string {
	sum := sha256.Sum256([]byte(fake.LetterN(43)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
