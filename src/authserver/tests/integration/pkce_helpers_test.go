package integration

import (
	"crypto/sha256"
	"encoding/base64"
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
