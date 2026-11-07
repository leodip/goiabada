package protocolvalidation

import (
	"encoding/base64"
	"net/http"

	"github.com/leodip/goiabada/core/oauth"
)

// RFC 7636 section 4.1 defines code_verifier as 43*128unreserved: 43 to 128 characters of ALPHA,
// DIGIT, "-", ".", "_" and "~". Section 4.2 puts the challenge in the same production, but an S256
// challenge is BASE64URL(SHA256(ASCII(code_verifier))), so only one 43-character form of it can
// ever equal what the token endpoint computes, and the authorization endpoint holds a challenge to
// that form instead (isBase64URLSHA256, #714). A value outside it used to fail only at the
// exchange, after the user had signed in (#244).
const (
	pkceMinLength = 43
	pkceMaxLength = 128
)

// hasPKCELength reports whether value is 43 to 128 bytes long, which for a value that also passes
// isPKCECharset is 43 to 128 characters.
func hasPKCELength(value string) bool {
	return len(value) >= pkceMinLength && len(value) <= pkceMaxLength
}

// isPKCECharset reports whether every character of value is one of RFC 7636's unreserved set. It is
// ASCII only, so a multi-byte character is refused whatever the length of the value.
func isPKCECharset(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// isPKCEValue reports whether value is a well-formed code_verifier.
func isPKCEValue(value string) bool {
	return hasPKCELength(value) && isPKCECharset(value)
}

// pkceCharsetText names the verifier's set in its refusal, so an integrator reads the rule from it.
const pkceCharsetText = "A-Z, a-z, 0-9, '-', '.', '_' and '~'"

// sha256Base64URLLength is the length of the unpadded base64url form of a SHA-256 hash: 32 bytes
// are 256 bits, which take 43 characters of six bits, the last character's two low bits spare.
const sha256Base64URLLength = 43

// sha256Base64URL is the strict unpadded base64url decoder: it refuses a value whose spare bits are
// not zero, which is no canonical encoding of any hash.
var sha256Base64URL = base64.RawURLEncoding.Strict()

// isBase64URLSHA256 reports whether value is the canonical base64url form, unpadded, of a SHA-256
// hash: what an S256 code_challenge is (RFC 7636 section 4.2), and what an RFC 7638 SHA-256 JWK
// thumbprint is. It checks, in order, exactly 43 characters, each of A-Z, a-z, 0-9, "-" and "_",
// before any decoding, since the standard library's decoder skips CR and LF even in strict mode;
// then a strict decode, which refuses non-zero spare bits; then 32 bytes (#42 decision 20).
func isBase64URLSHA256(value string) bool {
	if len(value) != sha256Base64URLLength {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '_':
		default:
			return false
		}
	}
	decoded, err := sha256Base64URL.DecodeString(value)
	return err == nil && len(decoded) == 32
}

// s256ChallengeRuleText is the rule an S256 challenge is refused under, in both PKCE branches.
const s256ChallengeRuleText = "It must be the SHA-256 hash of the code_verifier, base64url-encoded without padding: 43 characters of A-Z, a-z, 0-9, '-' and '_'."

// codeChallengeRefusal answers an S256 code_challenge that cannot be a SHA-256 hash, at the
// authorization endpoint: invalid_request. A client that has to use PKCE is told the challenge may
// be missing, which is how it learns that it must send one.
func codeChallengeRefusal(pkceRequired bool) error {
	description := "The code_challenge parameter is incorrect. " + s256ChallengeRuleText
	if pkceRequired {
		description = "The code_challenge parameter is either missing or incorrect. " + s256ChallengeRuleText
	}
	return oauth.NewErrorDetailWithHTTPStatus("invalid_request", description, http.StatusBadRequest)
}

// codeVerifierMalformedRefusal answers a code_verifier that is not 43 to 128 characters of RFC 7636
// section 4.1's set, at the token endpoint. RFC 7636 section 4.6 answers a verifier that cannot
// match with invalid_grant, and a value that is not a verifier at all cannot.
func codeVerifierMalformedRefusal() error {
	return oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
		"The code_verifier parameter is incorrect. It should be 43 to 128 characters long and may only contain "+pkceCharsetText+".",
		http.StatusBadRequest)
}
