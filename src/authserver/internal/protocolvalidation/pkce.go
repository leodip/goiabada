package protocolvalidation

import (
	"net/http"

	"github.com/leodip/goiabada/core/oauth"
)

// RFC 7636 section 4.1 defines code_verifier as 43*128unreserved and section 4.2 defines
// code_challenge with the same production, so one grammar answers for both: 43 to 128 characters of
// ALPHA, DIGIT, "-", ".", "_" and "~". A BASE64URL-encoded SHA-256 digest is 43 of them, which is why
// a challenge outside the set can never equal one and used to fail only at the exchange (#244).
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

// isPKCEValue reports whether value is a well-formed code_verifier or code_challenge.
func isPKCEValue(value string) bool {
	return hasPKCELength(value) && isPKCECharset(value)
}

// pkceCharsetText names the set in the two refusals, so an integrator reads the rule from either.
const pkceCharsetText = "A-Z, a-z, 0-9, '-', '.', '_' and '~'"

// codeChallengeCharsetRefusal answers a code_challenge of the right length that uses a character
// outside RFC 7636 section 4.2's set, at the authorization endpoint: invalid_request, as the length
// refusals beside it are.
func codeChallengeCharsetRefusal() error {
	return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
		"The code_challenge parameter is incorrect. It may only contain "+pkceCharsetText+".",
		http.StatusBadRequest)
}

// codeVerifierMalformedRefusal answers a code_verifier that is not 43 to 128 characters of RFC 7636
// section 4.1's set, at the token endpoint. RFC 7636 section 4.6 answers a verifier that cannot
// match with invalid_grant, and a value that is not a verifier at all cannot.
func codeVerifierMalformedRefusal() error {
	return oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
		"The code_verifier parameter is incorrect. It should be 43 to 128 characters long and may only contain "+pkceCharsetText+".",
		http.StatusBadRequest)
}
