package oauth

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The structural check is run on the compact serialization alone, before any signature is
// verified, so the tokens below carry a placeholder signature segment. Each refused case is one
// of #709's findings 1 to 4: a crit header (RFC 7515 section 4.1.11), a nested JWT's cty (RFC 7519
// section 7.2 step 8), invalid UTF-8 (RFC 7515 section 5.2 step 3, RFC 7519 section 7.2 step 10),
// and a character outside the unpadded base64url alphabet (RFC 7515 section 5.2 steps 2, 6 and 7).
// The header and payload are written as raw JSON text, so a case can hold bytes no JSON encoder
// would write.

const (
	structureSignature = "c2lnbmF0dXJl"
	structureHeader    = `{"alg":"RS256","kid":"k1","typ":"at+jwt"}`
	structurePayload   = `{"iss":"https://auth.example.com","sub":"248289761001","exp":1700000000}`
)

func compactJWT(header, payload string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + structureSignature
}

func TestCheckJWTStructure_AcceptsAWellFormedToken(t *testing.T) {
	for name, header := range map[string]string{
		"an access token's header":                                structureHeader,
		"an ID token's header":                                    `{"alg":"RS256","kid":"k1"}`,
		"a cty naming no nested JWT, which the rule leaves alone": `{"alg":"RS256","cty":"example"}`,
		"a typ of JWT, which is not cty":                          `{"alg":"RS256","typ":"JWT"}`,
		"an escaped non-ASCII character in a string":              `{"alg":"RS256","kid":"café"}`,
	} {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, CheckJWTStructure(compactJWT(header, structurePayload)))
		})
	}

	t.Run("a payload holding valid multi-byte UTF-8", func(t *testing.T) {
		assert.NoError(t, CheckJWTStructure(compactJWT(structureHeader, `{"sub":"José","name":"渡辺"}`)))
	})

	t.Run("every character of the alphabet, in a signature segment", func(t *testing.T) {
		token := compactJWT(structureHeader, structurePayload)
		token = token[:strings.LastIndex(token, ".")+1] +
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		assert.NoError(t, CheckJWTStructure(token))
	})
}

// RFC 7515 section 4.1.11: a recipient MUST refuse a JWS whose crit lists an extension it does not
// understand, and Goiabada understands none, so crit is refused whatever it holds.
func TestCheckJWTStructure_RefusesACritHeader(t *testing.T) {
	for name, header := range map[string]string{
		"an unknown extension":             `{"alg":"RS256","crit":["unhandled"],"unhandled":true}`,
		"a registered claim name":          `{"alg":"RS256","crit":["exp"]}`,
		"the empty list":                   `{"alg":"RS256","crit":[]}`,
		"null":                             `{"alg":"RS256","crit":null}`,
		"a string rather than a list":      `{"alg":"RS256","crit":"unhandled"}`,
		"crit first, before alg":           `{"crit":["unhandled"],"alg":"RS256","unhandled":1}`,
		"an access token's header besides": `{"alg":"RS256","kid":"k1","typ":"at+jwt","crit":["b64"],"b64":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, CheckJWTStructure(compactJWT(header, structurePayload)))
		})
	}
}

// RFC 7519 section 7.2 step 8: a cty of JWT says the payload is itself a JWT, nested. Goiabada
// supports no nested JWT. Media types compare case-insensitively (RFC 7515 section 4.1.10).
func TestCheckJWTStructure_RefusesANestedJWT(t *testing.T) {
	for _, cty := range []string{"JWT", "jwt", "Jwt", "application/jwt", "APPLICATION/JWT", "Application/Jwt"} {
		t.Run(cty, func(t *testing.T) {
			assert.Error(t, CheckJWTStructure(compactJWT(`{"alg":"RS256","cty":"`+cty+`"}`, structurePayload)))
		})
	}
}

// Go's JSON decoder replaces an invalid byte with U+FFFD rather than refusing it, so the check reads
// the decoded bytes before any decoder does.
func TestCheckJWTStructure_RefusesInvalidUTF8(t *testing.T) {
	for name, token := range map[string]string{
		"a byte that starts no character, in the header":  compactJWT("{\"alg\":\"RS256\",\"kid\":\"k\xff1\"}", structurePayload),
		"a truncated character, in the header":            compactJWT("{\"alg\":\"RS256\",\"kid\":\"k\xc3\"}", structurePayload),
		"a byte that starts no character, in the payload": compactJWT(structureHeader, "{\"sub\":\"a\xffb\"}"),
		"a surrogate encoded as UTF-8, in the payload":    compactJWT(structureHeader, "{\"sub\":\"\xed\xa0\x80\"}"),
		"an overlong encoding, in the payload":            compactJWT(structureHeader, "{\"sub\":\"\xc0\xaf\"}"),
	} {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, CheckJWTStructure(token))
		})
	}
}

// RFC 7515 section 5.2 decodes each part with no line breaks, whitespace or other additional
// characters, and the compact serialization is unpadded (RFC 7515 section 2). Go's decoder skips CR
// and LF, so without this check a token with a line break in it still verified.
func TestCheckJWTStructure_RefusesACharacterOutsideTheUnpaddedAlphabet(t *testing.T) {
	valid := compactJWT(structureHeader, structurePayload)
	segments := strings.Split(valid, ".")
	segmentNames := []string{"header", "payload", "signature"}

	for _, extra := range []struct {
		name string
		text string
	}{
		{"CR", "\r"},
		{"LF", "\n"},
		{"CRLF", "\r\n"},
		{"=", "="},
		{"==", "=="},
		{"a space", " "},
		{"a tab", "\t"},
		{"+, of the padded alphabet", "+"},
		{"/, of the padded alphabet", "/"},
		{"a non-ASCII letter", "é"},
		{"a NUL", "\x00"},
	} {
		for i, segmentName := range segmentNames {
			t.Run(extra.name+" appended to the "+segmentName, func(t *testing.T) {
				altered := append([]string(nil), segments...)
				altered[i] += extra.text
				assert.Error(t, CheckJWTStructure(strings.Join(altered, ".")))
			})
			t.Run(extra.name+" inside the "+segmentName, func(t *testing.T) {
				altered := append([]string(nil), segments...)
				altered[i] = altered[i][:4] + extra.text + altered[i][4:]
				assert.Error(t, CheckJWTStructure(strings.Join(altered, ".")))
			})
		}
	}

	t.Run("a line break before the token", func(t *testing.T) {
		assert.Error(t, CheckJWTStructure("\n"+valid))
	})
	t.Run("a line break after the token", func(t *testing.T) {
		assert.Error(t, CheckJWTStructure(valid+"\r\n"))
	})
}

func TestCheckJWTStructure_RefusesWhatIsNotACompactJWS(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(structureHeader))
	payload := base64.RawURLEncoding.EncodeToString([]byte(structurePayload))
	for name, token := range map[string]string{
		"two segments":                      header + "." + payload,
		"four segments":                     header + "." + payload + "." + structureSignature + "." + structureSignature,
		"five segments, a compact JWE":      header + ".." + payload + "." + structureSignature + "." + structureSignature,
		"no dot at all":                     "not-a-token",
		"an empty header":                   "." + payload + "." + structureSignature,
		"a header that is not JSON":         base64.RawURLEncoding.EncodeToString([]byte("alg=RS256")) + "." + payload + "." + structureSignature,
		"a header that is a JSON array":     base64.RawURLEncoding.EncodeToString([]byte(`["alg","RS256"]`)) + "." + payload + "." + structureSignature,
		"a header length no encoding makes": "eyJhb." + payload + "." + structureSignature,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, CheckJWTStructure(token))
		})
	}
}
