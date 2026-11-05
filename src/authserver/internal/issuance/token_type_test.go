package issuance

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestTokenType_String owns the total String decision 16 of #385 settled for this type. The
// out-of-range rows are the guard: no production site converts an int to a TokenType, but the
// panicking index was the same shape in all seven enums this change moved, and fixing six of them
// while leaving one would leave the next caller to find out which.
func TestTokenType_String(t *testing.T) {
	testCases := []struct {
		name      string
		tokenType TokenType
		want      string
	}{
		{"id is the zero value", TokenTypeId, "ID"},
		{"bearer", TokenTypeBearer, "Bearer"},
		{"refresh", TokenTypeRefresh, "Refresh"},
		{"offline, the top of the range", TokenTypeOffline, "Offline"},
		{"one past the range", TokenType(4), ""},
		{"far past the range", TokenType(99), ""},
		{"negative", TokenType(-1), ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.tokenType.String())
		})
	}
}

// The three typ values of tokens that are not ID Tokens are refused as a hint, and nothing else is:
// an ID Token carries no typ, and an unknown value is not one this server stamps (#401).
func TestIsNotIDTokenTyp(t *testing.T) {
	testCases := []struct {
		typ  string
		want bool
	}{
		{"Bearer", true},
		{"Refresh", true},
		{"Offline", true},
		{"", false},
		{"ID", false},
		{"bearer", false},
		{"JWT", false},
	}

	for _, tc := range testCases {
		t.Run(tc.typ, func(t *testing.T) {
			assert.Equal(t, tc.want, IsNotIDTokenTyp(tc.typ))
		})
	}
}

// An id_token_hint must carry an ID token's JOSE header: typ JWT, the value every ID token this
// server issues and the account logout's hint carry. Every other header is refused, so the logout
// token (logout+jwt) and the access token (at+jwt), signed with the same key, are never taken for
// one, and a header with no typ is refused as well (#784 decision 12). A typ is a media type,
// compared without regard to case and with the application/ prefix optional (RFC 7515 section
// 4.1.9).
func TestHasIDTokenHeader(t *testing.T) {
	testCases := []struct {
		name   string
		header map[string]interface{}
		want   bool
	}{
		{"JWT, as every ID token carries it", map[string]interface{}{"alg": "RS256", "typ": "JWT"}, true},
		{"jwt in lower case", map[string]interface{}{"typ": "jwt"}, true},
		{"the full media type", map[string]interface{}{"typ": "application/jwt"}, true},
		{"a logout token", map[string]interface{}{"typ": "logout+jwt"}, false},
		{"a logout token's full media type", map[string]interface{}{"typ": "application/logout+jwt"}, false},
		{"an access token", map[string]interface{}{"typ": "at+jwt"}, false},
		{"an access token's full media type", map[string]interface{}{"typ": "application/at+jwt"}, false},
		{"JWT with a parameter", map[string]interface{}{"typ": "JWT; charset=utf-8"}, false},
		{"an empty typ", map[string]interface{}{"typ": ""}, false},
		{"typ is not a string", map[string]interface{}{"typ": 1}, false},
		{"no typ in the header", map[string]interface{}{"alg": "RS256"}, false},
		{"no header at all", nil, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, HasIDTokenHeader(tc.header))
		})
	}
}
