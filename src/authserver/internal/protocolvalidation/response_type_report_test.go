package protocolvalidation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseResponseType_ReportsWhatItDidNotUnderstand is #244's parser rule: a value that is none of
// code, token and id_token is reported as Unrecognised, and a recognised value seen twice as
// Repeated, so that neither is silently collapsed into the request it resembles. Each row differs
// from a passing spelling by the one token that makes it fail.
func TestParseResponseType_ReportsWhatItDidNotUnderstand(t *testing.T) {
	testCases := []struct {
		name         string
		responseType string
		unrecognised bool
		repeated     bool
	}{
		// Accepted spellings report nothing.
		{"code", "code", false, false},
		{"token", "token", false, false},
		{"id_token", "id_token", false, false},
		{"id_token token", "id_token token", false, false},
		{"token id_token", "token id_token", false, false},
		{"padded with separators", " \tid_token \n token ", false, false},
		{"empty", "", false, false},

		// An unrecognised value, alone or beside a recognised one.
		{"an unknown value", "foo", true, false},
		{"code and an unknown value", "code foo", true, false},
		{"an unknown value and code", "foo code", true, false},
		{"token and an unknown value", "token unknown", true, false},
		{"a value differing in case", "Code", true, false},
		{"a plural", "codes", true, false},
		{"two unknown values", "foo bar", true, false},
		{"the same unknown value twice is unknown, not repeated", "foo foo", true, false},

		// A recognised value twice.
		{"code twice", "code code", false, true},
		{"token twice", "token token", false, true},
		{"id_token twice", "id_token id_token", false, true},
		{"id_token token, id_token again", "id_token token id_token", false, true},
		{"code twice among others", "code token code", false, true},
		{"repeated and unknown", "code code foo", true, true},

		// Hybrid types are parsed, and are refused by the count, not by these two flags.
		{"code token", "code token", false, false},
		{"code id_token token", "code id_token token", false, false},

		// #244 part 4: only the space-delimited separators split. A no-break space, a next-line
		// character and a vertical tab join two words into one value, which is unknown.
		{"a no-break space between two types", "code token", true, false},
		{"a next-line character between two types", "code\u0085token", true, false},
		{"a vertical tab between two types", "code\vtoken", true, false},
		// The edge trim is kept: a padded value is still the value.
		{"a no-break space after a type", "code ", false, false},
		{"a vertical tab before a type", "\vcode", false, false},
		// Every other separator still splits.
		{"a tab between two types", "id_token\ttoken", false, false},
		{"a newline between two types", "id_token\ntoken", false, false},
		{"a form feed between two types", "id_token\ftoken", false, false},
		{"a carriage return between two types", "id_token\rtoken", false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := ParseResponseType(tc.responseType)

			assert.Equal(t, tc.unrecognised, info.Unrecognised, "Unrecognised for %q", tc.responseType)
			assert.Equal(t, tc.repeated, info.Repeated, "Repeated for %q", tc.responseType)
		})
	}
}

// TestResponseTypeInfo_IsCodeOnly: only the exact type "code" buys RFC 8252 7.3's loopback port
// flexibility, at the three sites that decide it. Each refused row is "code" plus one thing.
func TestResponseTypeInfo_IsCodeOnly(t *testing.T) {
	testCases := []struct {
		responseType string
		want         bool
	}{
		{"code", true},
		{" code ", true},
		{"\tcode\n", true},
		{"code ", true},

		{"code code", false},
		{"code foo", false},
		{"foo code", false},
		{"code token", false},
		{"code id_token", false},
		{"code id_token token", false},
		{"token", false},
		{"id_token", false},
		{"id_token token", false},
		{"Code", false},
		{"codes", false},
		{"code token", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.responseType, func(t *testing.T) {
			assert.Equal(t, tc.want, ParseResponseType(tc.responseType).IsCodeOnly())
		})
	}
}

// TestResponseTypeInfo_ScopeHonoured is OIDC Core 11: offline_access is ignored unless the response
// type returns an authorization code. What it removes it removes as a whole value, in every position,
// and leaves everything else as the normalized scope it was.
func TestResponseTypeInfo_ScopeHonoured(t *testing.T) {
	testCases := []struct {
		name         string
		responseType string
		scope        string
		want         string
	}{
		{"code keeps it", "code", "openid offline_access", "openid offline_access"},
		{"code keeps it first", "code", "offline_access openid", "offline_access openid"},
		{"code keeps it alone", "code", "offline_access", "offline_access"},
		{"code normalizes", "code", "openid  openid\toffline_access", "openid offline_access"},

		{"token drops it", "token", "openid offline_access", "openid"},
		{"id_token drops it", "id_token", "openid offline_access", "openid"},
		{"id_token token drops it", "id_token token", "openid offline_access", "openid"},
		{"token id_token drops it", "token id_token", "openid offline_access", "openid"},
		{"it is dropped first", "token", "offline_access openid", "openid"},
		{"it is dropped in the middle", "token", "openid offline_access profile", "openid profile"},
		{"it is dropped last", "token", "openid profile offline_access", "openid profile"},
		{"it is dropped when repeated", "token", "openid offline_access offline_access", "openid"},
		{"dropped alone leaves nothing", "token", "offline_access", ""},
		{"nothing to drop", "token", "openid profile", "openid profile"},
		{"an empty scope stays empty", "token", "", ""},

		// A value that merely holds the text is another scope, and case matters (RFC 6749 3.3).
		{"a resource scope holding the text is kept", "token", "openid res:offline_access_read", "openid res:offline_access_read"},
		{"a value differing in case is kept", "token", "openid OFFLINE_ACCESS", "openid OFFLINE_ACCESS"},

		// A response type the validator will refuse anyway has no code, so it is treated as none.
		{"an unknown response type drops it", "foo", "openid offline_access", "openid"},
		{"a hybrid type has a code, so it keeps it", "code token", "openid offline_access", "openid offline_access"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ParseResponseType(tc.responseType).ScopeHonoured(tc.scope))
		})
	}
}
