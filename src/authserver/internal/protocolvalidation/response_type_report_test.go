package protocolvalidation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseResponseType_ReportsWhatItDidNotUnderstand is #244's parser rule: a value that is none of
// code, token and id_token is reported as Unrecognised, a recognised value seen twice as Repeated,
// and spaces the grammar does not allow as Malformed, so that none is silently collapsed into the
// request it resembles. Each row differs from a passing spelling by the one thing that makes it fail.
func TestParseResponseType_ReportsWhatItDidNotUnderstand(t *testing.T) {
	testCases := []struct {
		name         string
		responseType string
		unrecognised bool
		repeated     bool
		malformed    bool
	}{
		// Accepted spellings report nothing.
		{"code", "code", false, false, false},
		{"token", "token", false, false, false},
		{"id_token", "id_token", false, false, false},
		{"id_token token", "id_token token", false, false, false},
		{"token id_token", "token id_token", false, false, false},
		{"empty", "", false, false, false},

		// An unrecognised value, alone or beside a recognised one.
		{"an unknown value", "foo", true, false, false},
		{"code and an unknown value", "code foo", true, false, false},
		{"an unknown value and code", "foo code", true, false, false},
		{"token and an unknown value", "token unknown", true, false, false},
		{"a value differing in case", "Code", true, false, false},
		{"a plural", "codes", true, false, false},
		{"two unknown values", "foo bar", true, false, false},
		{"the same unknown value twice is unknown, not repeated", "foo foo", true, false, false},

		// A recognised value twice.
		{"code twice", "code code", false, true, false},
		{"token twice", "token token", false, true, false},
		{"id_token twice", "id_token id_token", false, true, false},
		{"id_token token, id_token again", "id_token token id_token", false, true, false},
		{"code twice among others", "code token code", false, true, false},
		{"repeated and unknown", "code code foo", true, true, false},

		// Hybrid types are parsed, and are refused by the count, not by these flags.
		{"code token", "code token", false, false, false},
		{"code id_token token", "code id_token token", false, false, false},

		// The spaces RFC 6749 3.1.1's grammar does not allow. The values inside are still read, and
		// recognised; each of these used to be accepted as them (#244).
		{"a leading space", " code", false, false, true},
		{"a trailing space", "code ", false, false, true},
		{"spaces either side", " code ", false, false, true},
		{"a run of spaces between two types", "id_token  token", false, false, true},
		{"spaces alone", "   ", false, false, true},

		// Only the space separates. Any other character joins two words into one value, which is
		// unknown: a tab, a newline, a form feed and a carriage return used to split (#244).
		{"a tab between two types", "id_token\ttoken", true, false, false},
		{"a newline between two types", "id_token\ntoken", true, false, false},
		{"a form feed between two types", "id_token\ftoken", true, false, false},
		{"a carriage return between two types", "id_token\rtoken", true, false, false},
		{"a no-break space between two types", "code\u00a0token", true, false, false},
		{"a next-line character between two types", "code\u0085token", true, false, false},
		{"a vertical tab between two types", "code\vtoken", true, false, false},
		// Nothing is trimmed: a padded value is not the value. The edge trim used to read both as code.
		{"a no-break space after a type", "code\u00a0", true, false, false},
		{"a vertical tab before a type", "\vcode", true, false, false},
		// Both at once: spaces the grammar refuses, around values a tab joined.
		{"padded with separators", " \tid_token \n token ", true, false, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := ParseResponseType(tc.responseType)

			assert.Equal(t, tc.unrecognised, info.Unrecognised, "Unrecognised for %q", tc.responseType)
			assert.Equal(t, tc.repeated, info.Repeated, "Repeated for %q", tc.responseType)
			assert.Equal(t, tc.malformed, info.Malformed, "Malformed for %q", tc.responseType)
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

		// Spaces around it, or anything else, are not the exact type. The first three used to be
		// code-only (#244).
		{" code ", false},
		{"code ", false},
		{" code", false},
		{"\tcode\n", false},
		{"code\u00a0", false},

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
		{"code\u00a0token", false},
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
		{"code normalizes", "code", "openid openid offline_access", "openid offline_access"},

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
		// Only a space separates, so a tab leaves one value that is not offline_access (#244).
		{"a value a tab joined to it is kept", "token", "openid\toffline_access", "openid\toffline_access"},

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
