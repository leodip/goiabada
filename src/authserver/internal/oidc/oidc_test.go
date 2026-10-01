package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsClaimScope(t *testing.T) {
	testCases := []struct {
		name     string
		scope    string
		expected bool
	}{
		{"OpenID scope", "openid", true},
		{"Profile scope", "profile", true},
		{"Email scope", "email", true},
		{"Address scope", "address", true},
		{"Phone scope", "phone", true},
		{"Groups scope", "groups", true},
		{"Attributes scope", "attributes", true},
		{"offline_access is not a claim scope", "offline_access", false},
		{"Non-OIDC scope", "custom_scope", false},
		{"Case differs", "OPENID", false},
		{"Empty scope", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsClaimScope(tc.scope)
			if result != tc.expected {
				t.Errorf("IsClaimScope(%q) = %v; want %v", tc.scope, result, tc.expected)
			}
		})
	}
}

// RFC 6749 section 3.3 makes scope values case-sensitive strings, so offline_access is matched
// exactly: a case-folded or padded spelling is some other scope, which the validators then refuse
// as one (#425).
func TestIsOfflineAccessScope(t *testing.T) {
	testCases := []struct {
		name     string
		scope    string
		expected bool
	}{
		{"Exact match", "offline_access", true},
		{"Uppercase is another scope", "OFFLINE_ACCESS", false},
		{"Mixed case is another scope", "Offline_Access", false},
		{"Surrounding spaces are not trimmed", " offline_access ", false},
		{"Different scope", "online_access", false},
		{"A resource scope containing the text", "res:offline_access_read", false},
		{"Empty string", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsOfflineAccessScope(tc.scope)
			if result != tc.expected {
				t.Errorf("IsOfflineAccessScope(%q) = %v; want %v", tc.scope, result, tc.expected)
			}
		})
	}
}

// HasOfflineAccessScope answers over a whole space-delimited scope string, one value at a time.
// The resource-scope rows are the ones the prompt=none path answered wrongly while it matched the
// constant as a substring.
func TestHasOfflineAccessScope(t *testing.T) {
	testCases := []struct {
		name     string
		scope    string
		expected bool
	}{
		{"alone", "offline_access", true},
		{"first", "offline_access openid", true},
		{"middle", "openid offline_access profile", true},
		{"last", "openid profile offline_access", true},
		{"a resource scope containing the text", "openid res:offline_access_read", false},
		{"a resource named for it", "offline_access:read", false},
		{"a longer word", "offline_access_extended", false},
		{"uppercase", "openid OFFLINE_ACCESS", false},
		{"no offline_access", "openid profile email", false},
		{"empty", "", false},

		// Read through SplitScope (#244), so it agrees with the splitter: only a space separates, so
		// offline_access after a tab, a newline or a no-break space is part of another value, and a
		// value padded with one is not offline_access.
		{"after a run of spaces", "openid  offline_access", true},
		{"after a tab", "openid\toffline_access", false},
		{"after a newline", "openid\noffline_access", false},
		{"joined to a word by a no-break space", "openid\u00a0offline_access", false},
		{"padded by a no-break space", "openid offline_access\u00a0", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, HasOfflineAccessScope(tc.scope))
		})
	}
}

// / scopeWhitespaceCases is the one whitespace table for the scope splitter: every site that splits a
// scope reads it through SplitScope or NormalizeScope, so this is where the rule is pinned and
// every consumer's own test stays thin (#116). split is SplitScope's answer and normalized
// NormalizeScope's.
//
// The separator is the space (U+0020) alone, and nothing is trimmed (#244). Whether a scope is well
// formed is oauth.IsWellFormedSpaceDelimited's question, asked where a scope enters, so a run of
// spaces still splits into no empty value here; every other character, a tab, a newline, a form
// feed, a carriage return, a vertical tab, U+0085 or U+00A0, stays inside the element it sits in.
var scopeWhitespaceCases = []struct {
	name       string
	scope      string
	split      []string
	normalized string
}{
	{"one space", "openid profile", []string{"openid", "profile"}, "openid profile"},
	{"double space", "openid  profile", []string{"openid", "profile"}, "openid profile"},
	{"leading space", " openid profile", []string{"openid", "profile"}, "openid profile"},
	{"trailing space", "openid profile ", []string{"openid", "profile"}, "openid profile"},
	{"leading and trailing runs", "  openid profile  ", []string{"openid", "profile"}, "openid profile"},
	{"a tab is not a separator", "openid\tprofile", []string{"openid\tprofile"}, "openid\tprofile"},
	{"a newline is not a separator", "openid\nprofile", []string{"openid\nprofile"}, "openid\nprofile"},
	{"a carriage return and newline are not a separator", "openid\r\nprofile", []string{"openid\r\nprofile"}, "openid\r\nprofile"},
	{"a form feed is not a separator", "openid\fprofile", []string{"openid\fprofile"}, "openid\fprofile"},
	{"a vertical tab is not a separator", "openid\vprofile", []string{"openid\vprofile"}, "openid\vprofile"},
	{"U+00A0 is not a separator", "openid\u00a0profile", []string{"openid\u00a0profile"}, "openid\u00a0profile"},
	{"U+0085 is not a separator", "openid\u0085profile", []string{"openid\u0085profile"}, "openid\u0085profile"},
	{"U+00A0 leading the whole value is kept", "\u00a0openid", []string{"\u00a0openid"}, "\u00a0openid"},
	{"U+00A0 after a space is kept with its element", "openid \u00a0profile", []string{"openid", "\u00a0profile"}, "openid \u00a0profile"},
	{"a tab beside a space is kept with its element", "openid \tprofile", []string{"openid", "\tprofile"}, "openid \tprofile"},
	{"empty", "", []string{}, ""},
	{"spaces only", "   ", []string{}, ""},
	{"a tab alone is an element", "\t", []string{"\t"}, "\t"},
	{"a duplicate is kept by the split and dropped by normalizing", "openid openid profile", []string{"openid", "openid", "profile"}, "openid profile"},
	{"a duplicate across a run", "a:b  a:b", []string{"a:b", "a:b"}, "a:b"},
	{"a later duplicate keeps the first occurrence's place", "billing-api:read billing-api:write billing-api:read", []string{"billing-api:read", "billing-api:write", "billing-api:read"}, "billing-api:read billing-api:write"},
}

func TestSplitScope(t *testing.T) {
	for _, tc := range scopeWhitespaceCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.split, SplitScope(tc.scope))
		})
	}
}

func TestNormalizeScope(t *testing.T) {
	for _, tc := range scopeWhitespaceCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.normalized, NormalizeScope(tc.scope))
		})
	}
}

func TestScopeDescriptionKey(t *testing.T) {
	testCases := []struct {
		scope string
		want  string
	}{
		{"openid", "consent.scope.openid.description"},
		{"profile", "consent.scope.profile.description"},
		{"email", "consent.scope.email.description"},
		{"address", "consent.scope.address.description"},
		{"phone", "consent.scope.phone.description"},
		{"groups", "consent.scope.groups.description"},
		{"attributes", "consent.scope.attributes.description"},
		{"offline_access", "consent.scope.offline_access.description"},
		{"OFFLINE_ACCESS", ""},
		{"billing-api:read", ""},
		{"", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.scope, func(t *testing.T) {
			assert.Equal(t, tc.want, ScopeDescriptionKey(tc.scope))
		})
	}
}

// The discovery document's scopes_supported is read from here, so the literal list is pinned here
// and the handler's test asserts equality with this function rather than repeating it.
func TestSupportedScopes(t *testing.T) {
	assert.Equal(t,
		[]string{"openid", "profile", "email", "address", "phone", "groups", "attributes", "offline_access"},
		SupportedScopes())
}

// A caller that overwrites the returned slice must not reach the roster the predicates read.
func TestSupportedScopes_ReturnsAFreshSlice(t *testing.T) {
	first := SupportedScopes()
	first[0] = "tampered"

	assert.True(t, IsClaimScope("openid"))
	assert.False(t, IsClaimScope("tampered"))
	assert.Equal(t, "openid", SupportedScopes()[0])
}
