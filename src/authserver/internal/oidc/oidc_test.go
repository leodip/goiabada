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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, HasOfflineAccessScope(tc.scope))
		})
	}
}

// scopeWhitespaceCases is the one whitespace table for the scope splitter: every site that splits a
// scope reads it through SplitScope or NormalizeScope, so this is where the rule is pinned and
// every consumer's own test stays thin (#116). split is SplitScope's answer and normalized
// NormalizeScope's.
//
// The separators are RE2's \s, the set the regexes these functions replaced matched: space, tab,
// newline, form feed, carriage return. Vertical tab, U+0085 and U+00A0 are not separators, so each
// stays inside the element it sits in; strings.Fields would split on all three.
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
	{"tab", "openid\tprofile", []string{"openid", "profile"}, "openid profile"},
	{"newline", "openid\nprofile", []string{"openid", "profile"}, "openid profile"},
	{"carriage return and newline", "openid\r\nprofile", []string{"openid", "profile"}, "openid profile"},
	{"form feed", "openid\fprofile", []string{"openid", "profile"}, "openid profile"},
	{"mixed runs", " billing-api:read \t  billing-api:write\t", []string{"billing-api:read", "billing-api:write"}, "billing-api:read billing-api:write"},
	{"vertical tab inside an element is not a separator", "openid\vprofile", []string{"openid\vprofile"}, "openid\vprofile"},
	{"U+00A0 inside an element is not a separator", "openid profile", []string{"openid profile"}, "openid profile"},
	{"U+0085 inside an element is not a separator", "openid\u0085profile", []string{"openid\u0085profile"}, "openid\u0085profile"},
	{"U+00A0 leading the whole value is trimmed", " openid", []string{"openid"}, "openid"},
	// The two rows below are the only answers #116's consolidation changed, both widenings at the
	// token endpoint: whitespace outside the separator set standing beside a separator is trimmed
	// off its element, as SetScope and ROPC already did, where the token endpoint used to keep
	// " profile" and "\v" as elements and refuse them as unknown scopes. Keep them.
	{"U+00A0 after a separator is trimmed (widened, #116)", "openid  profile", []string{"openid", "profile"}, "openid profile"},
	{"a lone vertical tab between separators is dropped (widened, #116)", "openid \v profile", []string{"openid", "profile"}, "openid profile"},
	{"empty", "", []string{}, ""},
	{"spaces only", "   ", []string{}, ""},
	{"tab only", "\t", []string{}, ""},
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
