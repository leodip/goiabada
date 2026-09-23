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
