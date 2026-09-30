package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGrantType_Traits owns the grant table. Each constant is pinned against its wire literal,
// since RFC 6749 and RFC 7591 fix those spellings and a relying party sends them, and against all
// three traits its consumers read: the token endpoint's dispatch, the provided-but-empty scope
// refusal and dynamic client registration. The consumers' own tests are thin and cite this one.
//
// The readsScope rows are the ones TestGrantTypeConsumesScope held in the token handler before the
// table replaced that function (#437). The authorization_code row is the one that matters there:
// it never reads the scope parameter (RFC 6749 section 4.1.3 does not define it on that request),
// so refusing a malformed one would break a valid token exchange.
//
// Every value outside the table answers false to all three, which is what makes the token
// endpoint answer unsupported_grant_type and DCR invalid_client_metadata for it.
func TestGrantType_Traits(t *testing.T) {
	testCases := []struct {
		name        string
		grantType   GrantType
		wire        string
		accepted    bool
		readsScope  bool
		registrable bool
	}{
		{"authorization_code", GrantTypeAuthorizationCode, "authorization_code", true, false, true},
		{"refresh_token", GrantTypeRefreshToken, "refresh_token", true, true, true},
		{"client_credentials", GrantTypeClientCredentials, "client_credentials", true, true, true},
		// Accepted at the token endpoint but never registrable: DCR has never offered it.
		{"password", GrantTypePassword, "password", true, true, false},
		// Issued at the authorization endpoint only, so the token endpoint never redeems it.
		{"implicit", GrantTypeImplicit, "implicit", false, false, false},

		{"empty", GrantType(""), "", false, false, false},
		// Grant type values are case-sensitive; no table row matches a different spelling.
		{"upper-case password", GrantType("PASSWORD"), "PASSWORD", false, false, false},
		{"password with a trailing space", GrantType("password "), "password ", false, false, false},
		{"device code", GrantType("urn:ietf:params:oauth:grant-type:device_code"),
			"urn:ietf:params:oauth:grant-type:device_code", false, false, false},
		// Response types, not grants.
		{"code", GrantType("code"), "code", false, false, false},
		{"token", GrantType("token"), "token", false, false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wire, tc.grantType.String())
			assert.Equal(t, tc.accepted, tc.grantType.AcceptedAtTokenEndpoint(), "AcceptedAtTokenEndpoint")
			assert.Equal(t, tc.readsScope, tc.grantType.ReadsScope(), "ReadsScope")
			assert.Equal(t, tc.registrable, tc.grantType.Registrable(), "Registrable")
		})
	}
}

// TestGrantTypesSupported pins the discovery list, in order, since the JSON array's order is
// observable. Every grant the server implements is listed, password and implicit included,
// whatever a setting says: the list takes no setting at all (#437). A row missing here means a
// relying party reading discovery is told the server cannot do something it does.
func TestGrantTypesSupported(t *testing.T) {
	assert.Equal(t,
		[]string{"authorization_code", "refresh_token", "client_credentials", "password", "implicit"},
		GrantTypesSupported())
}

// A caller that overwrites the returned slice must not reach the table the traits read.
func TestGrantTypesSupported_ReturnsAFreshSlice(t *testing.T) {
	first := GrantTypesSupported()
	first[0] = "tampered"

	assert.True(t, GrantTypeAuthorizationCode.AcceptedAtTokenEndpoint())
	assert.False(t, GrantType("tampered").AcceptedAtTokenEndpoint())
	assert.Equal(t, "authorization_code", GrantTypesSupported()[0])
}
