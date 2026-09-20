package oidc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The serialized form of the three RFC 7591 types, asserted against literals.
//
// #385 moved these out of core/api, and the whole claim of that move is that nothing on the wire
// changed. Nothing else in the tree can check it: the integration suite exercises the happy path
// through real requests but reads the fields back through these same structs, so a tag renamed on
// both sides at once passes there. A literal is what makes the tags the subject.
//
// Both directions, and both a populated and a zero value per type, so an omitempty added or
// removed shows up rather than only a tag rename.
func TestDCRWireTypes_JSONRepresentation(t *testing.T) {
	tests := []struct {
		name     string
		want     any
		newValue func() any
		literal  string
	}{
		{
			name: "DynamicClientRegistrationRequest",
			want: &DynamicClientRegistrationRequest{
				RedirectURIs:            []string{"https://client.example.org/callback"},
				TokenEndpointAuthMethod: "client_secret_basic",
				GrantTypes:              []string{"authorization_code", "refresh_token"},
				ClientName:              "Example Client",
			},
			newValue: func() any { return &DynamicClientRegistrationRequest{} },
			literal: `{"redirect_uris":["https://client.example.org/callback"],` +
				`"token_endpoint_auth_method":"client_secret_basic",` +
				`"grant_types":["authorization_code","refresh_token"],` +
				`"client_name":"Example Client"}`,
		},
		{
			// Every field of the request is optional, so the zero value is the empty object.
			// RFC 7591 section 2 requires the server to ignore metadata it does not understand,
			// which is why a request carrying nothing this server reads is still a request.
			name:     "DynamicClientRegistrationRequest, zero",
			want:     &DynamicClientRegistrationRequest{},
			newValue: func() any { return &DynamicClientRegistrationRequest{} },
			literal:  `{}`,
		},
		{
			name: "DynamicClientRegistrationResponse",
			want: &DynamicClientRegistrationResponse{
				ClientID:                "generated-client-id",
				ClientSecret:            "generated-client-secret",
				ClientIDIssuedAt:        1758326400,
				ClientSecretExpiresAt:   0,
				RedirectURIs:            []string{"https://client.example.org/callback"},
				TokenEndpointAuthMethod: "client_secret_basic",
				GrantTypes:              []string{"authorization_code", "refresh_token"},
				ClientName:              "Example Client",
			},
			newValue: func() any { return &DynamicClientRegistrationResponse{} },
			literal: `{"client_id":"generated-client-id",` +
				`"client_secret":"generated-client-secret",` +
				`"client_id_issued_at":1758326400,` +
				`"client_secret_expires_at":0,` +
				`"redirect_uris":["https://client.example.org/callback"],` +
				`"token_endpoint_auth_method":"client_secret_basic",` +
				`"grant_types":["authorization_code","refresh_token"],` +
				`"client_name":"Example Client"}`,
		},
		{
			// A public client gets no secret, and the four members RFC 7591 section 3.2.1
			// pins must still be present. client_id is REQUIRED; client_secret_expires_at is
			// REQUIRED when a secret was issued and carries 0 for "never expires", which is
			// why neither it nor client_id_issued_at may take omitempty: 0 is a value here,
			// not an absence.
			name:     "DynamicClientRegistrationResponse, public client with no secret",
			want:     &DynamicClientRegistrationResponse{ClientID: "public-client-id"},
			newValue: func() any { return &DynamicClientRegistrationResponse{} },
			literal: `{"client_id":"public-client-id","client_id_issued_at":0,` +
				`"client_secret_expires_at":0,"token_endpoint_auth_method":"","grant_types":null}`,
		},
		{
			// RFC 7591 section 3.2.2: error is REQUIRED, error_description OPTIONAL.
			name: "DynamicClientRegistrationError",
			want: &DynamicClientRegistrationError{
				Error:            DCRErrorInvalidRedirectURI,
				ErrorDescription: "redirect_uris must use https",
			},
			newValue: func() any { return &DynamicClientRegistrationError{} },
			literal:  `{"error":"invalid_redirect_uri","error_description":"redirect_uris must use https"}`,
		},
		{
			name:     "DynamicClientRegistrationError, no description",
			want:     &DynamicClientRegistrationError{Error: DCRErrorInvalidClientMetadata},
			newValue: func() any { return &DynamicClientRegistrationError{} },
			literal:  `{"error":"invalid_client_metadata"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(tc.want)
			require.NoError(t, err)
			assert.Equal(t, tc.literal, string(encoded))

			decoded := tc.newValue()
			require.NoError(t, json.Unmarshal([]byte(tc.literal), decoded))
			assert.Equal(t, tc.want, decoded)
		})
	}
}

// The two error codes are wire values a client switches on, so they are asserted as strings
// rather than referred to by their Go names. RFC 7591 section 3.2.2 defines both spellings, and a
// typo in either is a refusal no conforming client can classify.
func TestDCRErrorCodes_AreTheRFC7591Spellings(t *testing.T) {
	assert.Equal(t, "invalid_redirect_uri", DCRErrorInvalidRedirectURI)
	assert.Equal(t, "invalid_client_metadata", DCRErrorInvalidClientMetadata)
}
