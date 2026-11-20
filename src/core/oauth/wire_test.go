package oauth

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthWireTypes_JSONRepresentation(t *testing.T) {
	tests := []struct {
		name     string
		want     any
		newValue func() any
		literal  string
	}{
		{
			name: "TokenResponse populated",
			want: &TokenResponse{
				AccessToken:      "access-token",
				IDToken:          "id-token",
				TokenType:        "Bearer",
				ExpiresIn:        3600,
				RefreshToken:     "refresh-token",
				RefreshExpiresIn: 7200,
				Scope:            "openid profile",
			},
			newValue: func() any { return &TokenResponse{} },
			literal:  `{"access_token":"access-token","id_token":"id-token","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-token","refresh_expires_in":7200,"scope":"openid profile"}`,
		},
		{
			// Every field of TokenResponse carries omitempty, so the zero value is the
			// empty object. A tag dropped from any of the seven shows up here.
			name:     "TokenResponse zero",
			want:     &TokenResponse{},
			newValue: func() any { return &TokenResponse{} },
			literal:  `{}`,
		},
		{
			name: "Jwk populated",
			want: &JWK{
				Alg: "RS256",
				Kid: "key-id",
				Kty: "RSA",
				Use: "sig",
				N:   "modulus",
				E:   "AQAB",
			},
			newValue: func() any { return &JWK{} },
			literal:  `{"alg":"RS256","kid":"key-id","kty":"RSA","use":"sig","n":"modulus","e":"AQAB"}`,
		},
		{
			// No field of JWK carries omitempty, so all six keys are present even when
			// empty. That is the /certs contract: a consumer reading a key it did not
			// find gets "" rather than a missing member.
			name:     "Jwk zero",
			want:     &JWK{},
			newValue: func() any { return &JWK{} },
			literal:  `{"alg":"","kid":"","kty":"","use":"","n":"","e":""}`,
		},
		{
			name: "Jwks populated",
			want: &JWKS{Keys: []JWK{{
				Alg: "RS256",
				Kid: "key-id",
				Kty: "RSA",
				Use: "sig",
				N:   "modulus",
				E:   "AQAB",
			}}},
			newValue: func() any { return &JWKS{} },
			literal:  `{"keys":[{"alg":"RS256","kid":"key-id","kty":"RSA","use":"sig","n":"modulus","e":"AQAB"}]}`,
		},
		{
			// Keep this row: a nil slice encodes as null, not []. The JWKS parser at
			// token_parser_jwks.go decodes /certs into this type, so the empty envelope
			// is a shape it has to survive.
			name:     "Jwks zero",
			want:     &JWKS{},
			newValue: func() any { return &JWKS{} },
			literal:  `{"keys":null}`,
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
