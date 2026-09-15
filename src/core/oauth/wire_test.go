package oauth

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"testing"

	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyTokenResponseGobName is the name gob writes into the stream for a TokenResponse
// stored in an interface value, and it is derived from this package's import path rather
// than from the type name alone.
//
// The admin console keeps a TokenResponse in its session (handler_auth_callback.go writes
// it, core/middleware reads it back), and session.Values is a map[interface{}]interface{},
// so every session in flight carries this string. Declaring the type at another import
// path changes it, and the decode of an existing session then fails with "name not
// registered for interface": the store answers that with a fresh session rather than a
// 500, so the administrator is signed out and sent back through /auth/authorize. Moving
// TokenResponse therefore costs a permanent gob.RegisterName under the name below, and
// this test is what makes that cost visible at the moment somebody tries (#338).
const legacyTokenResponseGobName = "github.com/leodip/goiabada/core/oauth.TokenResponse"

func TestTokenResponse_GobSessionIdentity(t *testing.T) {
	// Both binaries already register this type at startup. Registering the same type
	// under the same name again is a no-op, so the test is free to stand alone.
	gob.Register(TokenResponse{})

	want := TokenResponse{
		AccessToken:      "access-token",
		IdToken:          "id-token",
		TokenType:        "Bearer",
		ExpiresIn:        3600,
		RefreshToken:     "refresh-token",
		RefreshExpiresIn: 7200,
		Scope:            "openid profile",
	}

	// The shape the session store encodes: the value arrives at the encoder through an
	// interface, which is what makes gob write the concrete type's name into the stream.
	values := map[interface{}]interface{}{
		constants.SessionKeyJwt: want,
	}

	var encoded bytes.Buffer
	require.NoError(t, gob.NewEncoder(&encoded).Encode(values))

	assert.Contains(t, encoded.String(), legacyTokenResponseGobName,
		"the encoded session must carry the registered name a deployed session was written with")

	decoded := map[interface{}]interface{}{}
	require.NoError(t, gob.NewDecoder(bytes.NewReader(encoded.Bytes())).Decode(&decoded))

	got, ok := decoded[constants.SessionKeyJwt].(TokenResponse)
	require.True(t, ok, "the session value must decode back to oauth.TokenResponse")
	assert.Equal(t, want, got)
}

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
				IdToken:          "id-token",
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
			want: &Jwk{
				Alg: "RS256",
				Kid: "key-id",
				Kty: "RSA",
				Use: "sig",
				N:   "modulus",
				E:   "AQAB",
			},
			newValue: func() any { return &Jwk{} },
			literal:  `{"alg":"RS256","kid":"key-id","kty":"RSA","use":"sig","n":"modulus","e":"AQAB"}`,
		},
		{
			// No field of Jwk carries omitempty, so all six keys are present even when
			// empty. That is the /certs contract: a consumer reading a key it did not
			// find gets "" rather than a missing member.
			name:     "Jwk zero",
			want:     &Jwk{},
			newValue: func() any { return &Jwk{} },
			literal:  `{"alg":"","kid":"","kty":"","use":"","n":"","e":""}`,
		},
		{
			name: "Jwks populated",
			want: &Jwks{Keys: []Jwk{{
				Alg: "RS256",
				Kid: "key-id",
				Kty: "RSA",
				Use: "sig",
				N:   "modulus",
				E:   "AQAB",
			}}},
			newValue: func() any { return &Jwks{} },
			literal:  `{"keys":[{"alg":"RS256","kid":"key-id","kty":"RSA","use":"sig","n":"modulus","e":"AQAB"}]}`,
		},
		{
			// Keep this row: a nil slice encodes as null, not []. The JWKS parser at
			// token_parser_jwks.go decodes /certs into this type, so the empty envelope
			// is a shape it has to survive.
			name:     "Jwks zero",
			want:     &Jwks{},
			newValue: func() any { return &Jwks{} },
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
