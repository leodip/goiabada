package rsautil

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		bitSize int
		wantErr bool
	}{
		{"Valid 2048-bit key", 2048, false},
		{"Valid 4096-bit key", 4096, false},
		{"Valid 1024-bit key", 1024, false}, // 1024-bit keys are valid, though not recommended for security reasons
		{"Invalid bit size", 0, true},       // This should definitely fail
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := GeneratePrivateKey(tt.bitSize)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, privateKey)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, privateKey)
				assert.Equal(t, tt.bitSize, privateKey.N.BitLen())
			}
		})
	}
}

func TestEncodePrivateKeyToPEM(t *testing.T) {
	privateKey, err := GeneratePrivateKey(2048)
	require.NoError(t, err)

	pemBytes := EncodePrivateKeyToPEM(privateKey)
	assert.NotEmpty(t, pemBytes)
	assert.Contains(t, string(pemBytes), "-----BEGIN RSA PRIVATE KEY-----")
	assert.Contains(t, string(pemBytes), "-----END RSA PRIVATE KEY-----")
}

func TestEncodePublicKeyToPEM(t *testing.T) {
	privateKey, err := GeneratePrivateKey(2048)
	require.NoError(t, err)

	publicKey := &privateKey.PublicKey
	pemBytes, err := EncodePublicKeyToPEM(publicKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, pemBytes)
	assert.Contains(t, string(pemBytes), "-----BEGIN RSA PUBLIC KEY-----")
	assert.Contains(t, string(pemBytes), "-----END RSA PUBLIC KEY-----")
}

func TestMarshalRSAPublicKeyToJWK(t *testing.T) {
	privateKey, err := GeneratePrivateKey(2048)
	require.NoError(t, err)

	publicKey := &privateKey.PublicKey
	kid := "test-key-id"

	jwkBytes, err := MarshalRSAPublicKeyToJWK(publicKey, kid)
	assert.NoError(t, err)
	assert.NotEmpty(t, jwkBytes)

	var jwk map[string]interface{}
	err = json.Unmarshal(jwkBytes, &jwk)
	assert.NoError(t, err)

	assert.Equal(t, "RS256", jwk["alg"])
	assert.Equal(t, kid, jwk["kid"])
	assert.Equal(t, "RSA", jwk["kty"])
	assert.Equal(t, "sig", jwk["use"])
	assert.NotEmpty(t, jwk["n"])
	assert.NotEmpty(t, jwk["e"])
}
