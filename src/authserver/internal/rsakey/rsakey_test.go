package rsakey

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeOnePEM decodes data as exactly one PEM block with nothing after it, so a second block or
// trailing bytes cannot hide behind a first one that passes.
func decodeOnePEM(t *testing.T, data []byte) *pem.Block {
	t.Helper()
	block, rest := pem.Decode(data)
	require.NotNil(t, block, "not a PEM block")
	assert.Empty(t, rest, "bytes after the PEM block")
	return block
}

// TestGenerate_Encodings holds each encoding to the format its label or its field promises, by
// parsing it with the parser that format names rather than by matching its text. The public PEM is
// the one #424 changed: SubjectPublicKeyInfo bytes, which RFC 7468 section 13 labels "PUBLIC KEY".
func TestGenerate_Encodings(t *testing.T) {
	material, err := Generate(1024, "test-kid")
	require.NoError(t, err)

	privateBlock := decodeOnePEM(t, material.PrivateKeyPEM)
	assert.Equal(t, "RSA PRIVATE KEY", privateBlock.Type)
	privateKey, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	require.NoError(t, err, "the private key PEM is not PKCS#1")
	require.NoError(t, privateKey.Validate())
	assert.Equal(t, 1024, privateKey.N.BitLen())

	publicBlock := decodeOnePEM(t, material.PublicKeyPEM)
	assert.Equal(t, "PUBLIC KEY", publicBlock.Type)
	assert.Equal(t, material.PublicKeyDER, publicBlock.Bytes, "the public PEM and the DER disagree")

	parsed, err := x509.ParsePKIXPublicKey(material.PublicKeyDER)
	require.NoError(t, err, "the public key DER is not SubjectPublicKeyInfo")
	publicKey, ok := parsed.(*rsa.PublicKey)
	require.True(t, ok, "the public key is not RSA")
	assert.True(t, publicKey.Equal(&privateKey.PublicKey), "the public key is not the private key's")

	var jwk map[string]string
	require.NoError(t, json.Unmarshal(material.PublicKeyJWK, &jwk))
	assert.Equal(t, "RS256", jwk["alg"])
	assert.Equal(t, "test-kid", jwk["kid"])
	assert.Equal(t, "RSA", jwk["kty"])
	assert.Equal(t, "sig", jwk["use"])

	n, err := base64.RawURLEncoding.DecodeString(jwk["n"])
	require.NoError(t, err)
	assert.Equal(t, 0, new(big.Int).SetBytes(n).Cmp(privateKey.N), "the JWK's n is not the modulus")
	e, err := base64.RawURLEncoding.DecodeString(jwk["e"])
	require.NoError(t, err)
	assert.Equal(t, int64(privateKey.E), new(big.Int).SetBytes(e).Int64(), "the JWK's e is not the exponent")
}

func TestGenerate_BitSizes(t *testing.T) {
	tests := []struct {
		name    string
		bits    int
		wantErr bool
	}{
		{"1024 bits", 1024, false},
		{"2048 bits", 2048, false},
		{"zero is refused", 0, true},
		{"512 is refused, crypto/rsa's floor being 1024", 512, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			material, err := Generate(tt.bits, "kid")
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unable to generate a private key")
				assert.Equal(t, Material{}, material)
				return
			}
			require.NoError(t, err)
			privateKey, err := x509.ParsePKCS1PrivateKey(decodeOnePEM(t, material.PrivateKeyPEM).Bytes)
			require.NoError(t, err)
			assert.Equal(t, tt.bits, privateKey.N.BitLen())
		})
	}
}

func TestGenerate_EachCallIsAFreshKey(t *testing.T) {
	first, err := Generate(1024, "kid")
	require.NoError(t, err)
	second, err := Generate(1024, "kid")
	require.NoError(t, err)

	assert.NotEqual(t, first.PublicKeyDER, second.PublicKeyDER)
}
