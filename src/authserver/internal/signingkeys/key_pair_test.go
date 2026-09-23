package signingkeys

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/uuidutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// testKeySizeBits is the smallest size crypto/rsa generates. Production mints at 4096, which the
// rotator's own test pins; the encodings do not depend on the size.
const testKeySizeBits = 1024

// TestNewKeyPair_BuildsTheRowTheKeySetStores holds the row to what each of its readers needs: the
// state it was asked for, a kid the JWK agrees with, the public key in RFC 7468's label over the
// same bytes as the DER column, and a private key that is encrypted at rest yet decrypts through
// ParsePrivateKey to the half of the pair the public columns describe. A row whose private and
// public halves came from different keys would sign tokens nobody could verify.
func TestNewKeyPair_BuildsTheRowTheKeySetStores(t *testing.T) {
	for _, state := range []models.KeyState{models.KeyStateCurrent, models.KeyStateNext} {
		t.Run(state.String(), func(t *testing.T) {
			row, err := NewKeyPair(state, testKeySizeBits)
			require.NoError(t, err)
			require.NotNil(t, row)

			assert.Equal(t, state.String(), row.State)
			assert.Equal(t, "RSA", row.Type)
			assert.Equal(t, "RS256", row.Algorithm)
			assert.Zero(t, row.Id, "NewKeyPair writes nothing, so no id is assigned")

			parsedKid, err := uuidutil.Parse(row.KeyIdentifier)
			require.NoError(t, err)
			assert.Equal(t, row.KeyIdentifier, parsedKid)

			var jwk map[string]string
			require.NoError(t, json.Unmarshal(row.PublicKeyJWK, &jwk))
			assert.Equal(t, row.KeyIdentifier, jwk["kid"], "the JWK names a different kid from the row")

			block, rest := pem.Decode(row.PublicKeyPEM)
			require.NotNil(t, block)
			assert.Empty(t, rest)
			assert.Equal(t, "PUBLIC KEY", block.Type)
			assert.Equal(t, row.PublicKeyASN1_DER, block.Bytes, "the public PEM and the DER column disagree")

			parsed, err := x509.ParsePKIXPublicKey(row.PublicKeyASN1_DER)
			require.NoError(t, err)
			publicKey, ok := parsed.(*rsa.PublicKey)
			require.True(t, ok)

			assert.NotContains(t, string(row.PrivateKeyPEM), "PRIVATE KEY", "the private key is stored in the clear")
			privateKey, err := ParsePrivateKey(row)
			require.NoError(t, err)
			assert.True(t, privateKey.PublicKey.Equal(publicKey), "the private key is not the stored public key's")
		})
	}
}

func TestNewKeyPair_MintsAKidPerKey(t *testing.T) {
	first, err := NewKeyPair(models.KeyStateNext, testKeySizeBits)
	require.NoError(t, err)
	second, err := NewKeyPair(models.KeyStateNext, testKeySizeBits)
	require.NoError(t, err)

	assert.NotEqual(t, first.KeyIdentifier, second.KeyIdentifier)
	assert.NotEqual(t, first.PublicKeyASN1_DER, second.PublicKeyASN1_DER)
}

func TestNewKeyPair_RefusesABitSizeRSARefuses(t *testing.T) {
	row, err := NewKeyPair(models.KeyStateNext, 512)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to generate a private key")
	assert.Nil(t, row)
}

// relabel re-encodes a PEM's bytes under another label, which is how a row stored before #424
// differs from one NewKeyPair builds: the same SubjectPublicKeyInfo bytes under "RSA PUBLIC KEY".
func relabel(t *testing.T, data []byte, label string) []byte {
	t.Helper()
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	return pem.EncodeToMemory(&pem.Block{Type: label, Bytes: block.Bytes})
}

// TestNewKeyPair_TheTokenParserReadsBothLabels is what makes it safe to change the label without
// rewriting stored rows (#424 decision 9): a key generated before the change keeps "RSA PUBLIC KEY"
// until it rotates out, and a token it signed must still verify, as must one signed by a key
// generated after. Each row signs a token through ParsePrivateKey and serves as the current key.
func TestNewKeyPair_TheTokenParserReadsBothLabels(t *testing.T) {
	for _, label := range []string{"PUBLIC KEY", "RSA PUBLIC KEY"} {
		t.Run(label, func(t *testing.T) {
			row, err := NewKeyPair(models.KeyStateCurrent, testKeySizeBits)
			require.NoError(t, err)
			row.PublicKeyPEM = relabel(t, row.PublicKeyPEM, label)

			privateKey, err := ParsePrivateKey(row)
			require.NoError(t, err)
			token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub": "subject",
				"exp": time.Now().Add(time.Hour).Unix(),
			}).SignedString(privateKey)
			require.NoError(t, err)

			database := mocks_data.NewDatabase(t)
			database.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(row, nil).Once()

			result, err := NewTokenParser(database).DecodeAndValidateTokenString(context.Background(), token, true)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, "subject", result.Claims["sub"])
		})
	}
}
