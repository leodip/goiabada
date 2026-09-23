package signingkeys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The parser reads its key from the database and nowhere else, so every case below that parses a
// token stubs the current key on a strict mock. A case that leaves GetAllSigningKeys unstubbed is
// also asserting that no fallback key was tried.

func TestDecodeAndValidateTokenString(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name          string
		tokenClaims   jwt.MapClaims
		expectedError string
	}{
		{
			name: "Valid token",
			tokenClaims: jwt.MapClaims{
				"sub": "1234567890",
				"exp": time.Now().Add(time.Hour).Unix(),
			},
			expectedError: "",
		},
		{
			name: "Expired token",
			tokenClaims: jwt.MapClaims{
				"sub": "1234567890",
				"exp": time.Now().Add(-time.Hour).Unix(),
			},
			expectedError: "token has invalid claims: token is expired",
		},
		{
			name: "Missing expiration",
			tokenClaims: jwt.MapClaims{
				"sub": "1234567890",
			},
			expectedError: "token has invalid claims: token is missing required claim: exp claim is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp := NewTokenParser(currentKeyDatabase(t, privateKey))
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, tt.tokenClaims)
			tokenString, _ := token.SignedString(privateKey)

			result, err := tp.DecodeAndValidateTokenString(context.Background(), tokenString, true)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tokenString, result.TokenBase64)
				assert.Equal(t, tt.tokenClaims["sub"], result.Claims["sub"])
			}
		})
	}
}

// Every claim of the three token types the auth server issues comes back as issued. Re-expressed
// from the deleted DecodeAndValidateTokenResponse, which parsed the refresh token without the
// expiration check; so does this case.
func TestDecodeAndValidateTokenString_ReturnsEveryClaimOfEachTokenType(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	expirationTime := now.Add(time.Hour)

	tests := []struct {
		name                string
		withExpirationCheck bool
		stringClaims        map[string]string
	}{
		{
			name:                "access token",
			withExpirationCheck: true,
			stringClaims: map[string]string{
				"type": "Bearer", "sub": "user123", "aud": "client456",
				"iss": "https://auth.example.com", "scope": "openid profile email",
			},
		},
		{
			name:                "id token",
			withExpirationCheck: true,
			stringClaims: map[string]string{
				"type": "ID", "sub": "user123", "aud": "client456", "iss": "https://auth.example.com",
				"nonce": "randomnonce789", "name": "John Doe", "email": "john@example.com",
			},
		},
		{
			name:                "refresh token",
			withExpirationCheck: false,
			stringClaims: map[string]string{
				"type": "Refresh", "sub": "user123", "aud": "https://auth.example.com",
				"iss": "https://auth.example.com", "jti": "uniquerefreshid987",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp := NewTokenParser(currentKeyDatabase(t, privateKey))
			claims := map[string]interface{}{"iat": now.Unix()}
			for k, v := range tt.stringClaims {
				claims[k] = v
			}
			token := createTestToken(privateKey, claims, expirationTime)

			result, err := tp.DecodeAndValidateTokenString(context.Background(), token, tt.withExpirationCheck)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, token, result.TokenBase64)
			for k, v := range tt.stringClaims {
				assert.Equal(t, v, result.GetStringClaim(k), k)
			}
			assert.Equal(t, now.Unix(), result.GetTimeClaim("iat").Unix())
			assert.Equal(t, expirationTime.Unix(), result.GetTimeClaim("exp").Unix())
		})
	}
}

// Without the expiration check no claim is validated, which is how logout and the authorize
// endpoint read an id_token_hint: an expired hint still names its subject. With the check the same
// token is refused, and neither answer tries a fallback key, since the signature verified.
func TestDecodeAndValidateTokenString_TheExpirationCheckIsTheCallersChoice(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := createTestToken(privateKey, map[string]interface{}{"sub": "user123"}, time.Now().Add(-time.Hour))

	t.Run("without the check an expired token is accepted", func(t *testing.T) {
		tp := NewTokenParser(currentKeyDatabase(t, privateKey))

		result, err := tp.DecodeAndValidateTokenString(context.Background(), token, false)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "user123", result.GetStringClaim("sub"))
	})

	t.Run("with the check it is refused as expired", func(t *testing.T) {
		tp := NewTokenParser(currentKeyDatabase(t, privateKey))

		result, err := tp.DecodeAndValidateTokenString(context.Background(), token, true)

		require.Error(t, err)
		assert.ErrorIs(t, err, jwt.ErrTokenExpired)
		assert.Nil(t, result)
	})
}

func TestDecodeAndValidateTokenString_InvalidSignature(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockDB := currentKeyDatabase(t, privateKey)
	tp := NewTokenParser(mockDB)

	// When signature validation fails, the parser tries all signing keys as fallback
	mockDB.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return([]models.KeyPair{}, nil)

	claims := jwt.MapClaims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(wrongPrivateKey)

	result, err := tp.DecodeAndValidateTokenString(context.Background(), tokenString, true)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token signature is invalid")
	assert.Nil(t, result)
}

// A token signed by a key that has stopped being current still verifies, through the fallback
// keys; the current key among them is skipped rather than tried twice.
func TestDecodeAndValidateTokenString_AcceptsATokenSignedByAFallbackKey(t *testing.T) {
	currentKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	previousKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockDB := currentKeyDatabase(t, currentKey)
	tp := NewTokenParser(mockDB)

	mockDB.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return([]models.KeyPair{
		{Id: 1, State: models.KeyStateCurrent.String(), PublicKeyPEM: []byte(exportRSAPublicKeyAsPEMStr(&currentKey.PublicKey))},
		{Id: 2, State: models.KeyStatePrevious.String(), PublicKeyPEM: []byte(exportRSAPublicKeyAsPEMStr(&previousKey.PublicKey))},
	}, nil).Once()

	token := createTestToken(previousKey, map[string]interface{}{"sub": "user123"}, time.Now().Add(time.Hour))

	result, err := tp.DecodeAndValidateTokenString(context.Background(), token, true)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "user123", result.GetStringClaim("sub"))
}

// A failed read of the fallback keys reaches the caller beside the parse error, each matchable:
// the parse error says why the token was refused, the lookup error that no other key could be
// tried. Returning the parse error alone hid the second (#424).
func TestDecodeAndValidateTokenString_AFailedFallbackLookupReportsBothErrors(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockDB := currentKeyDatabase(t, privateKey)
	tp := NewTokenParser(mockDB)

	lookupErr := errors.New("the key set is unreachable")
	mockDB.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return(nil, lookupErr).Once()

	token := createTestToken(wrongPrivateKey, map[string]interface{}{"sub": "user123"}, time.Now().Add(time.Hour))

	result, err := tp.DecodeAndValidateTokenString(context.Background(), token, true)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid)
	assert.ErrorIs(t, err, lookupErr)
	assert.Contains(t, err.Error(), "unable to read the signing keys to try")
}

func TestDecodeAndValidateTokenString_RejectsNonRS256Token(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockDB := currentKeyDatabase(t, privateKey)
	tp := NewTokenParser(mockDB)

	mockDB.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return([]models.KeyPair{}, nil)

	claims := jwt.MapClaims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("secret"))

	result, err := tp.DecodeAndValidateTokenString(context.Background(), tokenString, true)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signing method HS256 is invalid")
	assert.Nil(t, result)
}

// An empty token parses to an empty result and reads no key: the strict mock has nothing stubbed.
func TestDecodeAndValidateTokenString_EmptyToken(t *testing.T) {
	for _, withExpirationCheck := range []bool{true, false} {
		mockDB := mocks_data.NewDatabase(t)
		tp := NewTokenParser(mockDB)

		result, err := tp.DecodeAndValidateTokenString(context.Background(), "", withExpirationCheck)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "", result.TokenBase64)
		assert.Nil(t, result.Claims)
	}
}

// currentKeyDatabase is a strict database mock whose current signing key is privateKey's.
func currentKeyDatabase(t *testing.T, privateKey *rsa.PrivateKey) *mocks_data.Database {
	t.Helper()
	mockDB := mocks_data.NewDatabase(t)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&models.KeyPair{
		PublicKeyPEM: []byte(exportRSAPublicKeyAsPEMStr(&privateKey.PublicKey)),
	}, nil)
	return mockDB
}

func createTestToken(privateKey *rsa.PrivateKey, claims map[string]interface{}, expirationTime time.Time) string {
	token := jwt.New(jwt.SigningMethodRS256)
	claims["exp"] = expirationTime.Unix()
	for k, v := range claims {
		token.Claims.(jwt.MapClaims)[k] = v
	}
	tokenString, _ := token.SignedString(privateKey)
	return tokenString
}

func exportRSAPublicKeyAsPEMStr(pubkey *rsa.PublicKey) string {
	pubkeyBytes, _ := x509.MarshalPKIXPublicKey(pubkey)
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubkeyBytes,
		},
	)
	return string(pubkeyPem)
}
