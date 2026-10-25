package signingkeys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The parser reads its key from the database and nowhere else, so every case below that verifies a
// token stubs the current key on a strict mock. A case that leaves GetAllSigningKeys unstubbed is
// also asserting that no fallback key was tried, and one with nothing stubbed that no key was read.
//
// A failure of the token itself carries ErrTokenRefused, and an expired token ErrTokenExpired as
// well; a failure to read or decode a key carries neither, so a caller can tell a token it should
// refuse from one it could not check (#680).

func TestDecodeAndValidateTokenString(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name          string
		tokenClaims   jwt.MapClaims
		expectedError string
		expired       bool
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
			expired:       true,
		},
		{
			name: "Missing expiration",
			tokenClaims: jwt.MapClaims{
				"sub": "1234567890",
			},
			expectedError: "token has invalid claims: token is missing required claim: exp claim is required",
		},
		{
			name: "Not yet valid",
			tokenClaims: jwt.MapClaims{
				"sub": "1234567890",
				"exp": time.Now().Add(2 * time.Hour).Unix(),
				"nbf": time.Now().Add(time.Hour).Unix(),
			},
			expectedError: "token has invalid claims: token is not valid yet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp := NewTokenParser(currentKeyDatabase(t, privateKey))
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, tt.tokenClaims)
			tokenString, _ := token.SignedString(privateKey)

			result, err := tp.DecodeAndValidateTokenString(context.Background(), tokenString, true)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
				require.ErrorIs(t, err, ErrTokenRefused)
				assert.Equal(t, tt.expired, errors.Is(err, ErrTokenExpired), "expired mark")
			} else {
				require.NoError(t, err)
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
				assert.Equal(t, v, result.StringClaim(k), k)
			}
			assert.Equal(t, now.Unix(), result.TimeClaim("iat").Unix())
			assert.Equal(t, expirationTime.Unix(), result.TimeClaim("exp").Unix())
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
		assert.Equal(t, "user123", result.StringClaim("sub"))
	})

	t.Run("with the check it is refused as expired", func(t *testing.T) {
		tp := NewTokenParser(currentKeyDatabase(t, privateKey))

		result, err := tp.DecodeAndValidateTokenString(context.Background(), token, true)

		require.Error(t, err)
		require.ErrorIs(t, err, jwt.ErrTokenExpired)
		assert.Nil(t, result)
	})
}

func TestDecodeAndValidateTokenString_InvalidSignature(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockDB := currentKeyDatabase(t, privateKey)
	tp := NewTokenParser(mockDB)

	// When signature validation fails, the parser tries all signing keys as fallback
	mockDB.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return([]record.KeyPair{}, nil)

	claims := jwt.MapClaims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(wrongPrivateKey)

	result, err := tp.DecodeAndValidateTokenString(context.Background(), tokenString, true)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "token signature is invalid")
	assert.Nil(t, result)
	require.ErrorIs(t, err, ErrTokenRefused)
	require.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid)
	require.NotErrorIs(t, err, ErrTokenExpired)
}

// A token signed by a key that has stopped being current still verifies, through the fallback
// keys; the current key among them is skipped rather than tried twice.
func TestDecodeAndValidateTokenString_AcceptsATokenSignedByAFallbackKey(t *testing.T) {
	currentKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	previousKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockDB := currentKeyDatabase(t, currentKey)
	tp := NewTokenParser(mockDB)

	mockDB.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return([]record.KeyPair{
		{Id: 1, State: record.KeyStateCurrent.String(), PublicKeyPEM: []byte(exportRSAPublicKeyAsPEMStr(&currentKey.PublicKey))},
		{Id: 2, State: record.KeyStatePrevious.String(), PublicKeyPEM: []byte(exportRSAPublicKeyAsPEMStr(&previousKey.PublicKey))},
	}, nil).Once()

	token := createTestToken(previousKey, map[string]interface{}{"sub": "user123"}, time.Now().Add(time.Hour))

	result, err := tp.DecodeAndValidateTokenString(context.Background(), token, true)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "user123", result.StringClaim("sub"))
}

// A failed read of the fallback keys reaches the caller beside the parse error, each matchable:
// the parse error says why the current key did not verify it, the lookup error that no other key
// could be tried. Returning the parse error alone hid the second (#424). The token might be good,
// so the error carries no refused mark (#680).
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
	require.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid)
	require.ErrorIs(t, err, lookupErr)
	assert.Contains(t, err.Error(), "unable to read the signing keys to try")
	require.NotErrorIs(t, err, ErrTokenRefused)
	require.NotErrorIs(t, err, ErrTokenExpired)
}

// A token whose header names a method other than RS256 cannot be valid, so it is refused before any
// key is read: the strict mock has nothing stubbed.
func TestDecodeAndValidateTokenString_RejectsNonRS256Token(t *testing.T) {
	tp := NewTokenParser(datamocks.NewDatabase(t))

	claims := jwt.MapClaims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("secret"))

	result, err := tp.DecodeAndValidateTokenString(context.Background(), tokenString, true)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "signing method HS256 is invalid")
	assert.Nil(t, result)
	require.ErrorIs(t, err, ErrTokenRefused)
	require.NotErrorIs(t, err, ErrTokenExpired)
}

// A token that is not a well-formed JWT cannot be valid either, and is refused before any key is
// read, with the library's malformed error kept in the chain.
func TestDecodeAndValidateTokenString_RefusesAMalformedTokenWithoutReadingAKey(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signed := createTestToken(privateKey, map[string]interface{}{"sub": "user123"}, time.Now().Add(time.Hour))
	parts := strings.Split(signed, ".")

	tokens := map[string]string{
		"one segment":                    "not-a-refresh-token",
		"a header that is not base64":    "!!!." + parts[1] + "." + parts[2],
		"a signature that is not base64": parts[0] + "." + parts[1] + ".!!!",
	}
	for name, token := range tokens {
		t.Run(name, func(t *testing.T) {
			tp := NewTokenParser(datamocks.NewDatabase(t))

			result, err := tp.DecodeAndValidateTokenString(context.Background(), token, true)

			require.Error(t, err)
			assert.Nil(t, result)
			require.ErrorIs(t, err, ErrTokenRefused)
			require.ErrorIs(t, err, jwt.ErrTokenMalformed)
			require.NotErrorIs(t, err, ErrTokenExpired)
		})
	}
}

// An expired token signed by a previous key is refused as expired: its signature verified against
// a stored key, so the key set holding other keys after it does not turn it into a bad signature.
func TestDecodeAndValidateTokenString_AnExpiredTokenSignedByAFallbackKeyIsExpired(t *testing.T) {
	currentKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	previousKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	unrelatedKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockDB := currentKeyDatabase(t, currentKey)
	tp := NewTokenParser(mockDB)

	mockDB.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return([]record.KeyPair{
		{Id: 1, State: record.KeyStateCurrent.String(), PublicKeyPEM: []byte(exportRSAPublicKeyAsPEMStr(&currentKey.PublicKey))},
		{Id: 2, State: record.KeyStatePrevious.String(), PublicKeyPEM: []byte(exportRSAPublicKeyAsPEMStr(&previousKey.PublicKey))},
		{Id: 3, State: record.KeyStateNext.String(), PublicKeyPEM: []byte(exportRSAPublicKeyAsPEMStr(&unrelatedKey.PublicKey))},
	}, nil).Once()

	token := createTestToken(previousKey, map[string]interface{}{"sub": "user123"}, time.Now().Add(-time.Hour))

	result, err := tp.DecodeAndValidateTokenString(context.Background(), token, true)

	require.Error(t, err)
	assert.Nil(t, result)
	require.ErrorIs(t, err, ErrTokenRefused)
	require.ErrorIs(t, err, ErrTokenExpired)
	require.ErrorIs(t, err, jwt.ErrTokenExpired)
}

// Each way the parser can fail to check a well-formed RS256 token, because it could not read or
// decode a key, comes back unmarked with its cause in the chain: the token might be good.
func TestDecodeAndValidateTokenString_AKeyItCouldNotReadOrDecodeIsNotARefusal(t *testing.T) {
	currentKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	previousKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	currentKeyPair := record.KeyPair{Id: 1, State: record.KeyStateCurrent.String(),
		PublicKeyPEM: []byte(exportRSAPublicKeyAsPEMStr(&currentKey.PublicKey))}
	undecodableKeyPair := record.KeyPair{Id: 2, State: record.KeyStatePrevious.String(),
		PublicKeyPEM: []byte("not a key")}

	t.Run("the current key cannot be read", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		readErr := errors.New("the database is unreachable")
		mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(nil, readErr).Once()
		tp := NewTokenParser(mockDB)
		token := createTestToken(currentKey, map[string]interface{}{"sub": "user123"}, time.Now().Add(time.Hour))

		result, err := tp.DecodeAndValidateTokenString(context.Background(), token, true)

		require.Error(t, err)
		assert.Nil(t, result)
		require.ErrorIs(t, err, readErr)
		require.NotErrorIs(t, err, ErrTokenRefused)
		require.NotErrorIs(t, err, ErrTokenExpired)
	})

	t.Run("the current key cannot be decoded", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&undecodableKeyPair, nil).Once()
		tp := NewTokenParser(mockDB)
		token := createTestToken(currentKey, map[string]interface{}{"sub": "user123"}, time.Now().Add(time.Hour))

		result, err := tp.DecodeAndValidateTokenString(context.Background(), token, true)

		require.Error(t, err)
		assert.Nil(t, result)
		require.ErrorIs(t, err, jwt.ErrKeyMustBePEMEncoded)
		require.NotErrorIs(t, err, ErrTokenRefused)
	})

	t.Run("a stored key the token may be signed by cannot be decoded", func(t *testing.T) {
		mockDB := currentKeyDatabase(t, currentKey)
		mockDB.On("GetAllSigningKeys", mock.Anything, mock.Anything).
			Return([]record.KeyPair{undecodableKeyPair, currentKeyPair}, nil).Once()
		tp := NewTokenParser(mockDB)
		token := createTestToken(previousKey, map[string]interface{}{"sub": "user123"}, time.Now().Add(time.Hour))

		result, err := tp.DecodeAndValidateTokenString(context.Background(), token, true)

		require.Error(t, err)
		assert.Nil(t, result)
		require.ErrorIs(t, err, jwt.ErrKeyMustBePEMEncoded)
		require.NotErrorIs(t, err, ErrTokenRefused)
	})

	t.Run("an undecodable stored key does not stop another from verifying", func(t *testing.T) {
		mockDB := currentKeyDatabase(t, currentKey)
		mockDB.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return([]record.KeyPair{
			undecodableKeyPair,
			{Id: 3, State: record.KeyStatePrevious.String(), PublicKeyPEM: []byte(exportRSAPublicKeyAsPEMStr(&previousKey.PublicKey))},
		}, nil).Once()
		tp := NewTokenParser(mockDB)
		token := createTestToken(previousKey, map[string]interface{}{"sub": "user123"}, time.Now().Add(time.Hour))

		result, err := tp.DecodeAndValidateTokenString(context.Background(), token, true)

		require.NoError(t, err)
		assert.Equal(t, "user123", result.StringClaim("sub"))
	})
}

// An empty token parses to an empty result and reads no key: the strict mock has nothing stubbed.
func TestDecodeAndValidateTokenString_EmptyToken(t *testing.T) {
	for _, withExpirationCheck := range []bool{true, false} {
		mockDB := datamocks.NewDatabase(t)
		tp := NewTokenParser(mockDB)

		result, err := tp.DecodeAndValidateTokenString(context.Background(), "", withExpirationCheck)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Empty(t, result.TokenBase64)
		assert.Nil(t, result.Claims)
	}
}

// currentKeyDatabase is a strict database mock whose current signing key is privateKey's.
func currentKeyDatabase(t *testing.T, privateKey *rsa.PrivateKey) *datamocks.Database {
	t.Helper()
	mockDB := datamocks.NewDatabase(t)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&record.KeyPair{
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
