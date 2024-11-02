package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestDecodeAndValidateTokenResponse_ValidTokens(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tp := NewTokenParser(mockDB)

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKeyPEM := exportRSAPublicKeyAsPEMStr(&privateKey.PublicKey)

	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		PublicKeyPEM: []byte(publicKeyPEM),
	}, nil)

	now := time.Now()
	expirationTime := now.Add(time.Hour)

	accessTokenClaims := map[string]interface{}{
		"type":  "Bearer",
		"sub":   "user123",
		"aud":   "client456",
		"iss":   "https://auth.example.com",
		"iat":   now.Unix(),
		"exp":   expirationTime.Unix(),
		"scope": "openid profile email",
	}

	idTokenClaims := map[string]interface{}{
		"type":  "ID",
		"sub":   "user123",
		"aud":   "client456",
		"iss":   "https://auth.example.com",
		"iat":   now.Unix(),
		"exp":   expirationTime.Unix(),
		"nonce": "randomnonce789",
		"name":  "John Doe",
		"email": "john@example.com",
	}

	refreshTokenClaims := map[string]interface{}{
		"type": "Refresh",
		"sub":  "user123",
		"aud":  "https://auth.example.com",
		"iss":  "https://auth.example.com",
		"iat":  now.Unix(),
		"exp":  expirationTime.Unix(),
		"jti":  "uniquerefreshid987",
	}

	tokenResponse := &TokenResponse{
		AccessToken:  createTestToken(privateKey, accessTokenClaims, expirationTime),
		IdToken:      createTestToken(privateKey, idTokenClaims, expirationTime),
		RefreshToken: createTestToken(privateKey, refreshTokenClaims, expirationTime),
	}

	result, err := tp.DecodeAndValidateTokenResponse(tokenResponse)

	assert.NoError(t, err)

	// Access Token Validations
	assert.NotNil(t, result.AccessToken)
	assert.Equal(t, "Bearer", result.AccessToken.GetStringClaim("type"))
	assert.Equal(t, "user123", result.AccessToken.GetStringClaim("sub"))
	assert.Equal(t, "client456", result.AccessToken.GetStringClaim("aud"))
	assert.Equal(t, "https://auth.example.com", result.AccessToken.GetStringClaim("iss"))
	assert.Equal(t, now.Unix(), int64(result.AccessToken.GetTimeClaim("iat").Unix()))
	assert.Equal(t, expirationTime.Unix(), int64(result.AccessToken.GetTimeClaim("exp").Unix()))
	assert.Equal(t, "openid profile email", result.AccessToken.GetStringClaim("scope"))
	assert.True(t, result.AccessToken.HasScope("openid"))
	assert.True(t, result.AccessToken.HasScope("profile"))
	assert.True(t, result.AccessToken.HasScope("email"))

	// ID Token Validations
	assert.NotNil(t, result.IdToken)
	assert.Equal(t, "ID", result.IdToken.GetStringClaim("type"))
	assert.Equal(t, "user123", result.IdToken.GetStringClaim("sub"))
	assert.Equal(t, "client456", result.IdToken.GetStringClaim("aud"))
	assert.Equal(t, "https://auth.example.com", result.IdToken.GetStringClaim("iss"))
	assert.Equal(t, now.Unix(), int64(result.IdToken.GetTimeClaim("iat").Unix()))
	assert.Equal(t, expirationTime.Unix(), int64(result.IdToken.GetTimeClaim("exp").Unix()))
	assert.Equal(t, "randomnonce789", result.IdToken.GetStringClaim("nonce"))
	assert.Equal(t, "John Doe", result.IdToken.GetStringClaim("name"))
	assert.Equal(t, "john@example.com", result.IdToken.GetStringClaim("email"))

	// Refresh Token Validations
	assert.NotNil(t, result.RefreshToken)
	assert.Equal(t, "Refresh", result.RefreshToken.GetStringClaim("type"))
	assert.Equal(t, "user123", result.RefreshToken.GetStringClaim("sub"))
	assert.Equal(t, "https://auth.example.com", result.RefreshToken.GetStringClaim("aud"))
	assert.Equal(t, "https://auth.example.com", result.RefreshToken.GetStringClaim("iss"))
	assert.Equal(t, now.Unix(), int64(result.RefreshToken.GetTimeClaim("iat").Unix()))
	assert.Equal(t, expirationTime.Unix(), int64(result.RefreshToken.GetTimeClaim("exp").Unix()))
	assert.Equal(t, "uniquerefreshid987", result.RefreshToken.GetStringClaim("jti"))
}

func TestDecodeAndValidateTokenResponse_ExpiredAccessToken(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tp := NewTokenParser(mockDB)

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKeyPEM := exportRSAPublicKeyAsPEMStr(&privateKey.PublicKey)

	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		PublicKeyPEM: []byte(publicKeyPEM),
	}, nil)

	tokenResponse := &TokenResponse{
		AccessToken: createTestToken(privateKey, map[string]interface{}{"type": "Bearer"}, time.Now().Add(-time.Hour)),
	}

	result, err := tp.DecodeAndValidateTokenResponse(tokenResponse)

	assert.Error(t, err)
	assert.Equal(t, "token has invalid claims: token is expired", err.Error())
	assert.Nil(t, result)
}

func TestDecodeAndValidateTokenResponse_InvalidSignature(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tp := NewTokenParser(mockDB)

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privateKeyAlternate, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKeyPEM := exportRSAPublicKeyAsPEMStr(&privateKey.PublicKey)

	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		PublicKeyPEM: []byte(publicKeyPEM),
	}, nil)

	tokenResponse := &TokenResponse{
		AccessToken: createTestToken(privateKeyAlternate, map[string]interface{}{"type": "Bearer"}, time.Now().Add(time.Hour)),
	}

	result, err := tp.DecodeAndValidateTokenResponse(tokenResponse)

	assert.Error(t, err)
	assert.Equal(t, "token signature is invalid: crypto/rsa: verification error", err.Error())
	assert.Nil(t, result)
}

func TestDecodeAndValidateTokenResponse_EmptyTokens(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tp := NewTokenParser(mockDB)

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKeyPEM := exportRSAPublicKeyAsPEMStr(&privateKey.PublicKey)

	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		PublicKeyPEM: []byte(publicKeyPEM),
	}, nil)

	tokenResponse := &TokenResponse{
		AccessToken:  "",
		IdToken:      "",
		RefreshToken: "",
	}

	result, err := tp.DecodeAndValidateTokenResponse(tokenResponse)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Nil(t, result.AccessToken)
	assert.Nil(t, result.IdToken)
	assert.Nil(t, result.RefreshToken)
}

func TestDecodeAndValidateTokenString(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tp := NewTokenParser(mockDB)

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

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
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, tt.tokenClaims)
			tokenString, _ := token.SignedString(privateKey)

			result, err := tp.DecodeAndValidateTokenString(tokenString, publicKey, true)

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

func TestDecodeAndValidateTokenString_InvalidSignature(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tp := NewTokenParser(mockDB)

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	claims := jwt.MapClaims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(wrongPrivateKey)

	result, err := tp.DecodeAndValidateTokenString(tokenString, publicKey, true)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token signature is invalid")
	assert.Nil(t, result)
}

func TestDecodeAndValidateTokenString_EmptyToken(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tp := NewTokenParser(mockDB)

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	result, err := tp.DecodeAndValidateTokenString("", publicKey, true)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "", result.TokenBase64)
	assert.Nil(t, result.Claims)
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
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkeyBytes,
		},
	)
	return string(pubkeyPem)
}
