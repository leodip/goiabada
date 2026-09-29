package issuance

import (
	"context"
	"testing"
	"time"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/uuidutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGenerateTokenResponseForClientCred(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher)

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 3600,
	}

	ctx := context.Background()

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	tests := []struct {
		name           string
		client         *models.Client
		scope          string
		expectedScopes []string
		expectedAud    interface{}
	}{
		{
			name: "Single custom scope",
			client: &models.Client{
				Id:               1,
				ClientIdentifier: "test-client-1",
			},
			scope:          "resource1:read",
			expectedScopes: []string{"resource1:read"},
			expectedAud:    "resource1",
		},
		{
			name: "Multiple custom scopes",
			client: &models.Client{
				Id:               2,
				ClientIdentifier: "test-client-2",
			},
			scope:          "resource1:read resource2:write",
			expectedScopes: []string{"resource1:read", "resource2:write"},
			expectedAud:    []interface{}{"resource1", "resource2"},
		},
		{
			name: "Custom scopes with OIDC scopes (should be ignored)",
			client: &models.Client{
				Id:               3,
				ClientIdentifier: "test-client-3",
			},
			scope:          "resource1:read openid profile",
			expectedScopes: []string{"resource1:read"},
			expectedAud:    "resource1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&models.KeyPair{
				KeyIdentifier: "test-key-id",
				PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
			}, nil)

			response, err := tokenIssuer.GenerateTokenResponseForClientCred(ctx, settings, tt.client, tt.scope)

			assert.NoError(t, err)
			assert.NotNil(t, response)
			assert.Equal(t, "Bearer", response.TokenType)
			assert.Equal(t, int64(3600), response.ExpiresIn)
			assert.NotEmpty(t, response.AccessToken)
			assert.Empty(t, response.IdToken)
			assert.Empty(t, response.RefreshToken)
			assert.Equal(t, tt.scope, response.Scope)

			claims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)

			assert.Equal(t, settings.Issuer, claims["iss"])
			assert.Equal(t, tt.client.ClientIdentifier, claims["sub"])
			assert.Equal(t, tt.expectedAud, claims["aud"])
			assert.Equal(t, "Bearer", claims["typ"])
			assert.Equal(t, tt.scope, claims["scope"])

			assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
			assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
			assertTimeClaimWithinRange(t, claims, "exp", 3600*time.Second, "exp should be 3600 seconds from now")

			_, err = uuidutil.Parse(claims["jti"].(string))
			assert.NoError(t, err)

			mockDB.AssertExpectations(t)
		})
	}
}

func TestGenerateTokenResponseForClientCred_InvalidScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher)

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 3600,
	}

	ctx := context.Background()

	client := &models.Client{
		Id:               4,
		ClientIdentifier: "test-client-4",
	}

	privateKeyBytes := getTestPrivateKey(t)

	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)

	response, err := tokenIssuer.GenerateTokenResponseForClientCred(ctx, settings, client, "invalid-scope")

	if err == nil {
		t.Error("Expected an error, but got nil")
		if response != nil {
			t.Errorf("Unexpected response: %+v", response)
		}
	} else {
		assert.Contains(t, err.Error(), "invalid scope: invalid-scope")
	}

	mockDB.AssertExpectations(t)
}
