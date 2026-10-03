package issuance

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestIssueImplicitTx_AccessTokenOnly(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &record.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		IncludeOpenIDConnectClaimsInAccessToken: false,
	}

	ctx := context.Background()

	sub := fake.UUID()
	sessionIdentifier := "test-session-implicit"
	authenticatedAt := time.Now().UTC().Add(-5 * time.Minute)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	client := &record.Client{
		Id:               1,
		ClientIdentifier: "implicit-test-client",
	}
	user := &record.User{
		Id:       1,
		Subject:  sub,
		Email:    "implicit@example.com",
		Username: "implicituser",
		Groups:   []record.Group{},
	}

	mockDB.On("GetCurrentSigningKey", mock.Anything, issueTx).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, issueTx, user).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, issueTx, user.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, issueTx, user).Return(nil)

	input := &ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             "openid profile",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
		SessionIdentifier: sessionIdentifier,
		Nonce:             "test-nonce-123",
		AuthenticatedAt:   authenticatedAt,
	}

	armImplicitTransaction(mockDB, input.SessionIdentifier)

	response, err := tokenIssuer.IssueImplicitTx(ctx, settings, input, true, false)
	assert.NoError(t, err)
	assert.NotNil(t, response)

	// Verify access token is issued
	assert.NotEmpty(t, response.AccessToken)
	// Verify NO id_token is issued
	assert.Empty(t, response.IdToken)
	// Verify token type
	assert.Equal(t, "Bearer", response.TokenType)
	// Verify expiration
	assert.Equal(t, int64(600), response.ExpiresIn)
	// Verify scope
	assert.Contains(t, response.Scope, "openid")

	// Decode and verify access token claims
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, sub, accessClaims["sub"])
	assert.Equal(t, input.AcrLevel.String(), accessClaims["acr"])
	assert.ElementsMatch(t, strings.Fields(input.AuthMethods), accessClaims["amr"])
	assert.Equal(t, sessionIdentifier, accessClaims["sid"])
	assert.Equal(t, "test-nonce-123", accessClaims["nonce"])
	assert.Equal(t, "Bearer", accessClaims["typ"])

	mockDB.AssertExpectations(t)
}

func TestIssueImplicitTx_IdTokenOnly(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &record.Settings{
		Issuer:                              "https://test-issuer.com",
		TokenExpirationInSeconds:            600,
		IncludeOpenIDConnectClaimsInIdToken: true,
	}

	ctx := context.Background()

	sub := fake.UUID()
	sessionIdentifier := "test-session-idtoken"
	authenticatedAt := time.Now().UTC().Add(-5 * time.Minute)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	client := &record.Client{
		Id:               1,
		ClientIdentifier: "idtoken-test-client",
	}
	user := &record.User{
		Id:            1,
		Subject:       sub,
		Email:         "idtoken@example.com",
		EmailVerified: true,
		Username:      "idtokenuser",
		GivenName:     "IdToken",
		FamilyName:    "User",
		UpdatedAt:     sql.NullTime{Time: time.Now().Add(-1 * time.Hour), Valid: true},
		Groups:        []record.Group{},
	}

	mockDB.On("GetCurrentSigningKey", mock.Anything, issueTx).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, issueTx, user).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, issueTx, user.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, issueTx, user).Return(nil)
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, user.Id).Return(false, nil)

	input := &ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             "openid profile email",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
		SessionIdentifier: sessionIdentifier,
		Nonce:             "nonce-for-idtoken",
		AuthenticatedAt:   authenticatedAt,
	}

	armImplicitTransaction(mockDB, input.SessionIdentifier)

	response, err := tokenIssuer.IssueImplicitTx(ctx, settings, input, false, true)
	assert.NoError(t, err)
	assert.NotNil(t, response)

	// Verify NO access token is issued
	assert.Empty(t, response.AccessToken)
	// Verify id_token IS issued
	assert.NotEmpty(t, response.IdToken)
	// Verify scope
	assert.Equal(t, "openid profile email", response.Scope)

	// Decode and verify id_token claims
	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, idClaims["iss"])
	assert.Equal(t, sub, idClaims["sub"])
	assert.Equal(t, client.ClientIdentifier, idClaims["aud"])
	assert.Equal(t, input.AcrLevel.String(), idClaims["acr"])
	assert.ElementsMatch(t, strings.Fields(input.AuthMethods), idClaims["amr"])
	assert.Equal(t, sessionIdentifier, idClaims["sid"])
	assert.Equal(t, "nonce-for-idtoken", idClaims["nonce"])

	// Verify NO at_hash (since no access token was issued)
	assert.Nil(t, idClaims["at_hash"])

	// Verify OIDC claims
	assert.Equal(t, "idtoken@example.com", idClaims["email"])
	assert.Equal(t, true, idClaims["email_verified"])
	assert.Equal(t, "IdToken User", idClaims["name"])
	assert.Equal(t, "IdToken", idClaims["given_name"])
	assert.Equal(t, "User", idClaims["family_name"])

	mockDB.AssertExpectations(t)
}

func TestIssueImplicitTx_BothTokens(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &record.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		IncludeOpenIDConnectClaimsInAccessToken: true,
	}

	ctx := context.Background()

	sub := fake.UUID()
	sessionIdentifier := "test-session-both"
	authenticatedAt := time.Now().UTC().Add(-5 * time.Minute)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	client := &record.Client{
		Id:               1,
		ClientIdentifier: "both-tokens-client",
	}
	user := &record.User{
		Id:            1,
		Subject:       sub,
		Email:         "both@example.com",
		EmailVerified: true,
		Username:      "bothuser",
		GivenName:     "Both",
		FamilyName:    "Tokens",
		UpdatedAt:     sql.NullTime{Time: time.Now().Add(-1 * time.Hour), Valid: true},
		Groups:        []record.Group{},
	}

	mockDB.On("GetCurrentSigningKey", mock.Anything, issueTx).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, issueTx, user).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, issueTx, user.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, issueTx, user).Return(nil)
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, user.Id).Return(false, nil)

	input := &ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             "openid profile email",
		AcrLevel:          "urn:goiabada:pwd:otp_mandatory",
		AuthMethods:       "pwd otp",
		SessionIdentifier: sessionIdentifier,
		Nonce:             "nonce-for-both",
		AuthenticatedAt:   authenticatedAt,
	}

	armImplicitTransaction(mockDB, input.SessionIdentifier)

	response, err := tokenIssuer.IssueImplicitTx(ctx, settings, input, true, true)
	assert.NoError(t, err)
	assert.NotNil(t, response)

	// Verify BOTH tokens are issued
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(600), response.ExpiresIn)

	// Decode and verify access token
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, sub, accessClaims["sub"])

	// Decode and verify id_token
	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, idClaims["iss"])
	assert.Equal(t, sub, idClaims["sub"])
	assert.Equal(t, "nonce-for-both", idClaims["nonce"])

	// Verify at_hash IS present (since access token was also issued)
	assert.NotNil(t, idClaims["at_hash"])
	atHash := idClaims["at_hash"].(string)
	assert.NotEmpty(t, atHash)

	// Verify at_hash is correct
	expectedAtHash := tokenIssuer.calculateAtHash(response.AccessToken)
	assert.Equal(t, expectedAtHash, atHash)

	mockDB.AssertExpectations(t)
}

func TestIssueImplicitTx_NoRefreshToken(t *testing.T) {
	// This test verifies that implicit flow NEVER issues a refresh token
	// per RFC 6749 Section 4.2.2
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &record.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600,
	}

	ctx := context.Background()

	sub := fake.UUID()
	privateKeyBytes := getTestPrivateKey(t)

	client := &record.Client{
		Id:               1,
		ClientIdentifier: "no-refresh-client",
	}
	user := &record.User{
		Id:      1,
		Subject: sub,
		Groups:  []record.Group{},
	}

	mockDB.On("GetCurrentSigningKey", mock.Anything, issueTx).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, issueTx, user).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, issueTx, user.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, issueTx, user).Return(nil)

	// Request with offline_access scope - should NOT result in refresh token for implicit flow
	input := &ImplicitGrantInput{
		Client:      client,
		User:        user,
		Scope:       "openid offline_access",
		AcrLevel:    "urn:goiabada:pwd",
		AuthMethods: "pwd",

		Nonce:           "nonce-123",
		AuthenticatedAt: time.Now().UTC(),
	}

	armImplicitTransaction(mockDB, input.SessionIdentifier)

	response, err := tokenIssuer.IssueImplicitTx(ctx, settings, input, true, false)
	assert.NoError(t, err)
	assert.NotNil(t, response)

	// ImplicitGrantResponse struct does NOT have a RefreshToken field
	// This test documents that implicit flow cannot return refresh tokens by design
	assert.NotEmpty(t, response.AccessToken)
	// The response type itself prevents refresh tokens

	mockDB.AssertExpectations(t)
}

func TestIssueImplicitTx_ClientOverrideExpiration(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &record.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600, // 10 minutes global
	}

	ctx := context.Background()

	sub := fake.UUID()
	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	client := &record.Client{
		Id:                       1,
		ClientIdentifier:         "custom-expiry-client",
		TokenExpirationInSeconds: 1800, // 30 minutes client override
	}
	user := &record.User{
		Id:      1,
		Subject: sub,
		Groups:  []record.Group{},
	}

	mockDB.On("GetCurrentSigningKey", mock.Anything, issueTx).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, issueTx, user).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, issueTx, user.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, issueTx, user).Return(nil)

	input := &ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             "openid",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
		SessionIdentifier: "session-123",
		Nonce:             "nonce-123",
		AuthenticatedAt:   time.Now().UTC(),
	}

	armImplicitTransaction(mockDB, input.SessionIdentifier)

	response, err := tokenIssuer.IssueImplicitTx(ctx, settings, input, true, false)
	assert.NoError(t, err)
	assert.NotNil(t, response)

	// Verify client override is used
	assert.Equal(t, int64(1800), response.ExpiresIn)

	// Verify token expiration claim
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	exp := accessClaims["exp"].(float64)
	iat := accessClaims["iat"].(float64)
	assert.Equal(t, float64(1800), exp-iat)

	mockDB.AssertExpectations(t)
}

func TestIssueImplicitTx_WithGroupsAndAttributes(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &record.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600,
	}

	ctx := context.Background()

	sub := fake.UUID()
	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	client := &record.Client{
		Id:               1,
		ClientIdentifier: "groups-attrs-client",
	}
	user := &record.User{
		Id:        1,
		Subject:   sub,
		UpdatedAt: sql.NullTime{Time: time.Now().Add(-1 * time.Hour), Valid: true},
		Groups: []record.Group{
			{GroupIdentifier: "admin", IncludeInIdToken: true, IncludeInAccessToken: true},
			{GroupIdentifier: "users", IncludeInIdToken: true, IncludeInAccessToken: false},
			{GroupIdentifier: "readonly", IncludeInIdToken: false, IncludeInAccessToken: true},
		},
		Attributes: []record.UserAttribute{
			{Key: "department", Value: "engineering", IncludeInIdToken: true, IncludeInAccessToken: true},
			{Key: "level", Value: "senior", IncludeInIdToken: true, IncludeInAccessToken: false},
			{Key: "team", Value: "platform", IncludeInIdToken: false, IncludeInAccessToken: true},
		},
	}

	mockDB.On("GetCurrentSigningKey", mock.Anything, issueTx).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, issueTx, user).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, issueTx, user.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, issueTx, user).Return(nil)
	// Note: UserHasProfilePicture not called because we don't have "profile" scope

	input := &ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             "openid groups attributes",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
		SessionIdentifier: "session-123",
		Nonce:             "nonce-123",
		AuthenticatedAt:   time.Now().UTC(),
	}

	armImplicitTransaction(mockDB, input.SessionIdentifier)

	response, err := tokenIssuer.IssueImplicitTx(ctx, settings, input, true, true)
	assert.NoError(t, err)
	assert.NotNil(t, response)

	// Verify access token groups and attributes
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)

	accessGroups := accessClaims["groups"].([]interface{})
	assert.Len(t, accessGroups, 2) // admin and readonly
	assert.Contains(t, accessGroups, "admin")
	assert.Contains(t, accessGroups, "readonly")
	assert.NotContains(t, accessGroups, "users")

	accessAttrs := accessClaims["attributes"].(map[string]interface{})
	assert.Equal(t, "engineering", accessAttrs["department"])
	assert.Equal(t, "platform", accessAttrs["team"])
	assert.Nil(t, accessAttrs["level"])

	// Verify id_token groups and attributes
	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)

	idGroups := idClaims["groups"].([]interface{})
	assert.Len(t, idGroups, 2) // admin and users
	assert.Contains(t, idGroups, "admin")
	assert.Contains(t, idGroups, "users")
	assert.NotContains(t, idGroups, "readonly")

	idAttrs := idClaims["attributes"].(map[string]interface{})
	assert.Equal(t, "engineering", idAttrs["department"])
	assert.Equal(t, "senior", idAttrs["level"])
	assert.Nil(t, idAttrs["team"])

	mockDB.AssertExpectations(t)
}
