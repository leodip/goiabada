package issuance

import (
	"context"
	"fmt"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestIssuePasswordGrant_BasicOpenIDScope tests ROPC with basic openid scope
func TestIssuePasswordGrant_BasicOpenIDScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInIdToken:     true,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.Background()

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	sub := fake.UUID()
	client := &models.Client{
		Id:                                      1,
		ClientIdentifier:                        "test-client",
		TokenExpirationInSeconds:                900,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 7200,
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "user@example.com",
		EmailVerified: true,
		Username:      "testuser",
		Enabled:       true,
	}

	keyPair := &models.KeyPair{
		Id:            1,
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
		PublicKeyPEM:  publicKeyBytes,
	}

	// Set up mock expectations - ROPC doesn't use CreateCode or GetUserSessionBySessionIdentifier
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Groups = []models.Group{}
	})
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Attributes = []models.UserAttribute{}
	})
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	input := &ROPCGrantInput{
		Client: client,
		User:   user,
		Scope:  "openid",
	}

	response, err := tokenIssuer.IssuePasswordGrant(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(900), response.ExpiresIn) // Client override

	// Verify access token claims
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, "https://test-issuer.com", accessClaims["iss"])
	assert.Equal(t, sub, accessClaims["sub"])
	// Level 1, the advertised meaning of password-only, not the unadvertised urn:goiabada:pwd (#433).
	assert.Equal(t, "urn:goiabada:level1", accessClaims["acr"])
	assert.ElementsMatch(t, []string{"pwd"}, accessClaims["amr"])
	// ROPC is sessionless, on BOTH tokens. This replaced an assert.Nil on the same claim:
	// equivalent in what it catches, since a leaked identifier is a non-nil string, but it
	// distinguishes "absent" from "present and nil" and reads as the intent rather than as a
	// value check (#106).
	assert.NotContains(t, accessClaims, "sid")

	// Verify id_token claims
	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, "https://test-issuer.com", idClaims["iss"])
	assert.Equal(t, sub, idClaims["sub"])
	assert.Equal(t, "urn:goiabada:level1", idClaims["acr"])
	assert.ElementsMatch(t, []string{"pwd"}, idClaims["amr"])
	// The ID token is where the browser session used to leak, so this is the assertion that
	// matters most on this path. Also replaced an equivalent assert.Nil.
	assert.NotContains(t, idClaims, "sid", "a ROPC ID token must never carry a session identifier")
	// Note: at_hash is not included in ROPC id_token generation as it's not required by the spec for this flow

	mockDB.AssertExpectations(t)
}

// TestIssuePasswordGrant_WithOfflineAccess tests ROPC with offline_access scope
func TestIssuePasswordGrant_WithOfflineAccess(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		RefreshTokenOfflineIdleTimeoutInSeconds: 86400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 604800,
	}

	ctx := context.Background()

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	sub := fake.UUID()
	client := &models.Client{
		Id:                                      1,
		ClientIdentifier:                        "test-client",
		RefreshTokenOfflineIdleTimeoutInSeconds: 172800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 1209600,
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "user@example.com",
		EmailVerified: true,
		Username:      "testuser",
		Enabled:       true,
	}

	keyPair := &models.KeyPair{
		Id:            1,
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
		PublicKeyPEM:  publicKeyBytes,
	}

	// Set up mock expectations - ROPC doesn't use CreateCode
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Groups = []models.Group{}
	})
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Attributes = []models.UserAttribute{}
	})
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	input := &ROPCGrantInput{
		Client: client,
		User:   user,
		Scope:  "openid offline_access",
	}

	response, err := tokenIssuer.IssuePasswordGrant(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Contains(t, response.Scope, "offline_access")
	assert.True(t, response.RefreshExpiresIn > 0)

	// Verify access token doesn't have sid for ROPC tokens
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Nil(t, accessClaims["sid"])

	mockDB.AssertExpectations(t)
}

// TestIssuePasswordGrant_WithProfileScope tests ROPC with profile scope claims
func TestIssuePasswordGrant_WithProfileScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInIdToken:     true,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.Background()

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	sub := fake.UUID()
	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}
	user := &models.User{
		Id:         1,
		Subject:    sub,
		Email:      "user@example.com",
		Username:   "testuser",
		GivenName:  "John",
		FamilyName: "Doe",
		Nickname:   "johnd",
		Enabled:    true,
	}

	keyPair := &models.KeyPair{
		Id:            1,
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
		PublicKeyPEM:  publicKeyBytes,
	}

	// Set up mock expectations - ROPC doesn't use CreateCode or GetUserSessionBySessionIdentifier
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Groups = []models.Group{}
	})
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Attributes = []models.UserAttribute{}
	})
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, user.Id).Return(false, nil)
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	input := &ROPCGrantInput{
		Client: client,
		User:   user,
		Scope:  "openid profile",
	}

	response, err := tokenIssuer.IssuePasswordGrant(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.IdToken)

	// Verify id_token contains profile claims
	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, "John", idClaims["given_name"])
	assert.Equal(t, "Doe", idClaims["family_name"])
	assert.Equal(t, "johnd", idClaims["nickname"])
	assert.Equal(t, "testuser", idClaims["preferred_username"])

	mockDB.AssertExpectations(t)
}

// TestIssuePasswordGrant_WithEmailScope tests ROPC with email scope claims
func TestIssuePasswordGrant_WithEmailScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInIdToken:     true,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.Background()

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	sub := fake.UUID()
	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "user@example.com",
		EmailVerified: true,
		Username:      "testuser",
		Enabled:       true,
	}

	keyPair := &models.KeyPair{
		Id:            1,
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
		PublicKeyPEM:  publicKeyBytes,
	}

	// Set up mock expectations - ROPC doesn't use CreateCode or GetUserSessionBySessionIdentifier
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Groups = []models.Group{}
	})
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Attributes = []models.UserAttribute{}
	})
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	input := &ROPCGrantInput{
		Client: client,
		User:   user,
		Scope:  "openid email",
	}

	response, err := tokenIssuer.IssuePasswordGrant(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.IdToken)

	// Verify id_token contains email claims
	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, "user@example.com", idClaims["email"])
	assert.Equal(t, true, idClaims["email_verified"])

	mockDB.AssertExpectations(t)
}

// TestIssuePasswordGrant_WithResourcePermissions tests ROPC with resource:permission scopes
func TestIssuePasswordGrant_WithResourcePermissions(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.Background()

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	sub := fake.UUID()
	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "user@example.com",
		EmailVerified: true,
		Username:      "testuser",
		Enabled:       true,
	}

	keyPair := &models.KeyPair{
		Id:            1,
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
		PublicKeyPEM:  publicKeyBytes,
	}

	// Set up mock expectations - ROPC doesn't use CreateCode or GetUserSessionBySessionIdentifier
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Groups = []models.Group{}
	})
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Attributes = []models.UserAttribute{}
	})
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	input := &ROPCGrantInput{
		Client: client,
		User:   user,
		Scope:  "openid myapi:read myapi:write",
	}

	response, err := tokenIssuer.IssuePasswordGrant(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.Contains(t, response.Scope, "myapi:read")
	assert.Contains(t, response.Scope, "myapi:write")

	// Verify access token has resource in audience
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	aud := accessClaims["aud"]
	audList, ok := aud.([]interface{})
	if ok {
		audStrings := make([]string, len(audList))
		for i, v := range audList {
			audStrings[i] = v.(string)
		}
		assert.Contains(t, audStrings, "myapi")
	}

	mockDB.AssertExpectations(t)
}

// TestIssuePasswordGrant_WithGroups tests ROPC with groups scope
func TestIssuePasswordGrant_WithGroups(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.Background()

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	sub := fake.UUID()
	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "user@example.com",
		EmailVerified: true,
		Username:      "testuser",
		Enabled:       true,
	}

	keyPair := &models.KeyPair{
		Id:            1,
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
		PublicKeyPEM:  publicKeyBytes,
	}

	// Set up mock expectations with groups - ROPC doesn't use CreateCode or GetUserSessionBySessionIdentifier
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Groups = []models.Group{
			{Id: 1, GroupIdentifier: "admins", IncludeInAccessToken: true, IncludeInIdToken: true},
			{Id: 2, GroupIdentifier: "users", IncludeInAccessToken: true, IncludeInIdToken: false},
		}
	})
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Attributes = []models.UserAttribute{}
	})
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	input := &ROPCGrantInput{
		Client: client,
		User:   user,
		Scope:  "openid groups",
	}

	response, err := tokenIssuer.IssuePasswordGrant(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.IdToken)

	// Verify id_token contains groups
	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	groups := idClaims["groups"].([]interface{})
	assert.Contains(t, groups, "admins")
	// "users" has IncludeInIdToken=false so should not be in id_token

	// Verify access token contains groups
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	accessGroups := accessClaims["groups"].([]interface{})
	assert.Contains(t, accessGroups, "admins")
	assert.Contains(t, accessGroups, "users")

	mockDB.AssertExpectations(t)
}

// TestIssuePasswordGrant_WithoutOpenID tests ROPC without openid scope (no id_token)
func TestIssuePasswordGrant_WithoutOpenID(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.Background()

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	sub := fake.UUID()
	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "user@example.com",
		EmailVerified: true,
		Username:      "testuser",
		Enabled:       true,
	}

	keyPair := &models.KeyPair{
		Id:            1,
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
		PublicKeyPEM:  publicKeyBytes,
	}

	// Set up mock expectations - ROPC doesn't use CreateCode or GetUserSessionBySessionIdentifier
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Groups = []models.Group{}
	})
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Attributes = []models.UserAttribute{}
	})
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	input := &ROPCGrantInput{
		Client: client,
		User:   user,
		Scope:  "myapi:read",
	}

	response, err := tokenIssuer.IssuePasswordGrant(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.Empty(t, response.IdToken) // No openid scope = no id_token
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "Bearer", response.TokenType)

	mockDB.AssertExpectations(t)
}

// TestIssuePasswordGrant_DatabaseError_GetSigningKey tests error handling for signing key errors
func TestIssuePasswordGrant_DatabaseError_GetSigningKey(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600,
	}

	ctx := context.Background()

	sub := fake.UUID()
	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}
	user := &models.User{
		Id:       1,
		Subject:  sub,
		Email:    "user@example.com",
		Username: "testuser",
		Enabled:  true,
	}

	// Set up mock to return error
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("database connection error"))

	input := &ROPCGrantInput{
		Client: client,
		User:   user,
		Scope:  "openid",
	}

	response, err := tokenIssuer.IssuePasswordGrant(ctx, settings, input)

	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Contains(t, err.Error(), "database connection error")

	mockDB.AssertExpectations(t)
}

// TestIssuePasswordGrant_DatabaseError_CreateRefreshToken tests error handling for refresh token creation errors
func TestIssuePasswordGrant_DatabaseError_CreateRefreshToken(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.Background()

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	sub := fake.UUID()
	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}
	user := &models.User{
		Id:       1,
		Subject:  sub,
		Email:    "user@example.com",
		Username: "testuser",
		Enabled:  true,
	}

	keyPair := &models.KeyPair{
		Id:            1,
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
		PublicKeyPEM:  publicKeyBytes,
	}

	// Set up mock expectations with CreateRefreshToken error
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Groups = []models.Group{}
	})
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Attributes = []models.UserAttribute{}
	})
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(fmt.Errorf("refresh token creation failed"))

	input := &ROPCGrantInput{
		Client: client,
		User:   user,
		Scope:  "openid",
	}

	response, err := tokenIssuer.IssuePasswordGrant(ctx, settings, input)

	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Contains(t, err.Error(), "refresh token creation failed")

	mockDB.AssertExpectations(t)
}

// TestIssuePasswordGrant_ClientTokenExpiration tests client-specific token expiration override
func TestIssuePasswordGrant_ClientTokenExpiration(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600, // Global setting
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.Background()

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	sub := fake.UUID()
	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "test-client",
		TokenExpirationInSeconds: 1800, // Client-specific override
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "user@example.com",
		EmailVerified: true,
		Username:      "testuser",
		Enabled:       true,
	}

	keyPair := &models.KeyPair{
		Id:            1,
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
		PublicKeyPEM:  publicKeyBytes,
	}

	// Set up mock expectations - ROPC doesn't use CreateCode or GetUserSessionBySessionIdentifier
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Groups = []models.Group{}
	})
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Attributes = []models.UserAttribute{}
	})
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	input := &ROPCGrantInput{
		Client: client,
		User:   user,
		Scope:  "openid",
	}

	response, err := tokenIssuer.IssuePasswordGrant(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, int64(1800), response.ExpiresIn) // Client override should be used

	mockDB.AssertExpectations(t)
}

// TestIssuePasswordGrant_GlobalTokenExpiration tests global token expiration (no client override)
func TestIssuePasswordGrant_GlobalTokenExpiration(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600, // Global setting
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.Background()

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	sub := fake.UUID()
	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "test-client",
		TokenExpirationInSeconds: 0, // No client override
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "user@example.com",
		EmailVerified: true,
		Username:      "testuser",
		Enabled:       true,
	}

	keyPair := &models.KeyPair{
		Id:            1,
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
		PublicKeyPEM:  publicKeyBytes,
	}

	// Set up mock expectations - ROPC doesn't use CreateCode or GetUserSessionBySessionIdentifier
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Groups = []models.Group{}
	})
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, user).Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(2).(*models.User)
		u.Attributes = []models.UserAttribute{}
	})
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	input := &ROPCGrantInput{
		Client: client,
		User:   user,
		Scope:  "openid",
	}

	response, err := tokenIssuer.IssuePasswordGrant(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, int64(600), response.ExpiresIn) // Global setting should be used

	mockDB.AssertExpectations(t)
}
