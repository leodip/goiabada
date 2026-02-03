package oauth

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// ============================================================================
// Tests for IncludeOpenIDConnectClaimsInIdToken Setting
// ============================================================================

func TestGenerateIdToken_IncludeOpenIDConnectClaimsInIdToken_GlobalEnabled(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                              "https://test-issuer.com",
		TokenExpirationInSeconds:            600,
		IncludeOpenIDConnectClaimsInIdToken: true, // Global setting enabled
	}

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	input := &TokenGenerationInput{
		User: &models.User{
			Subject:             sub,
			Email:               "test@example.com",
			EmailVerified:       true,
			Username:            "testuser",
			GivenName:           "Test",
			MiddleName:          "Middle",
			FamilyName:          "User",
			Nickname:            "Testy",
			Website:             "https://test.com",
			Gender:              "male",
			BirthDate:           sql.NullTime{Time: time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true},
			ZoneInfo:            "Europe/London",
			Locale:              "en-GB",
			PhoneNumber:         "+1234567890",
			PhoneNumberVerified: true,
			AddressLine1:        "123 Test St",
			AddressLine2:        "Apt 1",
			AddressLocality:     "Test City",
			AddressRegion:       "Test Region",
			AddressPostalCode:   "12345",
			AddressCountry:      "Test Country",
			UpdatedAt:           sql.NullTime{Time: now.Add(-1 * time.Minute), Valid: true},
		},
		Client: &models.Client{
			ClientIdentifier: "test-client",
			// IncludeOpenIDConnectClaimsInIdToken is "default", so uses global setting
			IncludeOpenIDConnectClaimsInIdToken: enums.ThreeStateSettingDefault.String(),
		},
		Scope:             "openid profile email address phone",
		Nonce:             "test-nonce",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       []string{"pwd"},
		SessionIdentifier: sessionIdentifier,
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		AccessToken:       "",
	}

	mockDB.On("UserHasProfilePicture", mock.AnythingOfType("*sql.Tx"), mock.AnythingOfType("int64")).Return(false, nil)

	idToken, err := tokenIssuer.generateIdTokenCore(settings, input, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	// Verify OIDC claims ARE included
	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	// Standard claims
	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, sub.String(), claims["sub"])
	assert.Equal(t, input.Client.ClientIdentifier, claims["aud"])
	assert.Equal(t, input.Nonce, claims["nonce"])

	// OIDC profile scope claims
	assert.Equal(t, input.User.GetFullName(), claims["name"])
	assert.Equal(t, input.User.GivenName, claims["given_name"])
	assert.Equal(t, input.User.MiddleName, claims["middle_name"])
	assert.Equal(t, input.User.FamilyName, claims["family_name"])
	assert.Equal(t, input.User.Nickname, claims["nickname"])
	assert.Equal(t, input.User.Username, claims["preferred_username"])
	assert.Equal(t, "http://localhost:8081/account/profile", claims["profile"])
	assert.Equal(t, input.User.Website, claims["website"])
	assert.Equal(t, input.User.Gender, claims["gender"])
	assert.Equal(t, "1990-01-01", claims["birthdate"])
	assert.Equal(t, input.User.ZoneInfo, claims["zoneinfo"])
	assert.Equal(t, input.User.Locale, claims["locale"])

	// OIDC email scope claims
	assert.Equal(t, input.User.Email, claims["email"])
	assert.Equal(t, input.User.EmailVerified, claims["email_verified"])

	// OIDC phone scope claims
	assert.Equal(t, input.User.PhoneNumber, claims["phone_number"])
	assert.Equal(t, input.User.PhoneNumberVerified, claims["phone_number_verified"])

	// OIDC address scope claims
	address, ok := claims["address"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, input.User.AddressLine1+"\r\n"+input.User.AddressLine2, address["street_address"])
	assert.Equal(t, input.User.AddressLocality, address["locality"])
	assert.Equal(t, input.User.AddressRegion, address["region"])
	assert.Equal(t, input.User.AddressPostalCode, address["postal_code"])
	assert.Equal(t, input.User.AddressCountry, address["country"])
}

func TestGenerateIdToken_IncludeOpenIDConnectClaimsInIdToken_GlobalDisabled(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                              "https://test-issuer.com",
		TokenExpirationInSeconds:            600,
		IncludeOpenIDConnectClaimsInIdToken: false, // Global setting disabled
	}

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-456"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	input := &TokenGenerationInput{
		User: &models.User{
			Subject:             sub,
			Email:               "test@example.com",
			EmailVerified:       true,
			Username:            "testuser",
			GivenName:           "Test",
			FamilyName:          "User",
			PhoneNumber:         "+1234567890",
			PhoneNumberVerified: true,
			AddressLine1:        "123 Test St",
			UpdatedAt:           sql.NullTime{Time: now.Add(-1 * time.Minute), Valid: true},
		},
		Client: &models.Client{
			ClientIdentifier: "test-client",
			// IncludeOpenIDConnectClaimsInIdToken is "default", so uses global setting
			IncludeOpenIDConnectClaimsInIdToken: enums.ThreeStateSettingDefault.String(),
		},
		Scope:             "openid profile email address phone",
		Nonce:             "test-nonce",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       []string{"pwd"},
		SessionIdentifier: sessionIdentifier,
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		AccessToken:       "",
	}

	// NOTE: No UserHasProfilePicture mock needed when setting is disabled
	// because the code doesn't check for pictures when OIDC claims aren't included

	idToken, err := tokenIssuer.generateIdTokenCore(settings, input, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	// Verify OIDC claims ARE NOT included
	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	// Standard claims should still be present
	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, sub.String(), claims["sub"])
	assert.Equal(t, input.Client.ClientIdentifier, claims["aud"])
	assert.Equal(t, input.Nonce, claims["nonce"])

	// OIDC scope claims should NOT be present
	assert.NotContains(t, claims, "name")
	assert.NotContains(t, claims, "given_name")
	assert.NotContains(t, claims, "family_name")
	assert.NotContains(t, claims, "nickname")
	assert.NotContains(t, claims, "preferred_username")
	assert.NotContains(t, claims, "profile")
	assert.NotContains(t, claims, "website")
	assert.NotContains(t, claims, "gender")
	assert.NotContains(t, claims, "birthdate")
	assert.NotContains(t, claims, "zoneinfo")
	assert.NotContains(t, claims, "locale")
	assert.NotContains(t, claims, "middle_name")
	assert.NotContains(t, claims, "email")
	assert.NotContains(t, claims, "email_verified")
	assert.NotContains(t, claims, "phone_number")
	assert.NotContains(t, claims, "phone_number_verified")
	assert.NotContains(t, claims, "address")
	assert.NotContains(t, claims, "updated_at")
	assert.NotContains(t, claims, "picture")
}

func TestGenerateIdToken_IncludeOpenIDConnectClaimsInIdToken_ClientOverrideOn(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                              "https://test-issuer.com",
		TokenExpirationInSeconds:            600,
		IncludeOpenIDConnectClaimsInIdToken: false, // Global setting disabled
	}

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-789"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	input := &TokenGenerationInput{
		User: &models.User{
			Subject:       sub,
			Email:         "test@example.com",
			EmailVerified: true,
			GivenName:     "Test",
			FamilyName:    "User",
			UpdatedAt:     sql.NullTime{Time: now.Add(-1 * time.Minute), Valid: true},
		},
		Client: &models.Client{
			ClientIdentifier: "test-client",
			// Client override: ON (should include claims despite global disabled)
			IncludeOpenIDConnectClaimsInIdToken: enums.ThreeStateSettingOn.String(),
		},
		Scope:             "openid profile email",
		Nonce:             "test-nonce",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       []string{"pwd"},
		SessionIdentifier: sessionIdentifier,
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		AccessToken:       "",
	}

	mockDB.On("UserHasProfilePicture", mock.AnythingOfType("*sql.Tx"), mock.AnythingOfType("int64")).Return(false, nil)

	idToken, err := tokenIssuer.generateIdTokenCore(settings, input, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	// Verify OIDC claims ARE included (client override wins)
	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, sub.String(), claims["sub"])

	// OIDC profile scope claims should be present
	assert.Equal(t, input.User.GivenName, claims["given_name"])
	assert.Equal(t, input.User.FamilyName, claims["family_name"])
	assert.Equal(t, input.User.GetFullName(), claims["name"])

	// OIDC email scope claims should be present
	assert.Equal(t, input.User.Email, claims["email"])
	assert.Equal(t, input.User.EmailVerified, claims["email_verified"])
}

func TestGenerateIdToken_IncludeOpenIDConnectClaimsInIdToken_ClientOverrideOff(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                              "https://test-issuer.com",
		TokenExpirationInSeconds:            600,
		IncludeOpenIDConnectClaimsInIdToken: true, // Global setting enabled
	}

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-321"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	input := &TokenGenerationInput{
		User: &models.User{
			Subject:       sub,
			Email:         "test@example.com",
			EmailVerified: true,
			GivenName:     "Test",
			FamilyName:    "User",
			UpdatedAt:     sql.NullTime{Time: now.Add(-1 * time.Minute), Valid: true},
		},
		Client: &models.Client{
			ClientIdentifier: "test-client",
			// Client override: OFF (should NOT include claims despite global enabled)
			IncludeOpenIDConnectClaimsInIdToken: enums.ThreeStateSettingOff.String(),
		},
		Scope:             "openid profile email",
		Nonce:             "test-nonce",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       []string{"pwd"},
		SessionIdentifier: sessionIdentifier,
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		AccessToken:       "",
	}

	// NOTE: No UserHasProfilePicture mock needed - email scope doesn't check for pictures

	idToken, err := tokenIssuer.generateIdTokenCore(settings, input, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	// Verify OIDC claims ARE NOT included (client override wins)
	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, sub.String(), claims["sub"])

	// OIDC scope claims should NOT be present
	assert.NotContains(t, claims, "given_name")
	assert.NotContains(t, claims, "family_name")
	assert.NotContains(t, claims, "name")
	assert.NotContains(t, claims, "email")
	assert.NotContains(t, claims, "email_verified")
}

func TestGenerateIdToken_IncludeOpenIDConnectClaimsInIdToken_GroupsAndAttributesAlwaysIncluded(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                              "https://test-issuer.com",
		TokenExpirationInSeconds:            600,
		IncludeOpenIDConnectClaimsInIdToken: false, // Disabled - but groups/attributes should still work
	}

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-groups"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	input := &TokenGenerationInput{
		User: &models.User{
			Subject:   sub,
			UpdatedAt: sql.NullTime{Time: now.Add(-1 * time.Minute), Valid: true},
			Groups: []models.Group{
				{GroupIdentifier: "group1", IncludeInIdToken: true},
				{GroupIdentifier: "group2", IncludeInIdToken: true},
				{GroupIdentifier: "group3", IncludeInIdToken: false},
			},
			Attributes: []models.UserAttribute{
				{Key: "attr1", Value: "value1", IncludeInIdToken: true},
				{Key: "attr2", Value: "value2", IncludeInIdToken: true},
				{Key: "attr3", Value: "value3", IncludeInIdToken: false},
			},
		},
		Client: &models.Client{
			ClientIdentifier:                    "test-client",
			IncludeOpenIDConnectClaimsInIdToken: enums.ThreeStateSettingDefault.String(),
		},
		Scope:             "openid profile email groups attributes",
		Nonce:             "test-nonce",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       []string{"pwd"},
		SessionIdentifier: sessionIdentifier,
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		AccessToken:       "",
	}

	// NOTE: No UserHasProfilePicture mock needed when setting is disabled

	idToken, err := tokenIssuer.generateIdTokenCore(settings, input, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	// OIDC scope claims should NOT be present (setting disabled)
	assert.NotContains(t, claims, "name")
	assert.NotContains(t, claims, "email")

	// But groups and attributes should ALWAYS be included (custom Goiabada scopes)
	groups, ok := claims["groups"].([]interface{})
	assert.True(t, ok, "groups claim should be present")
	assert.ElementsMatch(t, []string{"group1", "group2"}, groups)

	attributes, ok := claims["attributes"].(map[string]interface{})
	assert.True(t, ok, "attributes claim should be present")
	assert.Equal(t, "value1", attributes["attr1"])
	assert.Equal(t, "value2", attributes["attr2"])
	assert.NotContains(t, attributes, "attr3")
}

func TestGenerateTokenResponseForAuthCode_IncludeOpenIDConnectClaimsInIdToken_FullFlow(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		IncludeOpenIDConnectClaimsInIdToken:     false, // ID token claims disabled
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-full-flow"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &models.Code{
		Id:                1,
		ClientId:          1,
		UserId:            1,
		Scope:             "openid profile email",
		Nonce:             "test-nonce",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:                                      1,
		ClientIdentifier:                        "test-client",
		TokenExpirationInSeconds:                900,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 7200,
		// Client uses default (which is global disabled)
		IncludeOpenIDConnectClaimsInIdToken: enums.ThreeStateSettingDefault.String(),
	}
	user := &models.User{
		Id:            1,
		UpdatedAt:     sql.NullTime{Time: now.Add(-1 * time.Minute), Valid: true},
		Subject:       sub,
		Email:         "test@example.com",
		EmailVerified: true,
		Username:      "testuser",
		GivenName:     "Test",
		FamilyName:    "User",
	}

	mockDB.On("CodeLoadClient", mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, &code.User).Return(nil)
	mockDB.On("UserHasProfilePicture", mock.Anything, user.Id).Return(false, nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(&models.UserSession{
		Id:           1,
		UserId:       1,
		Started:      now.Add(-30 * time.Minute),
		LastAccessed: now.Add(-5 * time.Minute),
	}, nil)
	mockDB.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)

	response, err := tokenIssuer.GenerateTokenResponseForAuthCode(ctx, code)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)

	// Verify ID token does NOT have OIDC claims
	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, idClaims["iss"])
	assert.Equal(t, user.Subject.String(), idClaims["sub"])
	assert.Equal(t, client.ClientIdentifier, idClaims["aud"])
	assert.Equal(t, code.Nonce, idClaims["nonce"])
	assert.Equal(t, code.AcrLevel, idClaims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), idClaims["amr"])

	// OIDC scope claims should NOT be in ID token
	assert.NotContains(t, idClaims, "email")
	assert.NotContains(t, idClaims, "email_verified")
	assert.NotContains(t, idClaims, "given_name")
	assert.NotContains(t, idClaims, "family_name")
	assert.NotContains(t, idClaims, "name")

	// But access token SHOULD have them (IncludeOpenIDConnectClaimsInAccessToken is true)
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, user.Email, accessClaims["email"])
	assert.Equal(t, user.EmailVerified, accessClaims["email_verified"])
	assert.Equal(t, user.GivenName, accessClaims["given_name"])
	assert.Equal(t, user.FamilyName, accessClaims["family_name"])

	mockDB.AssertExpectations(t)
}

func TestGenerateTokenResponseForAuthCode_IncludeOpenIDConnectClaimsInIdToken_ClientOverrideFullFlow(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		IncludeOpenIDConnectClaimsInIdToken:     false, // Global disabled
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	now := time.Now().UTC()
	sub := uuid.New()
	sessionIdentifier := "test-session-override-flow"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &models.Code{
		Id:                2,
		ClientId:          2,
		UserId:            2,
		Scope:             "openid profile email",
		Nonce:             "test-nonce-override",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:                       2,
		ClientIdentifier:         "test-client-override",
		TokenExpirationInSeconds: 900,
		// Client override: ON
		IncludeOpenIDConnectClaimsInIdToken: enums.ThreeStateSettingOn.String(),
	}
	user := &models.User{
		Id:            2,
		UpdatedAt:     sql.NullTime{Time: now.Add(-1 * time.Minute), Valid: true},
		Subject:       sub,
		Email:         "override@example.com",
		EmailVerified: true,
		Username:      "overrideuser",
		GivenName:     "Override",
		FamilyName:    "User",
	}

	mockDB.On("CodeLoadClient", mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, &code.User).Return(nil)
	mockDB.On("UserHasProfilePicture", mock.Anything, user.Id).Return(false, nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(&models.UserSession{
		Id:           1,
		UserId:       2,
		Started:      now.Add(-30 * time.Minute),
		LastAccessed: now.Add(-5 * time.Minute),
	}, nil)
	mockDB.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: privateKeyBytes,
	}, nil)

	response, err := tokenIssuer.GenerateTokenResponseForAuthCode(ctx, code)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.IdToken)

	// Verify ID token DOES have OIDC claims (client override wins)
	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, user.Email, idClaims["email"])
	assert.Equal(t, user.EmailVerified, idClaims["email_verified"])
	assert.Equal(t, user.GivenName, idClaims["given_name"])
	assert.Equal(t, user.FamilyName, idClaims["family_name"])
	assert.Equal(t, user.GetFullName(), idClaims["name"])

	// Access token should NOT have them (global setting is false, no client override for access token)
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.NotContains(t, accessClaims, "email")
	assert.NotContains(t, accessClaims, "given_name")

	mockDB.AssertExpectations(t)
}

func TestGenerateIdToken_IncludeOpenIDConnectClaimsInIdToken_MinimalScope_NotAffected(t *testing.T) {
	// When scope is just "openid" with no profile/email/etc, setting should have no effect
	// since there are no OIDC claims to include anyway
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                              "https://test-issuer.com",
		TokenExpirationInSeconds:            600,
		IncludeOpenIDConnectClaimsInIdToken: false, // Disabled
	}

	now := time.Now().UTC()
	sub := uuid.New()

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	input := &TokenGenerationInput{
		User: &models.User{
			Subject:   sub,
			Email:     "test@example.com",
			GivenName: "Test",
			UpdatedAt: sql.NullTime{Time: now, Valid: true},
		},
		Client: &models.Client{
			ClientIdentifier:                    "minimal-client",
			IncludeOpenIDConnectClaimsInIdToken: enums.ThreeStateSettingDefault.String(),
		},
		Scope:             "openid", // Minimal scope - no profile/email scopes
		Nonce:             "test-nonce",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       []string{"pwd"},
		SessionIdentifier: "session-123",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
	}

	// NOTE: No UserHasProfilePicture mock needed when setting is disabled

	idToken, err := tokenIssuer.generateIdTokenCore(settings, input, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	// Standard claims present
	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, sub.String(), claims["sub"])

	// No OIDC scope claims (because scope doesn't include them)
	assert.NotContains(t, claims, "email")
	assert.NotContains(t, claims, "given_name")
	assert.NotContains(t, claims, "name")

	// Setting has no effect in this case - result is the same whether true or false
}

func TestGenerateIdToken_IncludeOpenIDConnectClaimsInIdToken_MinimalScope_GlobalEnabled(t *testing.T) {
	// When scope is just "openid" with no profile/email/etc, setting should have no effect
	// even when global setting is enabled
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                              "https://test-issuer.com",
		TokenExpirationInSeconds:            600,
		IncludeOpenIDConnectClaimsInIdToken: true, // Enabled
	}

	now := time.Now().UTC()
	sub := uuid.New()

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	input := &TokenGenerationInput{
		User: &models.User{
			Subject:   sub,
			Email:     "test@example.com",
			GivenName: "Test",
			UpdatedAt: sql.NullTime{Time: now, Valid: true},
		},
		Client: &models.Client{
			ClientIdentifier:                    "minimal-enabled-client",
			IncludeOpenIDConnectClaimsInIdToken: enums.ThreeStateSettingDefault.String(),
		},
		Scope:             "openid", // Minimal scope - no profile/email scopes
		Nonce:             "test-nonce",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       []string{"pwd"},
		SessionIdentifier: "session-456",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
	}

	// NOTE: No UserHasProfilePicture mock needed when scope excludes profile

	idToken, err := tokenIssuer.generateIdTokenCore(settings, input, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	// Standard claims present
	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, sub.String(), claims["sub"])

	// No OIDC scope claims (because scope doesn't include them)
	assert.NotContains(t, claims, "email")
	assert.NotContains(t, claims, "given_name")
	assert.NotContains(t, claims, "name")
}

func TestGenerateIdToken_IncludeOpenIDConnectClaimsInIdToken_PartialScope_EmailOnly(t *testing.T) {
	// Test with only email scope (not profile, address, phone)
	// Should only include email claims, not other OIDC claims
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                              "https://test-issuer.com",
		TokenExpirationInSeconds:            600,
		IncludeOpenIDConnectClaimsInIdToken: true, // Enabled
	}

	now := time.Now().UTC()
	sub := uuid.New()

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	input := &TokenGenerationInput{
		User: &models.User{
			Subject:             sub,
			Email:               "test@example.com",
			EmailVerified:       true,
			GivenName:           "Test",
			FamilyName:          "User",
			PhoneNumber:         "+1234567890",
			PhoneNumberVerified: true,
			AddressLine1:        "123 Test St",
			UpdatedAt:           sql.NullTime{Time: now.Add(-1 * time.Minute), Valid: true},
		},
		Client: &models.Client{
			ClientIdentifier:                    "email-only-client",
			IncludeOpenIDConnectClaimsInIdToken: enums.ThreeStateSettingDefault.String(),
		},
		Scope:             "openid email", // Only email scope, NOT profile/address/phone
		Nonce:             "test-nonce",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       []string{"pwd"},
		SessionIdentifier: "session-email-only",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		AccessToken:       "",
	}

	// NOTE: No UserHasProfilePicture mock needed - email scope doesn't check for pictures

	idToken, err := tokenIssuer.generateIdTokenCore(settings, input, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	// Standard claims
	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, sub.String(), claims["sub"])

	// Email scope claims SHOULD be present
	assert.Equal(t, input.User.Email, claims["email"])
	assert.Equal(t, input.User.EmailVerified, claims["email_verified"])

	// Profile scope claims should NOT be present (scope doesn't include profile)
	assert.NotContains(t, claims, "given_name")
	assert.NotContains(t, claims, "family_name")
	assert.NotContains(t, claims, "name")
	assert.NotContains(t, claims, "preferred_username")
	assert.NotContains(t, claims, "profile")

	// Phone scope claims should NOT be present (scope doesn't include phone)
	assert.NotContains(t, claims, "phone_number")
	assert.NotContains(t, claims, "phone_number_verified")

	// Address scope claims should NOT be present (scope doesn't include address)
	assert.NotContains(t, claims, "address")
}

func TestGenerateIdToken_IncludeOpenIDConnectClaimsInIdToken_WithProfilePicture(t *testing.T) {
	// Test that picture claim is included when user has profile picture
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                              "https://test-issuer.com",
		TokenExpirationInSeconds:            600,
		IncludeOpenIDConnectClaimsInIdToken: true, // Enabled
	}

	now := time.Now().UTC()
	sub := uuid.New()
	userId := int64(999)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	input := &TokenGenerationInput{
		User: &models.User{
			Id:            userId,
			Subject:       sub,
			Email:         "picture@example.com",
			EmailVerified: true,
			GivenName:     "Picture",
			FamilyName:    "User",
			UpdatedAt:     sql.NullTime{Time: now.Add(-1 * time.Minute), Valid: true},
		},
		Client: &models.Client{
			ClientIdentifier:                    "picture-client",
			IncludeOpenIDConnectClaimsInIdToken: enums.ThreeStateSettingDefault.String(),
		},
		Scope:             "openid profile email",
		Nonce:             "test-nonce",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       []string{"pwd"},
		SessionIdentifier: "session-picture",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		AccessToken:       "",
	}

	// Mock: User HAS a profile picture
	mockDB.On("UserHasProfilePicture", mock.AnythingOfType("*sql.Tx"), userId).Return(true, nil)

	idToken, err := tokenIssuer.generateIdTokenCore(settings, input, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	// Standard claims
	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, sub.String(), claims["sub"])

	// Profile claims should be present
	assert.Equal(t, input.User.GivenName, claims["given_name"])
	assert.Equal(t, input.User.FamilyName, claims["family_name"])

	// Picture claim SHOULD be present (user has profile picture)
	// URL format: {baseURL}/userinfo/picture/{userSubject}
	expectedPictureURL := fmt.Sprintf("http://localhost:8081/userinfo/picture/%s", sub.String())
	assert.Equal(t, expectedPictureURL, claims["picture"])
}

func TestGenerateIdToken_IncludeOpenIDConnectClaimsInIdToken_EmptyUserFields(t *testing.T) {
	// Test with user having empty/null optional fields
	// Should only include non-empty claims
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081")

	settings := &models.Settings{
		Issuer:                              "https://test-issuer.com",
		TokenExpirationInSeconds:            600,
		IncludeOpenIDConnectClaimsInIdToken: true, // Enabled
	}

	now := time.Now().UTC()
	sub := uuid.New()

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	input := &TokenGenerationInput{
		User: &models.User{
			Subject:       sub,
			Email:         "minimal@example.com",
			EmailVerified: true,
			GivenName:     "Minimal",
			// FamilyName: empty
			// MiddleName: empty
			// Nickname: empty
			// Website: empty
			// Gender: empty
			// BirthDate: null (not valid)
			// ZoneInfo: empty
			// Locale: empty
			// PhoneNumber: empty
			// AddressLine1: empty
			UpdatedAt: sql.NullTime{Time: now.Add(-1 * time.Minute), Valid: true},
		},
		Client: &models.Client{
			ClientIdentifier:                    "minimal-fields-client",
			IncludeOpenIDConnectClaimsInIdToken: enums.ThreeStateSettingDefault.String(),
		},
		Scope:             "openid profile email address phone",
		Nonce:             "test-nonce",
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       []string{"pwd"},
		SessionIdentifier: "session-minimal",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		AccessToken:       "",
	}

	mockDB.On("UserHasProfilePicture", mock.AnythingOfType("*sql.Tx"), mock.AnythingOfType("int64")).Return(false, nil)

	idToken, err := tokenIssuer.generateIdTokenCore(settings, input, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	// Standard claims
	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, sub.String(), claims["sub"])

	// Email claims SHOULD be present (non-empty)
	assert.Equal(t, input.User.Email, claims["email"])
	assert.Equal(t, input.User.EmailVerified, claims["email_verified"])

	// GivenName SHOULD be present (non-empty)
	assert.Equal(t, input.User.GivenName, claims["given_name"])

	// Name SHOULD be present (derived from GivenName)
	assert.Equal(t, "Minimal", claims["name"])

	// Empty/null fields should NOT be present
	assert.NotContains(t, claims, "family_name")
	assert.NotContains(t, claims, "middle_name")
	assert.NotContains(t, claims, "nickname")
	assert.NotContains(t, claims, "website")
	assert.NotContains(t, claims, "gender")
	assert.NotContains(t, claims, "birthdate")
	assert.NotContains(t, claims, "zoneinfo")
	assert.NotContains(t, claims, "locale")
	assert.NotContains(t, claims, "phone_number")
	// NOTE: phone_number_verified IS included (always present when phone scope exists, defaults to false)
	assert.Equal(t, false, claims["phone_number_verified"])
	assert.NotContains(t, claims, "address")

	// Updated_at SHOULD be present (has valid timestamp)
	assert.Contains(t, claims, "updated_at")
}
