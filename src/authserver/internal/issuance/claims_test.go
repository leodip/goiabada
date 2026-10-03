package issuance

import (
	"context"
	"database/sql"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/userclaims"
	"github.com/leodip/goiabada/authserver/internal/uuidutil"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestGenerateAccessToken(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		IncludeOpenIDConnectClaimsInAccessToken: true,
	}

	now := time.Now().UTC()
	sub := fake.UUID()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

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
		IncludeOpenIDConnectClaimsInAccessToken: "on",
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "test@example.com",
		EmailVerified: true,
		Username:      "testuser",
		GivenName:     "Test",
		FamilyName:    "User",
		UpdatedAt:     sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
	}

	code.Client = *client
	code.User = *user

	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, user.Id).Return(false, nil)

	accessToken, err := tokenIssuer.generateAccessToken(context.Background(), nil, settings, code, code.Scope, now, privKey, "test-key-id", nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)

	claims := verifyAndDecodeToken(t, accessToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, user.Subject, claims["sub"])
	assert.Equal(t, builtin.AuthServerResourceIdentifier, claims["aud"])
	assert.Equal(t, code.Nonce, claims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), claims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), claims["amr"])
	assert.Equal(t, sessionIdentifier, claims["sid"])
	assert.Equal(t, "Bearer", claims["typ"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 900*time.Second, "exp should be 900 seconds from now")
	assertTimeClaimWithinRange(t, claims, "auth_time", -300*time.Second, "auth_time should be 300 seconds ago")

	_, err = uuidutil.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.FullName(), claims["name"])
	assert.Equal(t, user.GivenName, claims["given_name"])
	assert.Equal(t, user.FamilyName, claims["family_name"])
	assert.Equal(t, user.Username, claims["preferred_username"])
	assert.Equal(t, "http://localhost:8081/account/profile", claims["profile"])
	assert.Equal(t, user.Email, claims["email"])
	assert.Equal(t, user.EmailVerified, claims["email_verified"])
	assert.Equal(t, "openid profile email", claims["scope"])

	assertTimeClaimWithinRange(t, claims, "updated_at", -1*time.Hour, "updated_at should be 1 hour ago")
}

func TestGenerateAccessToken_CustomScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		IncludeOpenIDConnectClaimsInAccessToken: false,
	}

	now := time.Now().UTC()
	sub := fake.UUID()
	sessionIdentifier := "test-session-456"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                2,
		ClientId:          2,
		UserId:            2,
		Scope:             "resource1:read resource2:write",
		Nonce:             "custom-nonce",
		AuthenticatedAt:   now.Add(-10 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd:otp_mandatory",
		AuthMethods:       "pwd otp",
	}
	client := &models.Client{
		Id:               2,
		ClientIdentifier: "custom-client",
	}
	user := &models.User{
		Id:      2,
		Subject: sub,
	}

	code.Client = *client
	code.User = *user

	accessToken, err := tokenIssuer.generateAccessToken(context.Background(), nil, settings, code, code.Scope, now, privKey, "test-key-id", nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)

	claims := verifyAndDecodeToken(t, accessToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, user.Subject, claims["sub"])
	assert.Equal(t, []interface{}{"resource1", "resource2"}, claims["aud"])
	assert.Equal(t, code.Nonce, claims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), claims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), claims["amr"])
	assert.Equal(t, sessionIdentifier, claims["sid"])
	assert.Equal(t, "Bearer", claims["typ"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 600*time.Second, "exp should be 600 seconds from now")
	assertTimeClaimWithinRange(t, claims, "auth_time", -600*time.Second, "auth_time should be 600 seconds ago")

	_, err = uuidutil.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, "resource1:read resource2:write", claims["scope"])

	// Verify that no OpenID Connect claims are included
	assert.NotContains(t, claims, "name")
	assert.NotContains(t, claims, "email")
	assert.NotContains(t, claims, "profile")
}

func TestGenerateAccessToken_WithGroupsAndAttributes(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		IncludeOpenIDConnectClaimsInAccessToken: true,
	}

	now := time.Now().UTC()
	sub := fake.UUID()
	sessionIdentifier := "test-session-789"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                3,
		ClientId:          3,
		UserId:            3,
		Scope:             "openid profile email groups attributes",
		Nonce:             "groups-attributes-nonce",
		AuthenticatedAt:   now.Add(-15 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:                                      3,
		ClientIdentifier:                        "groups-attributes-client",
		TokenExpirationInSeconds:                1200,
		IncludeOpenIDConnectClaimsInAccessToken: "on",
	}
	user := &models.User{
		Id:            3,
		Subject:       sub,
		Email:         "groups.attributes@example.com",
		EmailVerified: true,
		Username:      "groupsuser",
		GivenName:     "Groups",
		FamilyName:    "User",
		UpdatedAt:     sql.NullTime{Time: now.Add(-2 * time.Hour), Valid: true},
		Groups: []models.Group{
			{GroupIdentifier: "group1", IncludeInAccessToken: true},
			{GroupIdentifier: "group2", IncludeInAccessToken: false},
			{GroupIdentifier: "group3", IncludeInAccessToken: true},
		},
		Attributes: []models.UserAttribute{
			{Key: "attr1", Value: "value1", IncludeInAccessToken: true},
			{Key: "attr2", Value: "value2", IncludeInAccessToken: false},
			{Key: "attr3", Value: "value3", IncludeInAccessToken: true},
		},
	}

	code.Client = *client
	code.User = *user

	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, user.Id).Return(false, nil)

	accessToken, err := tokenIssuer.generateAccessToken(context.Background(), nil, settings, code, code.Scope, now, privKey, "test-key-id", nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)

	claims := verifyAndDecodeToken(t, accessToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, user.Subject, claims["sub"])
	assert.Equal(t, builtin.AuthServerResourceIdentifier, claims["aud"])
	assert.Equal(t, code.Nonce, claims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), claims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), claims["amr"])
	assert.Equal(t, sessionIdentifier, claims["sid"])
	assert.Equal(t, "Bearer", claims["typ"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 1200*time.Second, "exp should be 1200 seconds from now")
	assertTimeClaimWithinRange(t, claims, "auth_time", -900*time.Second, "auth_time should be 900 seconds ago")

	_, err = uuidutil.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.FullName(), claims["name"])
	assert.Equal(t, user.GivenName, claims["given_name"])
	assert.Equal(t, user.FamilyName, claims["family_name"])
	assert.Equal(t, user.Username, claims["preferred_username"])
	assert.Equal(t, "http://localhost:8081/account/profile", claims["profile"])
	assert.Equal(t, user.Email, claims["email"])
	assert.Equal(t, user.EmailVerified, claims["email_verified"])

	assert.Equal(t, "openid profile email groups attributes", claims["scope"])

	assertTimeClaimWithinRange(t, claims, "updated_at", -2*time.Hour, "updated_at should be 2 hours ago")

	// Check groups claim
	groups, ok := claims["groups"].([]interface{})
	assert.True(t, ok)
	assert.ElementsMatch(t, []string{"group1", "group3"}, groups)

	// Check attributes claim
	attributes, ok := claims["attributes"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "value1", attributes["attr1"])
	assert.Equal(t, "value3", attributes["attr3"])
	assert.NotContains(t, attributes, "attr2")
}

func TestGenerateAccessToken_InvalidScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                              "https://test-issuer.com",
		TokenExpirationInSeconds:            600,
		IncludeOpenIDConnectClaimsInIdToken: true,
	}

	now := time.Now().UTC()
	sub := fake.UUID()
	sessionIdentifier := "test-session-invalid"

	privateKeyBytes := getTestPrivateKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                4,
		ClientId:          4,
		UserId:            4,
		Scope:             "invalid-scope",
		Nonce:             "invalid-nonce",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:               4,
		ClientIdentifier: "invalid-client",
	}
	user := &models.User{
		Id:      4,
		Subject: sub,
	}

	code.Client = *client
	code.User = *user

	_, err = tokenIssuer.generateAccessToken(context.Background(), nil, settings, code, code.Scope, now, privKey, "test-key-id", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid scope")
}

func TestGenerateIdToken_FullScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                              "https://test-issuer.com",
		TokenExpirationInSeconds:            600,
		IncludeOpenIDConnectClaimsInIdToken: true,
	}

	now := time.Now().UTC()
	sub := fake.UUID()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                1,
		ClientId:          1,
		UserId:            1,
		Scope:             "openid profile email address phone groups attributes",
		Nonce:             "test-nonce",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd:otp_mandatory",
		AuthMethods:       "pwd otp",
	}
	client := &models.Client{
		Id:                                  1,
		ClientIdentifier:                    "test-client",
		IncludeOpenIDConnectClaimsInIdToken: "on",
	}
	user := &models.User{
		Id:                  1,
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
		AddressLine2:        "Apt 4",
		AddressLocality:     "Testville",
		AddressRegion:       "Testshire",
		AddressPostalCode:   "TE1 2ST",
		AddressCountry:      "Testland",
		UpdatedAt:           sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
		Groups: []models.Group{
			{GroupIdentifier: "group1", IncludeInIdToken: true},
			{GroupIdentifier: "group2", IncludeInIdToken: false},
		},
		Attributes: []models.UserAttribute{
			{Key: "attr1", Value: "value1", IncludeInIdToken: true},
			{Key: "attr2", Value: "value2", IncludeInIdToken: false},
		},
	}

	code.Client = *client
	code.User = *user

	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, user.Id).Return(false, nil)

	idToken, err := tokenIssuer.generateIdToken(context.Background(), nil, settings, code, code.Scope, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, user.Subject, claims["sub"])
	assert.Equal(t, client.ClientIdentifier, claims["aud"])
	assert.Equal(t, code.Nonce, claims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), claims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), claims["amr"])
	assert.Equal(t, sessionIdentifier, claims["sid"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 600*time.Second, "exp should be 600 seconds from now")
	assertTimeClaimWithinRange(t, claims, "auth_time", -300*time.Second, "auth_time should be 300 seconds ago")

	_, err = uuidutil.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.FullName(), claims["name"])
	assert.Equal(t, user.GivenName, claims["given_name"])
	assert.Equal(t, user.MiddleName, claims["middle_name"])
	assert.Equal(t, user.FamilyName, claims["family_name"])
	assert.Equal(t, user.Nickname, claims["nickname"])
	assert.Equal(t, user.Username, claims["preferred_username"])
	assert.Equal(t, "http://localhost:8081/account/profile", claims["profile"])
	assert.Equal(t, user.Website, claims["website"])
	assert.Equal(t, user.Gender, claims["gender"])
	assert.Equal(t, "1990-01-01", claims["birthdate"])
	assert.Equal(t, user.ZoneInfo, claims["zoneinfo"])
	assert.Equal(t, user.Locale, claims["locale"])
	assert.Equal(t, user.Email, claims["email"])
	assert.Equal(t, user.EmailVerified, claims["email_verified"])
	assert.Equal(t, user.PhoneNumber, claims["phone_number"])
	assert.Equal(t, user.PhoneNumberVerified, claims["phone_number_verified"])

	address := claims["address"].(map[string]interface{})
	assert.Equal(t, user.AddressLine1+"\r\n"+user.AddressLine2, address["street_address"])
	assert.Equal(t, user.AddressLocality, address["locality"])
	assert.Equal(t, user.AddressRegion, address["region"])
	assert.Equal(t, user.AddressPostalCode, address["postal_code"])
	assert.Equal(t, user.AddressCountry, address["country"])

	groups := claims["groups"].([]interface{})
	assert.Contains(t, groups, "group1")
	assert.NotContains(t, groups, "group2")

	attributes := claims["attributes"].(map[string]interface{})
	assert.Equal(t, "value1", attributes["attr1"])
	assert.NotContains(t, attributes, "attr2")

	assertTimeClaimWithinRange(t, claims, "updated_at", -1*time.Hour, "updated_at should be 1 hour ago")
}

func TestGenerateIdToken_MinimalScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 300,
	}

	now := time.Now().UTC()
	sub := fake.UUID()
	sessionIdentifier := "test-session-456"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                2,
		ClientId:          2,
		UserId:            2,
		Scope:             "openid",
		Nonce:             "minimal-nonce",
		AuthenticatedAt:   now.Add(-1 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:               2,
		ClientIdentifier: "minimal-client",
	}
	user := &models.User{
		Id:      2,
		Subject: sub,
	}

	code.Client = *client
	code.User = *user

	idToken, err := tokenIssuer.generateIdToken(context.Background(), nil, settings, code, code.Scope, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, user.Subject, claims["sub"])
	assert.Equal(t, client.ClientIdentifier, claims["aud"])
	assert.Equal(t, code.Nonce, claims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), claims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), claims["amr"])
	assert.Equal(t, sessionIdentifier, claims["sid"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 300*time.Second, "exp should be 300 seconds from now")
	assertTimeClaimWithinRange(t, claims, "auth_time", -60*time.Second, "auth_time should be 60 seconds ago")

	_, err = uuidutil.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	assert.NotContains(t, claims, "name")
	assert.NotContains(t, claims, "email")
	assert.NotContains(t, claims, "address")
	assert.NotContains(t, claims, "phone_number")
	assert.NotContains(t, claims, "groups")
	assert.NotContains(t, claims, "attributes")
}

func TestGenerateIdToken_ClientOverride(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                              "https://test-issuer.com",
		TokenExpirationInSeconds:            600,
		IncludeOpenIDConnectClaimsInIdToken: true,
	}

	now := time.Now().UTC()
	sub := fake.UUID()
	sessionIdentifier := "test-session-789"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                3,
		ClientId:          3,
		UserId:            3,
		Scope:             "openid profile email",
		Nonce:             "override-nonce",
		AuthenticatedAt:   now.Add(-2 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd:otp_ifpossible",
		AuthMethods:       "pwd otp",
	}
	client := &models.Client{
		Id:                       3,
		ClientIdentifier:         "override-client",
		TokenExpirationInSeconds: 1200,
	}
	user := &models.User{
		Id:            3,
		Subject:       sub,
		Email:         "override@example.com",
		EmailVerified: true,
		Username:      "overrideuser",
		GivenName:     "Override",
		FamilyName:    "User",
		UpdatedAt:     sql.NullTime{Time: now.Add(-30 * time.Minute), Valid: true},
	}

	code.Client = *client
	code.User = *user

	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, user.Id).Return(false, nil)

	idToken, err := tokenIssuer.generateIdToken(context.Background(), nil, settings, code, code.Scope, now, privKey, "test-key-id")
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	claims := verifyAndDecodeToken(t, idToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, user.Subject, claims["sub"])
	assert.Equal(t, client.ClientIdentifier, claims["aud"])
	assert.Equal(t, code.Nonce, claims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), claims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), claims["amr"])
	assert.Equal(t, sessionIdentifier, claims["sid"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 1200*time.Second, "exp should be 1200 seconds from now (client override)")
	assertTimeClaimWithinRange(t, claims, "auth_time", -120*time.Second, "auth_time should be 120 seconds ago")

	_, err = uuidutil.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.FullName(), claims["name"])
	assert.Equal(t, user.GivenName, claims["given_name"])
	assert.Equal(t, user.FamilyName, claims["family_name"])
	assert.Equal(t, user.Username, claims["preferred_username"])
	assert.Equal(t, "http://localhost:8081/account/profile", claims["profile"])
	assert.Equal(t, user.Email, claims["email"])
	assert.Equal(t, user.EmailVerified, claims["email_verified"])

	assertTimeClaimWithinRange(t, claims, "updated_at", -30*time.Minute, "updated_at should be 30 minutes ago")
}

// The one lifetime rule every grant reads (#437 decision 11): a client's positive lifetime wins,
// and anything else inherits the server's.
func TestTokenLifetimeSeconds(t *testing.T) {
	settings := &models.Settings{TokenExpirationInSeconds: 3600}

	tests := []struct {
		name           string
		clientLifetime int
		expected       int
	}{
		{name: "client override wins", clientLifetime: 900, expected: 900},
		{name: "override longer than the setting wins too", clientLifetime: 7200, expected: 7200},
		{name: "zero inherits the setting", clientLifetime: 0, expected: 3600},
		{name: "a negative value inherits the setting", clientLifetime: -1, expected: 3600},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &models.Client{TokenExpirationInSeconds: tt.clientLifetime}
			assert.Equal(t, tt.expected, tokenLifetimeSeconds(settings, client))
		})
	}
}

func TestCalculateAtHash(t *testing.T) {
	tokenIssuer := &TokenIssuer{}

	testCases := []struct {
		name        string
		accessToken string
	}{
		{
			name:        "Standard access token",
			accessToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
		},
		{
			name:        "Empty token",
			accessToken: "",
		},
		{
			name:        "Short token",
			accessToken: "abc",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			atHash := tokenIssuer.calculateAtHash(tc.accessToken)

			if tc.accessToken == "" {
				// Empty token should still produce a hash (of empty string)
				assert.NotEmpty(t, atHash)
			} else {
				assert.NotEmpty(t, atHash)
			}

			// Verify it's base64url encoded (no padding, no + or /)
			assert.NotContains(t, atHash, "=")
			assert.NotContains(t, atHash, "+")
			assert.NotContains(t, atHash, "/")

			// Verify consistency - same input produces same output
			atHash2 := tokenIssuer.calculateAtHash(tc.accessToken)
			assert.Equal(t, atHash, atHash2)
		})
	}
}

func TestCalculateAtHash_MatchesOIDCSpec(t *testing.T) {
	// This test verifies the at_hash calculation follows OIDC Core 3.2.2.10
	// at_hash = base64url(left_half(SHA256(access_token)))
	tokenIssuer := &TokenIssuer{}

	// Use a known access token to verify the calculation
	accessToken := "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"

	atHash := tokenIssuer.calculateAtHash(accessToken)

	// The at_hash should be 16 bytes (128 bits) when decoded
	// SHA256 produces 32 bytes, left half is 16 bytes
	decoded, err := base64.RawURLEncoding.DecodeString(atHash)
	assert.NoError(t, err)
	assert.Len(t, decoded, 16, "at_hash should be 16 bytes (left half of SHA256)")
}

// TestAuthMethodsToArray tests the authMethodsToArray helper function
// which converts space-separated auth methods to a JSON array per OIDC Core 1.0 Section 2
func TestAuthMethodsToArray(t *testing.T) {
	tests := []struct {
		name        string
		authMethods string
		expected    []string
	}{
		{
			name:        "empty string returns empty array",
			authMethods: "",
			expected:    []string{},
		},
		{
			name:        "single method pwd",
			authMethods: "pwd",
			expected:    []string{"pwd"},
		},
		{
			name:        "single method otp",
			authMethods: "otp",
			expected:    []string{"otp"},
		},
		{
			name:        "two methods pwd otp",
			authMethods: "pwd otp",
			expected:    []string{"pwd", "otp"},
		},
		{
			name:        "two methods otp pwd (reversed order)",
			authMethods: "otp pwd",
			expected:    []string{"otp", "pwd"},
		},
		{
			name:        "multiple spaces between methods",
			authMethods: "pwd   otp",
			expected:    []string{"pwd", "otp"},
		},
		{
			name:        "leading and trailing spaces",
			authMethods: "  pwd otp  ",
			expected:    []string{"pwd", "otp"},
		},
		{
			name:        "tabs and mixed whitespace",
			authMethods: "pwd\totp",
			expected:    []string{"pwd", "otp"},
		},
		{
			name:        "three hypothetical methods",
			authMethods: "pwd otp sms",
			expected:    []string{"pwd", "otp", "sms"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := authMethodsToArray(tt.authMethods)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAuthMethodsToArray_OIDCCompliance verifies OIDC Core 1.0 Section 2 compliance
// The amr claim MUST be a JSON array of strings identifying authentication methods
func TestAuthMethodsToArray_OIDCCompliance(t *testing.T) {
	// Test that the result is always a slice (array), never nil
	t.Run("empty input returns empty slice not nil", func(t *testing.T) {
		result := authMethodsToArray("")
		assert.NotNil(t, result, "amr should be an empty array, not nil")
		assert.Equal(t, 0, len(result))
	})

	// Test common authentication scenarios
	t.Run("password-only authentication", func(t *testing.T) {
		result := authMethodsToArray("pwd")
		assert.Equal(t, []string{"pwd"}, result)
	})

	t.Run("password plus OTP (MFA)", func(t *testing.T) {
		result := authMethodsToArray("pwd otp")
		assert.Equal(t, []string{"pwd", "otp"}, result)
	})
}

// TestAMR_IsArrayType_InGeneratedTokens verifies that AMR claim in JWT is always an array type.
// OIDC Core 1.0 Section 2 requires amr to be a JSON array of strings.
// This test explicitly checks the type, not just the values.
func TestAMR_IsArrayType_InGeneratedTokens(t *testing.T) {
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
	sessionIdentifier := "test-session-123"

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "test@example.com",
		EmailVerified: true,
	}

	keyPair := &models.KeyPair{
		Id:            1,
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
		PublicKeyPEM:  publicKeyBytes,
	}

	t.Run("AuthCode flow - single method (pwd)", func(t *testing.T) {
		code := &models.Code{
			Id:                1,
			ClientId:          1,
			UserId:            1,
			Scope:             "openid",
			Nonce:             "test-nonce",
			AuthenticatedAt:   time.Now().UTC().Add(-5 * time.Minute),
			SessionIdentifier: sessionIdentifier,
			AcrLevel:          "urn:goiabada:level1",
			AuthMethods:       "pwd",
			Client:            *client,
			User:              *user,
		}

		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil).Once()
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(&models.UserSession{
			Started: time.Now().UTC().Add(-10 * time.Minute),
		}, nil).Once()
		mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil).Once()

		response, err := tokenIssuer.mintAuthorizationCodeTokens(ctx, settings, code)
		assert.NoError(t, err)

		// Verify access_token AMR is an array
		accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
		amrAccess := accessClaims["amr"]
		_, isArray := amrAccess.([]interface{})
		assert.True(t, isArray, "amr in access_token must be a JSON array, got %T", amrAccess)
		assert.ElementsMatch(t, []string{"pwd"}, amrAccess)

		// Verify id_token AMR is an array
		idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
		amrId := idClaims["amr"]
		_, isArray = amrId.([]interface{})
		assert.True(t, isArray, "amr in id_token must be a JSON array, got %T", amrId)
		assert.ElementsMatch(t, []string{"pwd"}, amrId)
	})

	t.Run("AuthCode flow - multiple methods (pwd otp)", func(t *testing.T) {
		code := &models.Code{
			Id:                2,
			ClientId:          1,
			UserId:            1,
			Scope:             "openid",
			Nonce:             "test-nonce-2",
			AuthenticatedAt:   time.Now().UTC().Add(-5 * time.Minute),
			SessionIdentifier: sessionIdentifier,
			AcrLevel:          "urn:goiabada:level2_mandatory",
			AuthMethods:       "pwd otp",
			Client:            *client,
			User:              *user,
		}

		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil).Once()
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(&models.UserSession{
			Started: time.Now().UTC().Add(-10 * time.Minute),
		}, nil).Once()
		mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil).Once()

		response, err := tokenIssuer.mintAuthorizationCodeTokens(ctx, settings, code)
		assert.NoError(t, err)

		// Verify access_token AMR is an array with both methods
		accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
		amrAccess := accessClaims["amr"]
		_, isArray := amrAccess.([]interface{})
		assert.True(t, isArray, "amr in access_token must be a JSON array, got %T", amrAccess)
		assert.ElementsMatch(t, []string{"pwd", "otp"}, amrAccess)

		// Verify id_token AMR is an array with both methods
		idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
		amrId := idClaims["amr"]
		_, isArray = amrId.([]interface{})
		assert.True(t, isArray, "amr in id_token must be a JSON array, got %T", amrId)
		assert.ElementsMatch(t, []string{"pwd", "otp"}, amrId)
	})

	t.Run("ROPC flow - always pwd array", func(t *testing.T) {
		mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil).Once()
		mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil).Once()

		input := &ROPCGrantInput{
			Client: client,
			User:   user,
			Scope:  "openid",
		}

		response, err := tokenIssuer.IssuePasswordGrant(ctx, settings, input)
		assert.NoError(t, err)

		// Verify access_token AMR is an array
		accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
		amrAccess := accessClaims["amr"]
		_, isArray := amrAccess.([]interface{})
		assert.True(t, isArray, "amr in ROPC access_token must be a JSON array, got %T", amrAccess)
		assert.ElementsMatch(t, []string{"pwd"}, amrAccess)

		// Verify id_token AMR is an array
		idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
		amrId := idClaims["amr"]
		_, isArray = amrId.([]interface{})
		assert.True(t, isArray, "amr in ROPC id_token must be a JSON array, got %T", amrId)
		assert.ElementsMatch(t, []string{"pwd"}, amrId)
	})

	t.Run("Implicit flow - AMR array", func(t *testing.T) {
		mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil).Once()
		mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		input := &ImplicitGrantInput{
			Client:            client,
			User:              user,
			Scope:             "openid",
			AcrLevel:          "urn:goiabada:level2_optional",
			AuthMethods:       "pwd otp",
			SessionIdentifier: sessionIdentifier,
			Nonce:             "test-nonce",
			AuthenticatedAt:   time.Now().UTC().Add(-5 * time.Minute),
		}

		armImplicitTransaction(mockDB, input.SessionIdentifier)

		response, err := tokenIssuer.IssueImplicitTx(ctx, settings, input, true, true)
		assert.NoError(t, err)

		// Verify access_token AMR is an array
		accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
		amrAccess := accessClaims["amr"]
		_, isArray := amrAccess.([]interface{})
		assert.True(t, isArray, "amr in implicit access_token must be a JSON array, got %T", amrAccess)
		assert.ElementsMatch(t, []string{"pwd", "otp"}, amrAccess)

		// Verify id_token AMR is an array
		idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
		amrId := idClaims["amr"]
		_, isArray = amrId.([]interface{})
		assert.True(t, isArray, "amr in implicit id_token must be a JSON array, got %T", amrId)
		assert.ElementsMatch(t, []string{"pwd", "otp"}, amrId)
	})

	mockDB.AssertExpectations(t)
}

// TestAMR_OmittedWhenNoAuthMethodRecorded verifies that the amr claim is absent from both the
// access token and the id_token when no authentication method was recorded, rather than present
// and empty. OIDC Core 1.0 section 2 makes amr OPTIONAL, so absent says nothing, where "amr": []
// asserts that the authentication used no methods at all (#240).
//
// The claim is observed only through the decoded signed token, and absence is asserted with the
// comma-ok form: claims["amr"] returns nil for a missing key, and an empty array decodes to a
// non-nil []interface{}{}, so assert.Nil would pass for either and pin nothing.
func TestAMR_OmittedWhenNoAuthMethodRecorded(t *testing.T) {
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
	sessionIdentifier := "test-session-amr-absent"

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "test@example.com",
		EmailVerified: true,
	}

	keyPair := &models.KeyPair{
		Id:            1,
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
		PublicKeyPEM:  publicKeyBytes,
	}

	expectAuthCodeCalls := func() {
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil).Once()
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(&models.UserSession{
			Started: time.Now().UTC().Add(-10 * time.Minute),
		}, nil).Once()
		mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil).Once()
	}

	expectImplicitCalls := func() {
		mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(keyPair, nil).Once()
		mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	}

	// An empty auth_methods is what a user_sessions row with no recorded method produces: the
	// column is a plain string with no constraint, and handler_authorize copies it into the auth
	// context, which stamps it onto the code.
	t.Run("AuthCode flow - no method recorded, amr absent from both tokens", func(t *testing.T) {
		expectAuthCodeCalls()

		code := &models.Code{
			Id:                10,
			ClientId:          1,
			UserId:            1,
			Scope:             "openid",
			Nonce:             "test-nonce-amr-absent",
			AuthenticatedAt:   time.Now().UTC().Add(-5 * time.Minute),
			SessionIdentifier: sessionIdentifier,
			AcrLevel:          "urn:goiabada:level1",
			AuthMethods:       "",
			Client:            *client,
			User:              *user,
		}

		response, err := tokenIssuer.mintAuthorizationCodeTokens(ctx, settings, code)
		assert.NoError(t, err)

		accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
		_, present := accessClaims["amr"]
		assert.False(t, present, "amr must be absent from the access_token, not an empty array")

		idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
		_, present = idClaims["amr"]
		assert.False(t, present, "amr must be absent from the id_token, not an empty array")
	})

	// Keep this: without it the guard could be written as an unconditional delete, or as
	// `if false`, and every absence case above would still be green.
	t.Run("AuthCode flow - method recorded, amr still present", func(t *testing.T) {
		expectAuthCodeCalls()

		code := &models.Code{
			Id:                11,
			ClientId:          1,
			UserId:            1,
			Scope:             "openid",
			Nonce:             "test-nonce-amr-present",
			AuthenticatedAt:   time.Now().UTC().Add(-5 * time.Minute),
			SessionIdentifier: sessionIdentifier,
			AcrLevel:          "urn:goiabada:level1",
			AuthMethods:       "pwd",
			Client:            *client,
			User:              *user,
		}

		response, err := tokenIssuer.mintAuthorizationCodeTokens(ctx, settings, code)
		assert.NoError(t, err)

		accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
		amrAccess, present := accessClaims["amr"]
		assert.True(t, present, "amr must still be present in the access_token when a method was recorded")
		assert.ElementsMatch(t, []string{"pwd"}, amrAccess)

		idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
		amrId, present := idClaims["amr"]
		assert.True(t, present, "amr must still be present in the id_token when a method was recorded")
		assert.ElementsMatch(t, []string{"pwd"}, amrId)
	})

	t.Run("Implicit flow - no method recorded, amr absent from both tokens", func(t *testing.T) {
		expectImplicitCalls()

		input := &ImplicitGrantInput{
			Client:            client,
			User:              user,
			Scope:             "openid",
			AcrLevel:          "urn:goiabada:level1",
			AuthMethods:       "",
			SessionIdentifier: sessionIdentifier,
			Nonce:             "test-nonce-implicit-absent",
			AuthenticatedAt:   time.Now().UTC().Add(-5 * time.Minute),
		}

		armImplicitTransaction(mockDB, input.SessionIdentifier)

		response, err := tokenIssuer.IssueImplicitTx(ctx, settings, input, true, true)
		assert.NoError(t, err)

		accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
		_, present := accessClaims["amr"]
		assert.False(t, present, "amr must be absent from the implicit access_token, not an empty array")

		idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
		_, present = idClaims["amr"]
		assert.False(t, present, "amr must be absent from the implicit id_token, not an empty array")
	})

	// Keep this, for the reason given on the auth code control case above.
	t.Run("Implicit flow - methods recorded, amr still present", func(t *testing.T) {
		expectImplicitCalls()

		input := &ImplicitGrantInput{
			Client:            client,
			User:              user,
			Scope:             "openid",
			AcrLevel:          "urn:goiabada:level2_optional",
			AuthMethods:       "pwd otp",
			SessionIdentifier: sessionIdentifier,
			Nonce:             "test-nonce-implicit-present",
			AuthenticatedAt:   time.Now().UTC().Add(-5 * time.Minute),
		}

		armImplicitTransaction(mockDB, input.SessionIdentifier)

		response, err := tokenIssuer.IssueImplicitTx(ctx, settings, input, true, true)
		assert.NoError(t, err)

		accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
		amrAccess, present := accessClaims["amr"]
		assert.True(t, present, "amr must still be present in the implicit access_token when methods were recorded")
		assert.ElementsMatch(t, []string{"pwd", "otp"}, amrAccess)

		idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
		amrId, present := idClaims["amr"]
		assert.True(t, present, "amr must still be present in the implicit id_token when methods were recorded")
		assert.ElementsMatch(t, []string{"pwd", "otp"}, amrId)
	})

	mockDB.AssertExpectations(t)
}

// TestAMR_EdgeCases tests edge cases for authMethodsToArray
func TestAMR_EdgeCases(t *testing.T) {
	t.Run("whitespace only returns empty array", func(t *testing.T) {
		result := authMethodsToArray("   ")
		assert.Equal(t, []string{}, result)
		assert.NotNil(t, result)
	})

	t.Run("newlines and tabs", func(t *testing.T) {
		result := authMethodsToArray("pwd\n\totp")
		assert.Equal(t, []string{"pwd", "otp"}, result)
	})

	t.Run("mixed whitespace variations", func(t *testing.T) {
		result := authMethodsToArray(" \t pwd \n otp \t ")
		assert.Equal(t, []string{"pwd", "otp"}, result)
	})

	t.Run("single newline", func(t *testing.T) {
		result := authMethodsToArray("\n")
		assert.Equal(t, []string{}, result)
	})
}

// =============================================================================
// Tests for unified core token generation functions
// =============================================================================

// TestCreateTokenInputFromCode verifies the factory function for auth code flow
func TestCreateTokenInputFromCode(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	now := time.Now().UTC()
	userSubject := fake.UUID()

	code := &models.Code{
		Scope:             "openid profile email",
		AcrLevel:          "urn:goiabada:level2",
		AuthMethods:       "pwd otp",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		SessionIdentifier: "session-123",
		Nonce:             "nonce-abc",
		User: models.User{
			Subject: userSubject,
			Email:   "test@example.com",
		},
		Client: models.Client{
			ClientIdentifier: "test-client",
		},
	}

	input := tokenIssuer.createTokenInputFromCode(code)

	assert.Equal(t, &code.User, input.User)
	assert.Equal(t, &code.Client, input.Client)
	assert.Equal(t, code.Scope, input.Scope)
	assert.Equal(t, code.AcrLevel, input.AcrLevel)
	assert.Equal(t, []string{"pwd", "otp"}, input.AuthMethods)
	assert.Equal(t, code.AuthenticatedAt, input.AuthenticatedAt)
	assert.Equal(t, code.SessionIdentifier, input.SessionIdentifier)
	assert.Equal(t, code.Nonce, input.Nonce)
	assert.Empty(t, input.AccessToken) // Not set by factory
}

// TestCreateTokenInputFromImplicit verifies the factory function for implicit flow
func TestCreateTokenInputFromImplicit(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	now := time.Now().UTC()
	userSubject := fake.UUID()

	implicitInput := &ImplicitGrantInput{
		Client: &models.Client{
			ClientIdentifier: "implicit-client",
		},
		User: &models.User{
			Subject: userSubject,
			Email:   "implicit@example.com",
		},
		Scope:             "openid profile",
		AcrLevel:          "urn:goiabada:level1",
		AuthMethods:       "pwd",
		SessionIdentifier: "implicit-session",
		Nonce:             "implicit-nonce",
		AuthenticatedAt:   now.Add(-2 * time.Minute),
	}

	input := tokenIssuer.createTokenInputFromImplicit(implicitInput)

	assert.Equal(t, implicitInput.User, input.User)
	assert.Equal(t, implicitInput.Client, input.Client)
	assert.Equal(t, implicitInput.Scope, input.Scope)
	assert.Equal(t, implicitInput.AcrLevel, input.AcrLevel)
	assert.Equal(t, []string{"pwd"}, input.AuthMethods)
	assert.Equal(t, implicitInput.AuthenticatedAt, input.AuthenticatedAt)
	assert.Equal(t, implicitInput.SessionIdentifier, input.SessionIdentifier)
	assert.Equal(t, implicitInput.Nonce, input.Nonce)
}

// TestCreateTokenInputFromROPC verifies the factory function for ROPC flow
func TestCreateTokenInputFromROPC(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	now := time.Now().UTC()
	userSubject := fake.UUID()

	ropcInput := &ROPCGrantInput{
		Client: &models.Client{
			ClientIdentifier: "ropc-client",
		},
		User: &models.User{
			Subject: userSubject,
			Email:   "ropc@example.com",
		},
		Scope:           "openid email",
		AuthenticatedAt: now,
	}

	input := tokenIssuer.createTokenInputFromROPC(ropcInput)

	assert.Equal(t, ropcInput.User, input.User)
	assert.Equal(t, ropcInput.Client, input.Client)
	assert.Equal(t, ropcInput.Scope, input.Scope)
	// ROPC-specific hardcoded values
	assert.Equal(t, models.AcrLevel1, input.AcrLevel)
	assert.Equal(t, []string{"pwd"}, input.AuthMethods)
	assert.Equal(t, now, input.AuthenticatedAt)
	// Reversed deliberately. This used to assert the session identifier was forwarded from
	// ROPCGrantInput, which is how a password grant could be handed an ID token carrying an
	// unrelated browser session's identifier. ROPC is sessionless now and the field is gone,
	// so the only correct expectation is empty (#106).
	assert.Empty(t, input.SessionIdentifier, "ROPC tokens must never carry a session identifier")
	assert.Empty(t, input.Nonce) // ROPC doesn't use nonce
}

// TestGenerateAccessTokenCore_InvalidScope tests error handling for invalid scopes
func TestGenerateAccessTokenCore_InvalidScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	privateKeyBytes := getTestPrivateKey(t)
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600,
	}

	now := time.Now().UTC()
	userSubject := fake.UUID()

	t.Run("Invalid scope format - no colon", func(t *testing.T) {
		input := &tokenGenerationInput{
			User: &models.User{
				Subject: userSubject,
			},
			Client: &models.Client{
				ClientIdentifier: "test-client",
			},
			Scope:           "invalidscope", // Missing colon separator
			AcrLevel:        "urn:goiabada:pwd",
			AuthMethods:     []string{"pwd"},
			AuthenticatedAt: now,
		}

		_, err := tokenIssuer.generateAccessTokenCore(context.Background(), nil, settings, input, now, privKey, "key-id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid scope")
	})

	t.Run("Empty audience - only openid scope", func(t *testing.T) {
		// This should not error - openid adds authserver as audience
		mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()

		input := &tokenGenerationInput{
			User: &models.User{
				Subject: userSubject,
			},
			Client: &models.Client{
				ClientIdentifier: "test-client",
			},
			Scope:           "openid",
			AcrLevel:        "urn:goiabada:pwd",
			AuthMethods:     []string{"pwd"},
			AuthenticatedAt: now,
		}

		token, err := tokenIssuer.generateAccessTokenCore(context.Background(), nil, settings, input, now, privKey, "key-id")
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		claims := verifyAndDecodeToken(t, token, getTestPublicKey(t))
		assert.Equal(t, "openid", claims["scope"])
	})
}

// TestGenerateAccessTokenCore_MultipleAudiences tests handling of multiple resource audiences
func TestGenerateAccessTokenCore_MultipleAudiences(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600,
	}

	now := time.Now().UTC()
	userSubject := fake.UUID()

	input := &tokenGenerationInput{
		User: &models.User{
			Subject: userSubject,
		},
		Client: &models.Client{
			ClientIdentifier: "test-client",
		},
		Scope:           "resource1:read resource2:write resource3:admin",
		AcrLevel:        "urn:goiabada:pwd",
		AuthMethods:     []string{"pwd"},
		AuthenticatedAt: now,
	}

	token, err := tokenIssuer.generateAccessTokenCore(context.Background(), nil, settings, input, now, privKey, "key-id")
	assert.NoError(t, err)

	claims := verifyAndDecodeToken(t, token, publicKeyBytes)
	aud := claims["aud"].([]interface{})
	assert.Len(t, aud, 3)
	assert.Contains(t, aud, "resource1")
	assert.Contains(t, aud, "resource2")
	assert.Contains(t, aud, "resource3")
}

// TestGenerateAccessTokenCore_OptionalClaims tests optional claims (nonce, sid)
func TestGenerateAccessTokenCore_OptionalClaims(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600,
	}

	now := time.Now().UTC()
	userSubject := fake.UUID()

	t.Run("With nonce and sid", func(t *testing.T) {
		input := &tokenGenerationInput{
			User: &models.User{
				Subject: userSubject,
			},
			Client: &models.Client{
				ClientIdentifier: "test-client",
			},
			Scope:             "resource:read",
			AcrLevel:          "urn:goiabada:pwd",
			AuthMethods:       []string{"pwd"},
			AuthenticatedAt:   now,
			Nonce:             "test-nonce",
			SessionIdentifier: "test-session",
		}

		token, err := tokenIssuer.generateAccessTokenCore(context.Background(), nil, settings, input, now, privKey, "key-id")
		assert.NoError(t, err)

		claims := verifyAndDecodeToken(t, token, publicKeyBytes)
		assert.Equal(t, "test-nonce", claims["nonce"])
		assert.Equal(t, "test-session", claims["sid"])
	})

	t.Run("Without nonce and sid", func(t *testing.T) {
		input := &tokenGenerationInput{
			User: &models.User{
				Subject: userSubject,
			},
			Client: &models.Client{
				ClientIdentifier: "test-client",
			},
			Scope:           "resource:read",
			AcrLevel:        "urn:goiabada:pwd",
			AuthMethods:     []string{"pwd"},
			AuthenticatedAt: now,
			Nonce:           "",
		}

		token, err := tokenIssuer.generateAccessTokenCore(context.Background(), nil, settings, input, now, privKey, "key-id")
		assert.NoError(t, err)

		claims := verifyAndDecodeToken(t, token, publicKeyBytes)
		_, hasNonce := claims["nonce"]
		_, hasSid := claims["sid"]
		assert.False(t, hasNonce, "nonce should not be present when empty")
		assert.False(t, hasSid, "sid should not be present when empty")
	})
}

// TestGenerateIdTokenCore_WithAtHash tests at_hash claim for implicit flow
func TestGenerateIdTokenCore_WithAtHash(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600,
	}

	now := time.Now().UTC()
	userSubject := fake.UUID()

	t.Run("With access token - at_hash included", func(t *testing.T) {
		input := &tokenGenerationInput{
			User: &models.User{
				Subject:   userSubject,
				UpdatedAt: sql.NullTime{Time: now, Valid: true},
			},
			Client: &models.Client{
				ClientIdentifier: "test-client",
			},
			Scope:           "openid",
			AcrLevel:        "urn:goiabada:pwd",
			AuthMethods:     []string{"pwd"},
			AuthenticatedAt: now,
			AccessToken:     "fake-access-token-for-hash",
		}

		token, err := tokenIssuer.generateIdTokenCore(context.Background(), nil, settings, input, now, privKey, "key-id")
		assert.NoError(t, err)

		claims := verifyAndDecodeToken(t, token, publicKeyBytes)
		atHash, hasAtHash := claims["at_hash"]
		assert.True(t, hasAtHash, "at_hash should be present when access token is provided")
		assert.NotEmpty(t, atHash)
	})

	t.Run("Without access token - no at_hash", func(t *testing.T) {
		input := &tokenGenerationInput{
			User: &models.User{
				Subject:   userSubject,
				UpdatedAt: sql.NullTime{Time: now, Valid: true},
			},
			Client: &models.Client{
				ClientIdentifier: "test-client",
			},
			Scope:           "openid",
			AcrLevel:        "urn:goiabada:pwd",
			AuthMethods:     []string{"pwd"},
			AuthenticatedAt: now,
			AccessToken:     "",
		}

		token, err := tokenIssuer.generateIdTokenCore(context.Background(), nil, settings, input, now, privKey, "key-id")
		assert.NoError(t, err)

		claims := verifyAndDecodeToken(t, token, publicKeyBytes)
		_, hasAtHash := claims["at_hash"]
		assert.False(t, hasAtHash, "at_hash should not be present when access token is empty")
	})
}

// TestGenerateIdTokenCore_GroupsAndAttributes tests groups/attributes with IncludeInIdToken
func TestGenerateIdTokenCore_GroupsAndAttributes(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600,
	}

	now := time.Now().UTC()
	userSubject := fake.UUID()

	user := &models.User{
		Subject:   userSubject,
		UpdatedAt: sql.NullTime{Time: now, Valid: true},
		Groups: []models.Group{
			{GroupIdentifier: "group1", IncludeInIdToken: true, IncludeInAccessToken: false},
			{GroupIdentifier: "group2", IncludeInIdToken: false, IncludeInAccessToken: true},
			{GroupIdentifier: "group3", IncludeInIdToken: true, IncludeInAccessToken: true},
		},
		Attributes: []models.UserAttribute{
			{Key: "attr1", Value: "value1", IncludeInIdToken: true, IncludeInAccessToken: false},
			{Key: "attr2", Value: "value2", IncludeInIdToken: false, IncludeInAccessToken: true},
		},
	}

	input := &tokenGenerationInput{
		User: user,
		Client: &models.Client{
			ClientIdentifier: "test-client",
		},
		Scope:           "openid groups attributes",
		AcrLevel:        "urn:goiabada:pwd",
		AuthMethods:     []string{"pwd"},
		AuthenticatedAt: now,
	}

	token, err := tokenIssuer.generateIdTokenCore(context.Background(), nil, settings, input, now, privKey, "key-id")
	assert.NoError(t, err)

	claims := verifyAndDecodeToken(t, token, publicKeyBytes)

	// Check groups - only IncludeInIdToken=true
	groups := claims["groups"].([]interface{})
	assert.Len(t, groups, 2)
	assert.Contains(t, groups, "group1")
	assert.Contains(t, groups, "group3")
	assert.NotContains(t, groups, "group2")

	// Check attributes - only IncludeInIdToken=true
	attrs := claims["attributes"].(map[string]interface{})
	assert.Equal(t, "value1", attrs["attr1"])
	_, hasAttr2 := attrs["attr2"]
	assert.False(t, hasAttr2)
}

// TestTokenGenerationInput_AllFieldsCopied ensures all fields are properly copied by factory functions
func TestTokenGenerationInput_AllFieldsCopied(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	now := time.Now().UTC()
	authTime := now.Add(-10 * time.Minute)
	userSubject := fake.UUID()

	// Test with Code - ensure all fields transferred
	code := &models.Code{
		Scope:             "openid profile email groups attributes",
		AcrLevel:          "urn:goiabada:level2_mandatory",
		AuthMethods:       "pwd otp",
		AuthenticatedAt:   authTime,
		SessionIdentifier: "session-xyz",
		Nonce:             "nonce-123",
		User: models.User{
			Id:      42,
			Subject: userSubject,
		},
		Client: models.Client{
			Id:               99,
			ClientIdentifier: "full-test-client",
		},
	}

	input := tokenIssuer.createTokenInputFromCode(code)

	// Verify all fields
	assert.Same(t, &code.User, input.User, "User pointer should be same")
	assert.Same(t, &code.Client, input.Client, "Client pointer should be same")
	assert.Equal(t, code.Scope, input.Scope)
	assert.Equal(t, code.AcrLevel, input.AcrLevel)
	assert.Equal(t, []string{"pwd", "otp"}, input.AuthMethods)
	assert.Equal(t, code.AuthenticatedAt, input.AuthenticatedAt)
	assert.Equal(t, code.SessionIdentifier, input.SessionIdentifier)
	assert.Equal(t, code.Nonce, input.Nonce)
	assert.Empty(t, input.AccessToken)
}

// TestGenerateAccessTokenCore_ClientOverrideExpiration tests client-specific token expiration
func TestGenerateAccessTokenCore_ClientOverrideExpiration(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	settings := &models.Settings{
		Issuer:                   "https://test-issuer.com",
		TokenExpirationInSeconds: 600, // Default 10 minutes
	}

	now := time.Now().UTC()
	userSubject := fake.UUID()

	t.Run("Uses client override when set", func(t *testing.T) {
		input := &tokenGenerationInput{
			User: &models.User{
				Subject: userSubject,
			},
			Client: &models.Client{
				ClientIdentifier:         "override-client",
				TokenExpirationInSeconds: 1800, // 30 minutes override
			},
			Scope:           "resource:read",
			AcrLevel:        "urn:goiabada:pwd",
			AuthMethods:     []string{"pwd"},
			AuthenticatedAt: now,
		}

		token, err := tokenIssuer.generateAccessTokenCore(context.Background(), nil, settings, input, now, privKey, "key-id")
		assert.NoError(t, err)

		claims := verifyAndDecodeToken(t, token, publicKeyBytes)
		exp := int64(claims["exp"].(float64))
		iat := int64(claims["iat"].(float64))
		assert.Equal(t, int64(1800), exp-iat, "Token should expire in 1800 seconds (client override)")
	})

	t.Run("Uses settings default when client not set", func(t *testing.T) {
		input := &tokenGenerationInput{
			User: &models.User{
				Subject: userSubject,
			},
			Client: &models.Client{
				ClientIdentifier:         "default-client",
				TokenExpirationInSeconds: 0, // Not set
			},
			Scope:           "resource:read",
			AcrLevel:        "urn:goiabada:pwd",
			AuthMethods:     []string{"pwd"},
			AuthenticatedAt: now,
		}

		token, err := tokenIssuer.generateAccessTokenCore(context.Background(), nil, settings, input, now, privKey, "key-id")
		assert.NoError(t, err)

		claims := verifyAndDecodeToken(t, token, publicKeyBytes)
		exp := int64(claims["exp"].(float64))
		iat := int64(claims["iat"].(float64))
		assert.Equal(t, int64(600), exp-iat, "Token should expire in 600 seconds (settings default)")
	})
}

// TestGenerateAccessTokenCore_OIDCClaimsInAccessToken tests includeOpenIDConnectClaimsInAccessToken setting
func TestGenerateAccessTokenCore_OIDCClaimsInAccessToken(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	now := time.Now().UTC()
	userSubject := fake.UUID()

	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()

	t.Run("Global setting ON - includes OIDC claims", func(t *testing.T) {
		settings := &models.Settings{
			Issuer:                                  "https://test-issuer.com",
			TokenExpirationInSeconds:                600,
			IncludeOpenIDConnectClaimsInAccessToken: true,
		}

		input := &tokenGenerationInput{
			User: &models.User{
				Subject:   userSubject,
				Email:     "test@example.com",
				UpdatedAt: sql.NullTime{Time: now, Valid: true},
			},
			Client: &models.Client{
				ClientIdentifier: "test-client",
			},
			Scope:           "openid email resource:read",
			AcrLevel:        "urn:goiabada:pwd",
			AuthMethods:     []string{"pwd"},
			AuthenticatedAt: now,
		}

		token, err := tokenIssuer.generateAccessTokenCore(context.Background(), nil, settings, input, now, privKey, "key-id")
		assert.NoError(t, err)

		claims := verifyAndDecodeToken(t, token, publicKeyBytes)
		assert.Equal(t, "test@example.com", claims["email"])
	})

	t.Run("Global setting OFF - no OIDC claims", func(t *testing.T) {
		settings := &models.Settings{
			Issuer:                                  "https://test-issuer.com",
			TokenExpirationInSeconds:                600,
			IncludeOpenIDConnectClaimsInAccessToken: false,
		}

		input := &tokenGenerationInput{
			User: &models.User{
				Subject:   userSubject,
				Email:     "test@example.com",
				UpdatedAt: sql.NullTime{Time: now, Valid: true},
			},
			Client: &models.Client{
				ClientIdentifier: "test-client",
			},
			Scope:           "openid email resource:read",
			AcrLevel:        "urn:goiabada:pwd",
			AuthMethods:     []string{"pwd"},
			AuthenticatedAt: now,
		}

		token, err := tokenIssuer.generateAccessTokenCore(context.Background(), nil, settings, input, now, privKey, "key-id")
		assert.NoError(t, err)

		claims := verifyAndDecodeToken(t, token, publicKeyBytes)
		_, hasEmail := claims["email"]
		assert.False(t, hasEmail, "email should not be in access token when OIDC claims disabled")
	})

	t.Run("Client override ON overrides global OFF", func(t *testing.T) {
		settings := &models.Settings{
			Issuer:                                  "https://test-issuer.com",
			TokenExpirationInSeconds:                600,
			IncludeOpenIDConnectClaimsInAccessToken: false,
		}

		input := &tokenGenerationInput{
			User: &models.User{
				Subject:   userSubject,
				Email:     "test@example.com",
				UpdatedAt: sql.NullTime{Time: now, Valid: true},
			},
			Client: &models.Client{
				ClientIdentifier:                        "override-client",
				IncludeOpenIDConnectClaimsInAccessToken: "on",
			},
			Scope:           "openid email resource:read",
			AcrLevel:        "urn:goiabada:pwd",
			AuthMethods:     []string{"pwd"},
			AuthenticatedAt: now,
		}

		token, err := tokenIssuer.generateAccessTokenCore(context.Background(), nil, settings, input, now, privKey, "key-id")
		assert.NoError(t, err)

		claims := verifyAndDecodeToken(t, token, publicKeyBytes)
		assert.Equal(t, "test@example.com", claims["email"])
	})

	t.Run("Client override OFF overrides global ON", func(t *testing.T) {
		settings := &models.Settings{
			Issuer:                                  "https://test-issuer.com",
			TokenExpirationInSeconds:                600,
			IncludeOpenIDConnectClaimsInAccessToken: true,
		}

		input := &tokenGenerationInput{
			User: &models.User{
				Subject:   userSubject,
				Email:     "test@example.com",
				UpdatedAt: sql.NullTime{Time: now, Valid: true},
			},
			Client: &models.Client{
				ClientIdentifier:                        "override-client",
				IncludeOpenIDConnectClaimsInAccessToken: "off",
			},
			Scope:           "openid email resource:read",
			AcrLevel:        "urn:goiabada:pwd",
			AuthMethods:     []string{"pwd"},
			AuthenticatedAt: now,
		}

		token, err := tokenIssuer.generateAccessTokenCore(context.Background(), nil, settings, input, now, privKey, "key-id")
		assert.NoError(t, err)

		claims := verifyAndDecodeToken(t, token, publicKeyBytes)
		_, hasEmail := claims["email"]
		assert.False(t, hasEmail, "email should not be in access token when client override is off")
	})
}

// TestClaimMapper_CarriesTheCallersContext is the claim path's arm of #386's seam 4. It is the
// one place a token's claims are assembled from a database read, and the read is three hops
// below the entry point that holds the request's context, so a hop that dropped it would be
// invisible at every other seam.
//
// It drives the mapper this package hands its context to rather than a method of its own, since
// #387 moved the claim block to authserver/internal/userclaims. What it holds here is the wiring
// claimMapper performs -- this issuer's port, this issuer's base URL, and the caller's context
// reaching the port through both -- which is exactly what the private method used to do.
//
// The reject arm is the same call without the profile scope: no picture claim is owed, so the
// port is not reached and there is no context to carry.
func TestClaimMapper_CarriesTheCallersContext(t *testing.T) {
	type marker struct{}
	ctx := context.WithValue(context.Background(), marker{}, "the caller's own")
	callersContext := mock.MatchedBy(func(got context.Context) bool {
		return got.Value(marker{}) == "the caller's own"
	})

	user := &models.User{Id: 42, Subject: "sub-42", GivenName: "Ada", FamilyName: "Lovelace"}

	t.Run("the profile scope reads the picture flag under the caller's context", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockDB.On("UserHasProfilePicture", callersContext, mock.Anything, int64(42)).Return(true, nil).Once()

		issuer := NewTokenIssuer(mockDB, "https://auth.example.com", testDataCipher, nil)
		claims := jwt.MapClaims{}
		issuer.claimMapper(userclaims.InclusionIdToken).AddOpenIDConnectClaims(ctx, nil, claims, user, []string{"openid", "profile"})

		assert.Equal(t, "https://auth.example.com/userinfo/picture/sub-42", claims["picture"])
		assert.Equal(t, "https://auth.example.com/account/profile", claims["profile"])
		mockDB.AssertExpectations(t)
	})

	t.Run("without the profile scope the port is not reached", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)

		issuer := NewTokenIssuer(mockDB, "https://auth.example.com", testDataCipher, nil)
		claims := jwt.MapClaims{}
		issuer.claimMapper(userclaims.InclusionIdToken).AddOpenIDConnectClaims(ctx, nil, claims, user, []string{"openid", "email"})

		assert.NotContains(t, claims, "picture")
		mockDB.AssertNotCalled(t, "UserHasProfilePicture", mock.Anything, mock.Anything, mock.Anything)
	})
}

// ============================================================================
// Claim characterization for #387
//
// The three tests below are issuance's half of the characterization decision 6 of #387
// requires before the claims mapper that will serve this package and /userinfo from one
// implementation. Each names a place where the two deliberately disagree today, and the
// counterpart case lives in handlers/handler_userinfo_test.go. They are written against the
// public generation path rather than against the claim block itself, because part of what
// diverges is the scope slice each token type hands it.
// ============================================================================

// issueCharacterizationTokens drives mintAuthorizationCodeTokens once for one scope string
// and returns the decoded ID and access token claims. Both OIDC claim settings are on, so the
// two token types differ only where the code makes them differ.
//
// The profile-picture port is registered only for a scope that carries "profile", so a lookup
// from any other arm fails the case as an unexpected call.
func issueCharacterizationTokens(t *testing.T, scope string, baseURL string, user *models.User,
	hasProfilePicture bool) (jwt.MapClaims, jwt.MapClaims) {
	t.Helper()

	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, baseURL, testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInIdToken:     true,
		IncludeOpenIDConnectClaimsInAccessToken: true,
	}
	ctx := context.Background()

	now := time.Now().UTC()
	sessionIdentifier := "test-session-characterization"

	code := &models.Code{
		Id:                1,
		ClientId:          1,
		UserId:            user.Id,
		Scope:             scope,
		AuthenticatedAt:   now.Add(-1 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{Id: 1, ClientIdentifier: "characterization-client"}

	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, &code.User).Return(nil)
	if slices.Contains(strings.Split(scope, " "), "profile") {
		mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, user.Id).
			Return(hasProfilePicture, nil)
	}
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).
		Return(&models.UserSession{
			Id:           1,
			UserId:       user.Id,
			Started:      now.Add(-30 * time.Minute),
			LastAccessed: now.Add(-5 * time.Minute),
		}, nil)
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).
		Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, getTestPrivateKey(t)),
	}, nil)

	response, err := tokenIssuer.mintAuthorizationCodeTokens(ctx, settings, code)
	require.NoError(t, err)
	require.NotNil(t, response)

	publicKeyBytes := getTestPublicKey(t)
	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)

	mockDB.AssertExpectations(t)
	return idClaims, accessClaims
}

// updated_at is a profile-scope claim at both token types, which is what OIDC Core 5.4 lists it
// as and what this repository's own documentation has always said it is. This test was written by
// #387 stage 1 as a characterization: it recorded issuance's gate, "any scope beyond openid
// alone", and the access token's extra row on top of it, where a lone openid still carried the
// claim because generateAccessTokenCore then appended authserver:userinfo to the scope slice for
// the audience before the claim block read it. Both were defects rather than choices, and the rows
// below are what each grant carries now that the gate is the profile scope at all three sites.
//
// The two rows that changed are the tripwire the characterization was for: "openid alone" stopped
// disagreeing between the two token types, and "openid email" stopped emitting a profile claim for
// a grant that was never given the profile scope.
func TestClaims_UpdatedAtRidesWithTheProfileScope(t *testing.T) {
	tests := []struct {
		name                    string
		scope                   string
		idTokenHasUpdatedAt     bool
		accessTokenHasUpdatedAt bool
	}{
		{
			// Was id=false, access=true: the same grant, two answers, because only one of the
			// two slices had authserver:userinfo appended to it.
			name:                    "openid alone",
			scope:                   "openid",
			idTokenHasUpdatedAt:     false,
			accessTokenHasUpdatedAt: false,
		},
		{
			// Was true/true: a profile claim with no profile scope granted, on the default path,
			// since IncludeOpenIDConnectClaimsInIdToken is seeded on.
			name:                    "openid email",
			scope:                   "openid email",
			idTokenHasUpdatedAt:     false,
			accessTokenHasUpdatedAt: false,
		},
		{
			name:                    "openid profile",
			scope:                   "openid profile",
			idTokenHasUpdatedAt:     true,
			accessTokenHasUpdatedAt: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			updatedAt := time.Now().UTC().Add(-1 * time.Minute)
			user := &models.User{
				Id:            1,
				Subject:       fake.UUID(),
				Email:         "characterization@example.com",
				EmailVerified: true,
				GivenName:     "Test",
				FamilyName:    "User",
				UpdatedAt:     sql.NullTime{Time: updatedAt, Valid: true},
			}

			idClaims, accessClaims := issueCharacterizationTokens(t, test.scope,
				"http://localhost:8081", user, false)

			if test.idTokenHasUpdatedAt {
				assert.Equal(t, float64(updatedAt.Unix()), idClaims["updated_at"])
			} else {
				assert.NotContains(t, idClaims, "updated_at")
			}

			if test.accessTokenHasUpdatedAt {
				assert.Equal(t, float64(updatedAt.Unix()), accessClaims["updated_at"])
			} else {
				assert.NotContains(t, accessClaims, "updated_at")
			}
		})
	}
}

// Divergence 3, issuance's side: the include predicate is per token type here, where /userinfo
// reads IncludeInIdToken at all three of its filter sites. A mapper taking one predicate would
// have to pick a token type, which is why #387 makes the predicate an input.
func TestClaimCharacterization_GroupsAndAttributesFollowThePerTokenTypeFlag(t *testing.T) {
	idTokenGroup := models.Group{
		Id:               1,
		GroupIdentifier:  "id-token-group",
		IncludeInIdToken: true, IncludeInAccessToken: false,
		Attributes: []models.GroupAttribute{
			{Key: "idTokenGroupAttr", Value: "idTokenGroupValue",
				IncludeInIdToken: true, IncludeInAccessToken: false},
		},
	}
	accessTokenGroup := models.Group{
		Id:               2,
		GroupIdentifier:  "access-token-group",
		IncludeInIdToken: false, IncludeInAccessToken: true,
		Attributes: []models.GroupAttribute{
			{Key: "accessTokenGroupAttr", Value: "accessTokenGroupValue",
				IncludeInIdToken: false, IncludeInAccessToken: true},
		},
	}

	user := &models.User{
		Id:      1,
		Subject: fake.UUID(),
		Groups:  []models.Group{idTokenGroup, accessTokenGroup},
		Attributes: []models.UserAttribute{
			{Key: "idTokenAttr", Value: "idTokenValue",
				IncludeInIdToken: true, IncludeInAccessToken: false},
			{Key: "accessTokenAttr", Value: "accessTokenValue",
				IncludeInIdToken: false, IncludeInAccessToken: true},
		},
	}

	idClaims, accessClaims := issueCharacterizationTokens(t, "openid groups attributes",
		"http://localhost:8081", user, false)

	idGroups, ok := idClaims["groups"].([]interface{})
	require.True(t, ok)
	assert.ElementsMatch(t, []interface{}{"id-token-group"}, idGroups)
	assert.Equal(t, map[string]interface{}{
		"idTokenAttr":      "idTokenValue",
		"idTokenGroupAttr": "idTokenGroupValue",
	}, idClaims["attributes"])

	accessGroups, ok := accessClaims["groups"].([]interface{})
	require.True(t, ok)
	assert.ElementsMatch(t, []interface{}{"access-token-group"}, accessGroups)
	assert.Equal(t, map[string]interface{}{
		"accessTokenAttr":      "accessTokenValue",
		"accessTokenGroupAttr": "accessTokenGroupValue",
	}, accessClaims["attributes"])
}

// Divergence 2, issuance's side: the base URL is the one injected into NewTokenIssuer, as
// /userinfo's is the one its handler was handed (#434). Nothing in this package loads the
// process configuration, so a mapper that read the base URL from anywhere but its input would
// fail this case rather than pass it silently.
func TestClaimCharacterization_ProfileAndPictureComeFromTheInjectedBaseURL(t *testing.T) {
	sub := fake.UUID()
	user := &models.User{
		Id:         1,
		Subject:    sub,
		GivenName:  "Test",
		FamilyName: "User",
		UpdatedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}

	idClaims, accessClaims := issueCharacterizationTokens(t, "openid profile",
		"https://injected.example", user, true)

	for _, claims := range []jwt.MapClaims{idClaims, accessClaims} {
		assert.Equal(t, "https://injected.example/account/profile", claims["profile"])
		assert.Equal(t, "https://injected.example/userinfo/picture/"+sub, claims["picture"])
	}
}

// scopeIsTheGrantIssue is what one flow of TestGenerateTokenResponse_ScopeIsTheGrant issued.
type scopeIsTheGrantIssue struct {
	reportedScope string
	accessToken   string
	idToken       string
	refreshToken  string
	storedRefresh *models.RefreshToken
}

// issueForScopeIsTheGrant runs one flow for one grant on a strict mock stubbed with the loads that
// flow makes. storedRefreshScope is the scope already recorded on the parent refresh token, read only
// by the two refresh flows; the code's scope and the ROPC grant are always the grant itself.
func issueForScopeIsTheGrant(t *testing.T, flow string, grant string, storedRefreshScope string) scopeIsTheGrantIssue {
	t.Helper()

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
	now := time.Now().UTC()
	sessionIdentifier := "scope-is-the-grant-session"

	user := models.User{
		Id:      1,
		Subject: fake.UUID(),
		Email:   "grant@example.com",
		Groups:  []models.Group{{GroupIdentifier: "grant-group", IncludeInIdToken: true, IncludeInAccessToken: true}},
	}
	client := models.Client{Id: 1, ClientIdentifier: "grant-client"}

	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, getTestPrivateKey(t)),
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	// Only a grant with the profile scope asks for the picture, and only a session-bound refresh
	// token asks for the session: both depend on the grant, not the flow.
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, user.Id).Return(false, nil).Maybe()
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(&models.UserSession{
		Id:      1,
		UserId:  user.Id,
		Started: now.Add(-5 * time.Minute),
	}, nil).Maybe()

	var issued scopeIsTheGrantIssue
	captureRefresh := func() {
		mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).
			Run(func(args mock.Arguments) {
				issued.storedRefresh = args.Get(2).(*models.RefreshToken)
			}).
			Return(nil)
	}

	code := &models.Code{
		Id:                1,
		ClientId:          client.Id,
		UserId:            user.Id,
		Scope:             grant,
		AuthenticatedAt:   now.Add(-time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:level1",
		AuthMethods:       "pwd",
		Client:            client,
		User:              user,
	}
	parent := &models.RefreshToken{
		Id:                   1,
		RefreshTokenJti:      "parent-jti",
		FirstRefreshTokenJti: "first-jti",
		UserId:               sql.NullInt64{Int64: user.Id, Valid: true},
		ClientId:             sql.NullInt64{Int64: client.Id, Valid: true},
		AuthenticatedAt:      sql.NullTime{Time: now.Add(-time.Hour), Valid: true},
		Scope:                storedRefreshScope,
		RefreshTokenType:     TokenTypeOffline.String(),
		MaxLifetime:          sql.NullTime{Time: now.Add(time.Hour), Valid: true},
		User:                 user,
		Client:               client,
	}
	implicit := &ImplicitGrantInput{
		Client:            &client,
		User:              &user,
		Scope:             grant,
		AcrLevel:          "urn:goiabada:level1",
		AuthMethods:       "pwd",
		SessionIdentifier: sessionIdentifier,
		AuthenticatedAt:   now.Add(-time.Minute),
	}

	switch flow {
	case "auth code exchange":
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
		captureRefresh()
		response, err := tokenIssuer.mintAuthorizationCodeTokens(ctx, settings, code)
		require.NoError(t, err)
		issued.reportedScope, issued.accessToken, issued.idToken, issued.refreshToken =
			response.Scope, response.AccessToken, response.IdToken, response.RefreshToken
	case "auth code refresh":
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
		captureRefresh()
		response, err := tokenIssuer.mintCodeRefreshTokens(ctx, nil, settings, code, parent, "")
		require.NoError(t, err)
		issued.reportedScope, issued.accessToken, issued.idToken, issued.refreshToken =
			response.Scope, response.AccessToken, response.IdToken, response.RefreshToken
	case "implicit token", "implicit id_token token", "implicit id_token":
		issueAccessToken := flow != "implicit id_token"
		issueIdToken := flow != "implicit token"
		armImplicitTransaction(mockDB, implicit.SessionIdentifier)
		response, err := tokenIssuer.IssueImplicitTx(ctx, settings, implicit, issueAccessToken, issueIdToken)
		require.NoError(t, err)
		issued.reportedScope, issued.accessToken, issued.idToken = response.Scope, response.AccessToken, response.IdToken
	case "ROPC":
		captureRefresh()
		response, err := tokenIssuer.IssuePasswordGrant(ctx, settings, &ROPCGrantInput{Client: &client, User: &user, Scope: grant})
		require.NoError(t, err)
		issued.reportedScope, issued.accessToken, issued.idToken, issued.refreshToken =
			response.Scope, response.AccessToken, response.IdToken, response.RefreshToken
	case "ROPC refresh":
		mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, parent).Return(nil)
		mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, parent).Return(nil)
		captureRefresh()
		response, err := tokenIssuer.mintROPCRefreshTokens(ctx, nil, settings, parent, "")
		require.NoError(t, err)
		issued.reportedScope, issued.accessToken, issued.idToken, issued.refreshToken =
			response.Scope, response.AccessToken, response.IdToken, response.RefreshToken
	default:
		t.Fatalf("unknown flow %q", flow)
	}
	return issued
}

// audienceOf reads aud as a list whether the token wrote one value or several.
func audienceOf(t *testing.T, claims jwt.MapClaims) []string {
	t.Helper()
	switch aud := claims["aud"].(type) {
	case string:
		return []string{aud}
	case []interface{}:
		values := make([]string, 0, len(aud))
		for _, v := range aud {
			values = append(values, v.(string))
		}
		return values
	default:
		t.Fatalf("aud is neither a string nor an array: %#v", claims["aud"])
		return nil
	}
}

// Every flow reports, and writes into the access token's scope claim, exactly the grant. Until #449
// any claim scope appended authserver:userinfo to both, a scope the client never asked for, which a
// refresh echoing the reported scope was then refused for (RFC 6749 section 6 lets a refresh request
// any scope "originally granted"). /userinfo gates on openid now, so the append bought nothing. The
// audience is unchanged: a claim scope still names authserver, whose /userinfo answers it, which a
// groups-only grant needs since it may name no other audience.
func TestGenerateTokenResponse_ScopeIsTheGrant(t *testing.T) {
	grants := []string{
		"openid",
		"openid profile email resource1:read",
		// A claim scope without openid, admitted as before (#449 decision 2).
		"groups",
		// No claim scope at all.
		"resource1:read offline_access",
	}
	flows := []string{"auth code exchange", "auth code refresh", "implicit token", "ROPC", "ROPC refresh"}

	publicKeyBytes := getTestPublicKey(t)

	for _, grant := range grants {
		grantScopes := strings.Split(grant, " ")
		hasClaimScope := slices.ContainsFunc(grantScopes, func(s string) bool {
			return slices.Contains([]string{"openid", "profile", "email", "address", "phone", "groups", "attributes"}, s)
		})
		for _, flow := range flows {
			t.Run(flow+"/"+grant, func(t *testing.T) {
				issued := issueForScopeIsTheGrant(t, flow, grant, grant)

				assert.Equal(t, grant, issued.reportedScope, "reported scope")
				accessClaims := verifyAndDecodeToken(t, issued.accessToken, publicKeyBytes)
				assert.Equal(t, grant, accessClaims["scope"], "access token scope claim")

				audience := audienceOf(t, accessClaims)
				assert.Equal(t, hasClaimScope, slices.Contains(audience, builtin.AuthServerResourceIdentifier),
					"aud names authserver exactly when the grant has a claim scope: %v", audience)
				assert.Equal(t, slices.Contains(grantScopes, "resource1:read"), slices.Contains(audience, "resource1"),
					"aud names resource1 exactly when the grant does: %v", audience)

				if slices.Contains(grantScopes, "groups") {
					assert.Equal(t, []interface{}{"grant-group"}, accessClaims["groups"])
				}

				if flow != "implicit token" {
					assert.Equal(t, slices.Contains(grantScopes, "openid"), issued.idToken != "",
						"an ID token is issued exactly when the grant carries openid")
				}

				if flow == "auth code exchange" {
					refreshClaims := verifyAndDecodeToken(t, issued.refreshToken, publicKeyBytes)
					assert.Equal(t, grant, refreshClaims["scope"], "refresh token scope claim")
					require.NotNil(t, issued.storedRefresh)
					assert.Equal(t, grant, issued.storedRefresh.Scope, "stored refresh token scope")
				}
			})
		}
	}

	// The two implicit response types that issue an ID token are reachable only with openid, so
	// they run on the openid grants alone. The id_token row issues no access token: it is here
	// because the reported scope's two assignments are one now.
	for _, grant := range []string{"openid", "openid profile email resource1:read"} {
		for _, flow := range []string{"implicit id_token token", "implicit id_token"} {
			t.Run(flow+"/"+grant, func(t *testing.T) {
				issued := issueForScopeIsTheGrant(t, flow, grant, grant)

				assert.Equal(t, grant, issued.reportedScope, "reported scope")
				assert.NotEmpty(t, issued.idToken)
				if flow == "implicit id_token" {
					assert.Empty(t, issued.accessToken)
					return
				}
				accessClaims := verifyAndDecodeToken(t, issued.accessToken, publicKeyBytes)
				assert.Equal(t, grant, accessClaims["scope"], "access token scope claim")
				assert.Contains(t, audienceOf(t, accessClaims), builtin.AuthServerResourceIdentifier)
			})
		}
	}

	// An auth-code refresh token issued before #449 recorded the decorated scope. The refresh reports
	// and issues the code's grant, and copies the stored scope onto the new refresh token unchanged,
	// because RFC 6749 section 6 requires the new refresh token's scope to be identical; nothing reads
	// it for an auth-code grant, whose validator consults the code's scope.
	t.Run("auth code refresh/legacy stored scope carrying authserver:userinfo", func(t *testing.T) {
		legacyScope := "openid authserver:userinfo"
		issued := issueForScopeIsTheGrant(t, "auth code refresh", "openid", legacyScope)

		assert.Equal(t, "openid", issued.reportedScope)
		accessClaims := verifyAndDecodeToken(t, issued.accessToken, publicKeyBytes)
		assert.Equal(t, "openid", accessClaims["scope"])
		assert.NotEmpty(t, issued.idToken)

		refreshClaims := verifyAndDecodeToken(t, issued.refreshToken, publicKeyBytes)
		assert.Equal(t, legacyScope, refreshClaims["scope"])
		require.NotNil(t, issued.storedRefresh)
		assert.Equal(t, legacyScope, issued.storedRefresh.Scope)
	})
}
