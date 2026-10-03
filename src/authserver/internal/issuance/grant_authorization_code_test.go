package issuance

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/uuid/uuidtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMintAuthorizationCodeTokens_FullOpenIDConnect(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &record.Settings{
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
	sub := fake.UUID()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &record.Code{
		Id:                1,
		ClientId:          1,
		UserId:            1,
		Scope:             "openid profile email address phone groups attributes offline_access",
		Nonce:             "test-nonce",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd:otp_mandatory",
		AuthMethods:       "pwd otp",
	}
	client := &record.Client{
		Id:                                      1,
		ClientIdentifier:                        "test-client",
		TokenExpirationInSeconds:                900,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 7200,
	}
	user := &record.User{
		Id:                  1,
		UpdatedAt:           sql.NullTime{Time: time.Now().Add(-1 * time.Minute), Valid: true},
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
		AddressLine2:        "apartment 1",
		AddressLocality:     "Test City",
		AddressRegion:       "Test Region",
		AddressPostalCode:   "12345",
		AddressCountry:      "Test Country",
		Groups: []record.Group{
			{GroupIdentifier: "group1", IncludeInIdToken: true, IncludeInAccessToken: true},
			{GroupIdentifier: "group2", IncludeInIdToken: true, IncludeInAccessToken: false},
			{GroupIdentifier: "group3", IncludeInIdToken: false, IncludeInAccessToken: true},
			{GroupIdentifier: "group4", IncludeInIdToken: true, IncludeInAccessToken: true},
		},
		Attributes: []record.UserAttribute{
			{Key: "attr1", Value: "value1", IncludeInIdToken: true, IncludeInAccessToken: true},
			{Key: "attr2", Value: "value2", IncludeInIdToken: true, IncludeInAccessToken: false},
			{Key: "attr3", Value: "value3", IncludeInIdToken: false, IncludeInAccessToken: true},
			{Key: "attr4", Value: "value4", IncludeInIdToken: true, IncludeInAccessToken: true},
		},
	}

	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, &code.User).Return(nil)
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, user.Id).Return(false, nil)
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*record.RefreshToken")).Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)

	response, err := tokenIssuer.mintAuthorizationCodeTokens(ctx, settings, code)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(900), response.ExpiresIn)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "openid profile email address phone groups attributes offline_access", response.Scope)
	assert.Equal(t, int64(3600), response.RefreshExpiresIn)

	// validate Id token --------------------------------------------

	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, idClaims["iss"])
	assert.Equal(t, user.Subject, idClaims["sub"])
	assert.Equal(t, client.ClientIdentifier, idClaims["aud"])
	assert.Equal(t, code.Nonce, idClaims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), idClaims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), idClaims["amr"])
	assert.Equal(t, sessionIdentifier, idClaims["sid"])

	assertTimeClaimWithinRange(t, idClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, idClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, idClaims, "exp", 900*time.Second, "exp should be 900 seconds from now")
	assertTimeClaimWithinRange(t, idClaims, "updated_at", -60*time.Second, "updated_at should be 60 seconds ago")
	assertTimeClaimWithinRange(t, idClaims, "auth_time", -300*time.Second, "auth_time should be 300 seconds ago")

	assert.Contains(t, idClaims, "auth_time")
	authTimeUnix := idClaims["auth_time"].(float64)
	authTime := time.Unix(int64(authTimeUnix), 0)
	assert.Equal(t, now.Add(-300*time.Second).Unix(), authTime.Unix(), fmt.Sprintf("auth_time should be 300 seconds ago: %s", authTime))

	_, err = uuidtest.Parse(idClaims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.FullName(), idClaims["name"])
	assert.Equal(t, user.GivenName, idClaims["given_name"])
	assert.Equal(t, user.MiddleName, idClaims["middle_name"])
	assert.Equal(t, user.FamilyName, idClaims["family_name"])
	assert.Equal(t, user.Nickname, idClaims["nickname"])
	assert.Equal(t, user.Username, idClaims["preferred_username"])
	assert.Equal(t, "http://localhost:8081/account/profile", idClaims["profile"])
	assert.Equal(t, user.Website, idClaims["website"])
	assert.Equal(t, user.Gender, idClaims["gender"])
	assert.Equal(t, "1990-01-01", idClaims["birthdate"])
	assert.Equal(t, user.ZoneInfo, idClaims["zoneinfo"])
	assert.Equal(t, user.Locale, idClaims["locale"])
	assert.NotEmpty(t, idClaims["updated_at"])
	assert.Equal(t, user.Email, idClaims["email"])
	assert.Equal(t, user.EmailVerified, idClaims["email_verified"])
	assert.Equal(t, user.PhoneNumber, idClaims["phone_number"])
	assert.Equal(t, user.PhoneNumberVerified, idClaims["phone_number_verified"])
	address, ok := idClaims["address"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, user.AddressLine1+"\r\n"+user.AddressLine2, address["street_address"])
	assert.Equal(t, user.AddressLocality, address["locality"])
	assert.Equal(t, user.AddressRegion, address["region"])
	assert.Equal(t, user.AddressPostalCode, address["postal_code"])
	assert.Equal(t, user.AddressCountry, address["country"])
	assert.Equal(t, "123 Test St\r\napartment 1\r\nTest City\r\nTest Region\r\n12345\r\nTest Country", address["formatted"])
	groups, ok := idClaims["groups"].([]interface{})
	assert.True(t, ok)
	assert.ElementsMatch(t, []string{"group1", "group2", "group4"}, groups)
	assert.Equal(t, 3, len(groups))
	attributes, ok := idClaims["attributes"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "value1", attributes["attr1"])
	assert.Equal(t, "value2", attributes["attr2"])
	assert.Equal(t, "value4", attributes["attr4"])
	assert.Equal(t, 3, len(attributes))

	// validate Access token --------------------------------------------

	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, user.Subject, accessClaims["sub"])
	assert.Equal(t, "authserver", accessClaims["aud"])
	assert.Equal(t, code.Nonce, accessClaims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), accessClaims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), accessClaims["amr"])
	// This grant includes offline_access, so its ACCESS token deliberately carries no sid:
	// an offline grant outlives the browser session, and binding its access tokens to a
	// session identifier the middleware will later fail to resolve is the defect #106
	// decision 9 fixes. The ID token above keeps sid, because RP-initiated logout matches
	// on it. Reversed from asserting presence; see TestAccessToken_SidEmission for the table.
	assert.NotContains(t, accessClaims, "sid")
	assert.Equal(t, "Bearer", accessClaims["typ"])

	assertTimeClaimWithinRange(t, accessClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, accessClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, accessClaims, "exp", 900*time.Second, "exp should be 900 seconds from now")
	assertTimeClaimWithinRange(t, accessClaims, "updated_at", -60*time.Second, "updated_at should be 60 seconds ago")
	assertTimeClaimWithinRange(t, accessClaims, "auth_time", -300*time.Second, "auth_time should be 300 seconds ago")

	_, err = uuidtest.Parse(accessClaims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.FullName(), accessClaims["name"])
	assert.Equal(t, user.GivenName, accessClaims["given_name"])
	assert.Equal(t, user.MiddleName, accessClaims["middle_name"])
	assert.Equal(t, user.FamilyName, accessClaims["family_name"])
	assert.Equal(t, user.Nickname, accessClaims["nickname"])
	assert.Equal(t, user.Username, accessClaims["preferred_username"])
	assert.Equal(t, "http://localhost:8081/account/profile", accessClaims["profile"])
	assert.Equal(t, user.Website, accessClaims["website"])
	assert.Equal(t, user.Gender, accessClaims["gender"])
	assert.Equal(t, "1990-01-01", accessClaims["birthdate"])
	assert.Equal(t, user.ZoneInfo, accessClaims["zoneinfo"])
	assert.Equal(t, user.Locale, accessClaims["locale"])
	assert.NotEmpty(t, accessClaims["updated_at"])
	assert.Equal(t, user.Email, accessClaims["email"])
	assert.Equal(t, user.EmailVerified, accessClaims["email_verified"])
	assert.Equal(t, user.PhoneNumber, accessClaims["phone_number"])
	assert.Equal(t, user.PhoneNumberVerified, accessClaims["phone_number_verified"])
	address, ok = accessClaims["address"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, user.AddressLine1+"\r\n"+user.AddressLine2, address["street_address"])
	assert.Equal(t, user.AddressLocality, address["locality"])
	assert.Equal(t, user.AddressRegion, address["region"])
	assert.Equal(t, user.AddressPostalCode, address["postal_code"])
	assert.Equal(t, user.AddressCountry, address["country"])
	assert.Equal(t, "123 Test St\r\napartment 1\r\nTest City\r\nTest Region\r\n12345\r\nTest Country", address["formatted"])
	groups, ok = accessClaims["groups"].([]interface{})
	assert.True(t, ok)
	assert.ElementsMatch(t, []string{"group1", "group3", "group4"}, groups)
	assert.Equal(t, 3, len(groups))
	attributes, ok = accessClaims["attributes"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "value1", attributes["attr1"])
	assert.Equal(t, "value3", attributes["attr3"])
	assert.Equal(t, "value4", attributes["attr4"])
	assert.Equal(t, 3, len(attributes))
	assert.Equal(t, "openid profile email address phone groups attributes offline_access", accessClaims["scope"])

	// validate Refresh token --------------------------------------------

	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, publicKeyBytes)
	assert.Equal(t, user.Subject, refreshClaims["sub"])
	assert.Equal(t, "https://test-issuer.com", refreshClaims["aud"])
	assert.Equal(t, "https://test-issuer.com", refreshClaims["iss"])
	assert.Equal(t, "Offline", refreshClaims["typ"])
	assert.Equal(t, "openid profile email address phone groups attributes offline_access", refreshClaims["scope"])

	assertTimeClaimWithinRange(t, refreshClaims, "exp", 3600*time.Second, "exp should be 3600 seconds from now")
	assertTimeClaimWithinRange(t, refreshClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "offline_access_max_lifetime", 7200*time.Second, "offline_access_max_lifetime should be 7200 seconds from now")

	_, err = uuidtest.Parse(refreshClaims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)
}

func TestMintAuthorizationCodeTokens_MinimalScope(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &record.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInIdToken:     true,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.Background()

	now := time.Now().UTC()
	sub := fake.UUID()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &record.Code{
		Id:                2,
		ClientId:          2,
		UserId:            2,
		Scope:             "openid",
		Nonce:             "minimal-nonce",
		AuthenticatedAt:   now.Add(-120 * time.Second), // Authenticated 2 minutes ago
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &record.Client{
		Id:               2,
		ClientIdentifier: "minimal-client",
	}
	user := &record.User{
		Id:      2,
		Subject: sub,
		Email:   "minimal@example.com",
	}

	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, &code.User).Return(nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(&record.UserSession{
		Id:           1,
		UserId:       1,
		Started:      now.Add(-30 * time.Minute),
		LastAccessed: now.Add(-5 * time.Minute),
	}, nil)
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*record.RefreshToken")).Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)

	response, err := tokenIssuer.mintAuthorizationCodeTokens(ctx, settings, code)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(600), response.ExpiresIn)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "openid", response.Scope)
	assert.InDelta(t, int64(600), response.RefreshExpiresIn, 1)

	// validate Id token --------------------------------------------

	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, "https://test-issuer.com", idClaims["iss"])
	assert.Equal(t, user.Subject, idClaims["sub"])
	assert.Equal(t, client.ClientIdentifier, idClaims["aud"])
	assert.Equal(t, code.Nonce, idClaims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), idClaims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), idClaims["amr"])
	assert.Equal(t, sessionIdentifier, idClaims["sid"])

	assertTimeClaimWithinRange(t, idClaims, "auth_time", -120*time.Second, "auth_time should be 2 minutes ago")
	assertTimeClaimWithinRange(t, idClaims, "exp", 600*time.Second, "exp should be 10 minutes in the future")
	assertTimeClaimWithinRange(t, idClaims, "iat", 0, "iat should be now")
	assertTimeClaimWithinRange(t, idClaims, "nbf", 0, "nbf should be now")

	_, err = uuidtest.Parse(idClaims["jti"].(string))
	assert.NoError(t, err)

	// validate Access token --------------------------------------------

	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, "https://test-issuer.com", accessClaims["iss"])
	assert.Equal(t, user.Subject, accessClaims["sub"])
	assert.Equal(t, code.Nonce, accessClaims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), accessClaims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), accessClaims["amr"])
	assert.Equal(t, sessionIdentifier, accessClaims["sid"])
	assert.Equal(t, "Bearer", accessClaims["typ"])
	assert.Equal(t, "openid", accessClaims["scope"])

	assertTimeClaimWithinRange(t, accessClaims, "auth_time", -120*time.Second, "auth_time should be 2 minutes ago")
	assertTimeClaimWithinRange(t, accessClaims, "exp", 600*time.Second, "exp should be 10 minutes in the future")
	assertTimeClaimWithinRange(t, accessClaims, "iat", 0, "iat should be now")
	assertTimeClaimWithinRange(t, accessClaims, "nbf", 0, "nbf should be now")

	_, err = uuidtest.Parse(accessClaims["jti"].(string))
	assert.NoError(t, err)

	// validate Refresh token --------------------------------------------

	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, publicKeyBytes)
	assert.Equal(t, user.Subject, refreshClaims["sub"])
	assert.Equal(t, "https://test-issuer.com", refreshClaims["aud"])
	assert.Equal(t, "Refresh", refreshClaims["typ"])
	assert.Equal(t, sessionIdentifier, refreshClaims["sid"])
	assert.Equal(t, "openid", refreshClaims["scope"])

	assertTimeClaimWithinRange(t, refreshClaims, "exp", 600*time.Second, "exp should be 10 minutes in the future")
	assertTimeClaimWithinRange(t, refreshClaims, "iat", 0, "iat should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "nbf", 0, "nbf should be now")

	_, err = uuidtest.Parse(refreshClaims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)
}

func TestMintAuthorizationCodeTokens_ClientOverrideAndMixedScopes(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &record.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.Background()

	now := time.Now().UTC()
	sub := fake.UUID()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &record.Code{
		Id:                3,
		ClientId:          3,
		UserId:            3,
		Scope:             "openid profile email resource1:read resource2:write",
		Nonce:             "mixed-nonce",
		AuthenticatedAt:   now.Add(-60 * time.Second),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd:otp_ifpossible",
		AuthMethods:       "pwd otp",
	}
	client := &record.Client{
		Id:                                      3,
		ClientIdentifier:                        "mixed-client",
		TokenExpirationInSeconds:                1500,
		RefreshTokenOfflineIdleTimeoutInSeconds: 2400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 4800,
		IncludeOpenIDConnectClaimsInAccessToken: "on",
		IncludeOpenIDConnectClaimsInIdToken:     "on",
	}
	user := &record.User{
		Id:            3,
		Subject:       sub,
		Email:         "mixed@example.com",
		EmailVerified: true,
		Username:      "mixeduser",
		GivenName:     "Mixed",
		FamilyName:    "User",
		UpdatedAt:     sql.NullTime{Time: now.Add(-24 * time.Hour), Valid: true},
		Groups: []record.Group{
			{GroupIdentifier: "group1", IncludeInIdToken: true, IncludeInAccessToken: true},
			{GroupIdentifier: "group2", IncludeInIdToken: false, IncludeInAccessToken: true},
		},
		Attributes: []record.UserAttribute{
			{Key: "attr1", Value: "value1", IncludeInIdToken: true, IncludeInAccessToken: true},
			{Key: "attr2", Value: "value2", IncludeInIdToken: true, IncludeInAccessToken: false},
		},
	}

	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, &code.User).Return(nil)
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, user.Id).Return(false, nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(&record.UserSession{
		Id:           1,
		UserId:       3,
		Started:      now.Add(-30 * time.Minute),
		LastAccessed: now.Add(-5 * time.Minute),
	}, nil)
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*record.RefreshToken")).Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)

	response, err := tokenIssuer.mintAuthorizationCodeTokens(ctx, settings, code)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(1500), response.ExpiresIn)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "openid profile email resource1:read resource2:write", response.Scope)
	assert.InDelta(t, int64(600), response.RefreshExpiresIn, 1)

	// validate Id token --------------------------------------------

	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, idClaims["iss"])
	assert.Equal(t, user.Subject, idClaims["sub"])
	assert.Equal(t, client.ClientIdentifier, idClaims["aud"])
	assert.Equal(t, code.Nonce, idClaims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), idClaims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), idClaims["amr"])
	assert.Equal(t, sessionIdentifier, idClaims["sid"])

	assertTimeClaimWithinRange(t, idClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, idClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, idClaims, "exp", 1500*time.Second, "exp should be 1500 seconds from now")
	assertTimeClaimWithinRange(t, idClaims, "auth_time", -60*time.Second, "auth_time should be 60 seconds ago")
	assertTimeClaimWithinRange(t, idClaims, "updated_at", -24*time.Hour, "updated_at should be 24 hours ago")

	_, err = uuidtest.Parse(idClaims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.Email, idClaims["email"])
	assert.Equal(t, user.EmailVerified, idClaims["email_verified"])
	assert.Equal(t, user.Username, idClaims["preferred_username"])
	assert.Equal(t, user.GivenName, idClaims["given_name"])
	assert.Equal(t, user.FamilyName, idClaims["family_name"])
	assert.Equal(t, user.FullName(), idClaims["name"])
	assert.Equal(t, "http://localhost:8081/account/profile", idClaims["profile"])

	assert.NotContains(t, idClaims, "groups")
	assert.NotContains(t, idClaims, "attributes")

	// validate Access token --------------------------------------------

	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, user.Subject, accessClaims["sub"])
	assert.Equal(t, []interface{}{"authserver", "resource1", "resource2"}, accessClaims["aud"])
	assert.Equal(t, code.Nonce, accessClaims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), accessClaims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), accessClaims["amr"])
	assert.Equal(t, sessionIdentifier, accessClaims["sid"])
	assert.Equal(t, "Bearer", accessClaims["typ"])

	assertTimeClaimWithinRange(t, accessClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, accessClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, accessClaims, "exp", 1500*time.Second, "exp should be 1500 seconds from now")
	assertTimeClaimWithinRange(t, accessClaims, "auth_time", -60*time.Second, "auth_time should be 60 seconds ago")
	assertTimeClaimWithinRange(t, accessClaims, "updated_at", -24*time.Hour, "updated_at should be 24 hours ago")

	_, err = uuidtest.Parse(accessClaims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, user.Email, accessClaims["email"])
	assert.Equal(t, user.EmailVerified, accessClaims["email_verified"])
	assert.Equal(t, user.Username, accessClaims["preferred_username"])
	assert.Equal(t, user.GivenName, accessClaims["given_name"])
	assert.Equal(t, user.FamilyName, accessClaims["family_name"])
	assert.Equal(t, user.FullName(), accessClaims["name"])
	assert.Equal(t, "http://localhost:8081/account/profile", accessClaims["profile"])

	assert.NotContains(t, accessClaims, "groups")
	assert.NotContains(t, accessClaims, "attributes")
	assert.Equal(t, "openid profile email resource1:read resource2:write", accessClaims["scope"])

	// validate Refresh token --------------------------------------------

	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, publicKeyBytes)
	assert.Equal(t, user.Subject, refreshClaims["sub"])
	assert.Equal(t, settings.Issuer, refreshClaims["aud"])
	assert.Equal(t, settings.Issuer, refreshClaims["iss"])
	assert.Equal(t, "Refresh", refreshClaims["typ"])
	assert.Equal(t, sessionIdentifier, refreshClaims["sid"])
	assert.Equal(t, "openid profile email resource1:read resource2:write", refreshClaims["scope"])

	assertTimeClaimWithinRange(t, refreshClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "exp", 600*time.Second, "exp should be 600 seconds from now")

	_, err = uuidtest.Parse(refreshClaims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)
}

func TestMintAuthorizationCodeTokens_ClientOverrideAndCustomScope(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &record.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.Background()

	now := time.Now().UTC()
	sub := fake.UUID()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &record.Code{
		Id:                4,
		ClientId:          4,
		UserId:            4,
		Scope:             "resource1:read resource2:write offline_access",
		Nonce:             "custom-nonce",
		AuthenticatedAt:   now.Add(-30 * time.Second),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &record.Client{
		Id:                                      4,
		ClientIdentifier:                        "custom-client",
		TokenExpirationInSeconds:                1200,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3000,
		RefreshTokenOfflineMaxLifetimeInSeconds: 6000,
		IncludeOpenIDConnectClaimsInAccessToken: "off",
	}
	user := &record.User{
		Id:      4,
		Subject: sub,
		Email:   "custom@example.com",
	}

	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, &code.User).Return(nil)
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*record.RefreshToken")).Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)

	response, err := tokenIssuer.mintAuthorizationCodeTokens(ctx, settings, code)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(1200), response.ExpiresIn)
	assert.NotEmpty(t, response.AccessToken)
	assert.Empty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "resource1:read resource2:write offline_access", response.Scope)
	assert.Equal(t, int64(3000), response.RefreshExpiresIn)

	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, user.Subject, accessClaims["sub"])
	assert.Equal(t, []interface{}{"resource1", "resource2"}, accessClaims["aud"])
	assert.Equal(t, code.Nonce, accessClaims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), accessClaims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), accessClaims["amr"])
	// This grant includes offline_access, so its ACCESS token deliberately carries no sid:
	// an offline grant outlives the browser session, and binding its access tokens to a
	// session identifier the middleware will later fail to resolve is the defect #106
	// decision 9 fixes. The ID token above keeps sid, because RP-initiated logout matches
	// on it. Reversed from asserting presence; see TestAccessToken_SidEmission for the table.
	assert.NotContains(t, accessClaims, "sid")
	assert.Equal(t, "Bearer", accessClaims["typ"])

	assertTimeClaimWithinRange(t, accessClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, accessClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, accessClaims, "exp", 1200*time.Second, "exp should be 1200 seconds from now")
	assertTimeClaimWithinRange(t, accessClaims, "auth_time", -30*time.Second, "auth_time should be 30 seconds ago")

	_, err = uuidtest.Parse(accessClaims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, "resource1:read resource2:write offline_access", accessClaims["scope"])
	assert.NotContains(t, accessClaims, "email")
	assert.NotContains(t, accessClaims, "name")

	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, publicKeyBytes)
	assert.Equal(t, user.Subject, refreshClaims["sub"])
	assert.Equal(t, settings.Issuer, refreshClaims["aud"])
	assert.Equal(t, settings.Issuer, refreshClaims["iss"])
	assert.Equal(t, "Offline", refreshClaims["typ"])
	assert.Equal(t, "resource1:read resource2:write offline_access", refreshClaims["scope"])

	assertTimeClaimWithinRange(t, refreshClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "exp", 3000*time.Second, "exp should be 3000 seconds from now")
	assertTimeClaimWithinRange(t, refreshClaims, "offline_access_max_lifetime", 6000*time.Second, "offline_access_max_lifetime should be 6000 seconds from now")

	_, err = uuidtest.Parse(refreshClaims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)
}

func TestMintAuthorizationCodeTokens_CustomScope(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &record.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}

	ctx := context.Background()

	now := time.Now().UTC()
	sub := fake.UUID()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &record.Code{
		Id:                5,
		ClientId:          5,
		UserId:            5,
		Scope:             "resource1:read",
		Nonce:             "custom-nonce",
		AuthenticatedAt:   now.Add(-30 * time.Second),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &record.Client{
		Id:               5,
		ClientIdentifier: "custom-scope-client",
	}
	user := &record.User{
		Id:      5,
		Subject: sub,
		Email:   "custom@example.com",
	}

	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, &code.User).Return(nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(&record.UserSession{
		Id:           1,
		UserId:       5,
		Started:      now.Add(-30 * time.Minute),
		LastAccessed: now.Add(-5 * time.Minute),
	}, nil)
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*record.RefreshToken")).Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)

	response, err := tokenIssuer.mintAuthorizationCodeTokens(ctx, settings, code)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(600), response.ExpiresIn)
	assert.NotEmpty(t, response.AccessToken)
	assert.Empty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "resource1:read", response.Scope)
	assert.InDelta(t, int64(600), response.RefreshExpiresIn, 1)

	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, user.Subject, accessClaims["sub"])
	assert.Equal(t, "resource1", accessClaims["aud"])
	assert.Equal(t, code.Nonce, accessClaims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), accessClaims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), accessClaims["amr"])
	assert.Equal(t, sessionIdentifier, accessClaims["sid"])
	assert.Equal(t, "Bearer", accessClaims["typ"])

	assertTimeClaimWithinRange(t, accessClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, accessClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, accessClaims, "exp", 600*time.Second, "exp should be 600 seconds from now")
	assertTimeClaimWithinRange(t, accessClaims, "auth_time", -30*time.Second, "auth_time should be 30 seconds ago")

	_, err = uuidtest.Parse(accessClaims["jti"].(string))
	assert.NoError(t, err)

	assert.Equal(t, "resource1:read", accessClaims["scope"])
	assert.NotContains(t, accessClaims, "email")
	assert.NotContains(t, accessClaims, "name")

	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, publicKeyBytes)
	assert.Equal(t, user.Subject, refreshClaims["sub"])
	assert.Equal(t, settings.Issuer, refreshClaims["aud"])
	assert.Equal(t, settings.Issuer, refreshClaims["iss"])
	assert.Equal(t, "Refresh", refreshClaims["typ"])
	assert.Equal(t, "resource1:read", refreshClaims["scope"])

	assertTimeClaimWithinRange(t, refreshClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "exp", 600*time.Second, "exp should be 600 seconds from now")

	_, err = uuidtest.Parse(refreshClaims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)
}
