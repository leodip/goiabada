package issuance

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/uuid/uuidtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGenerateRefreshToken_Offline(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
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
		Scope:             "openid offline_access",
		Nonce:             "test-nonce",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		SessionIdentifier: sessionIdentifier,
	}
	client := &models.Client{
		Id:                                      1,
		ClientIdentifier:                        "test-client",
		RefreshTokenOfflineIdleTimeoutInSeconds: 7200,
		RefreshTokenOfflineMaxLifetimeInSeconds: 172800,
	}
	user := &models.User{
		Id:      1,
		Subject: sub,
	}

	code.Client = *client
	code.User = *user

	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	refreshToken, refreshExpiresIn, err := tokenIssuer.generateRefreshToken(context.Background(), nil, settings, code, code.Scope, now, privKey, "test-key-id", nil)

	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)
	assert.Equal(t, int64(7200), refreshExpiresIn)

	claims := verifyAndDecodeToken(t, refreshToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, settings.Issuer, claims["aud"])
	assert.Equal(t, user.Subject, claims["sub"])
	assert.Equal(t, "Offline", claims["typ"])
	assert.Equal(t, code.Scope, claims["scope"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 7200*time.Second, "exp should be 7200 seconds from now")
	assertTimeClaimWithinRange(t, claims, "offline_access_max_lifetime", 172800*time.Second, "offline_access_max_lifetime should be 172800 seconds from now")

	_, err = uuidtest.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)
}

func TestGenerateRefreshToken_Refresh(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                          "https://test-issuer.com",
		UserSessionIdleTimeoutInSeconds: 1800,
		UserSessionMaxLifetimeInSeconds: 43200,
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
		Nonce:             "refresh-nonce",
		AuthenticatedAt:   now.Add(-10 * time.Minute),
		SessionIdentifier: sessionIdentifier,
	}
	client := &models.Client{
		Id:               2,
		ClientIdentifier: "refresh-client",
	}
	user := &models.User{
		Id:      2,
		Subject: sub,
	}

	code.Client = *client
	code.User = *user

	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(&models.UserSession{
		Id:           1,
		UserId:       2,
		Started:      now.Add(-30 * time.Minute),
		LastAccessed: now.Add(-5 * time.Minute),
	}, nil)

	refreshToken, refreshExpiresIn, err := tokenIssuer.generateRefreshToken(context.Background(), nil, settings, code, code.Scope, now, privKey, "test-key-id", nil)

	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)
	assert.Equal(t, int64(1800), refreshExpiresIn)

	claims := verifyAndDecodeToken(t, refreshToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, settings.Issuer, claims["aud"])
	assert.Equal(t, user.Subject, claims["sub"])
	assert.Equal(t, "Refresh", claims["typ"])
	assert.Equal(t, code.Scope, claims["scope"])
	assert.Equal(t, sessionIdentifier, claims["sid"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 1800*time.Second, "exp should be 1800 seconds from now")

	_, err = uuidtest.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)
}

func TestGenerateRefreshToken_WithExistingRefreshToken(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
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
		Scope:             "openid offline_access",
		Nonce:             "existing-nonce",
		AuthenticatedAt:   now.Add(-15 * time.Minute),
		SessionIdentifier: sessionIdentifier,
	}
	client := &models.Client{
		Id:               3,
		ClientIdentifier: "existing-client",
	}
	user := &models.User{
		Id:      3,
		Subject: sub,
	}

	code.Client = *client
	code.User = *user

	existingRefreshToken := &models.RefreshToken{
		Id:                   1,
		RefreshTokenJti:      "existing-jti",
		FirstRefreshTokenJti: "first-jti",
		MaxLifetime:          sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
	}

	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	refreshToken, refreshExpiresIn, err := tokenIssuer.generateRefreshToken(context.Background(), nil, settings, code, code.Scope, now, privKey, "test-key-id", existingRefreshToken)

	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)
	assert.Equal(t, int64(3600), refreshExpiresIn)

	claims := verifyAndDecodeToken(t, refreshToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, settings.Issuer, claims["aud"])
	assert.Equal(t, user.Subject, claims["sub"])
	assert.Equal(t, "Offline", claims["typ"])
	assert.Equal(t, code.Scope, claims["scope"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", 3600*time.Second, "exp should be 3600 seconds from now")
	assertTimeClaimWithinRange(t, claims, "offline_access_max_lifetime", 24*time.Hour, "offline_access_max_lifetime should match existing refresh token")

	_, err = uuidtest.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)

	mockDB.AssertCalled(t, "CreateRefreshToken", mock.Anything, mock.Anything, mock.MatchedBy(func(rt *models.RefreshToken) bool {
		return rt.PreviousRefreshTokenJti == "existing-jti" &&
			rt.FirstRefreshTokenJti == "first-jti"
	}))
}

func TestGenerateRefreshToken_OfflineMaxLifetimeLimit(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,  // 1 hour
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400, // 24 hours
	}

	initialTime := time.Now().UTC()
	sub := fake.UUID()
	sessionIdentifier := "test-session-max-lifetime"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	assert.NoError(t, err)

	code := &models.Code{
		Id:                4,
		ClientId:          4,
		UserId:            4,
		Scope:             "openid offline_access",
		Nonce:             "max-lifetime-nonce",
		AuthenticatedAt:   initialTime.Add(-22 * time.Hour), // 22 hours ago
		SessionIdentifier: sessionIdentifier,
	}
	client := &models.Client{
		Id:                                      4,
		ClientIdentifier:                        "max-lifetime-client",
		RefreshTokenOfflineIdleTimeoutInSeconds: 7200,   // 2 hours
		RefreshTokenOfflineMaxLifetimeInSeconds: 172800, // 48 hours (client setting)
	}
	user := &models.User{
		Id:      4,
		Subject: sub,
	}

	code.Client = *client
	code.User = *user

	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	// Simulate two previous refresh token generations
	secondRefreshTime := initialTime.Add(-1 * time.Hour)

	secondRefreshToken := &models.RefreshToken{
		Id:                      2,
		RefreshTokenJti:         "second-jti",
		FirstRefreshTokenJti:    "first-jti",
		PreviousRefreshTokenJti: "first-jti",
		MaxLifetime:             sql.NullTime{Time: initialTime.Add(1 * time.Hour), Valid: true},
		IssuedAt:                sql.NullTime{Time: secondRefreshTime, Valid: true},
	}

	// Now generate the third refresh token
	thirdRefreshTime := initialTime
	refreshToken, refreshExpiresIn, err := tokenIssuer.generateRefreshToken(context.Background(), nil, settings, code, code.Scope, thirdRefreshTime, privKey, "test-key-id", secondRefreshToken)

	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)

	// The remaining time should be close to 1 hour (3600 seconds)
	expectedRemainingTime := int64(3600)
	assert.InDelta(t, expectedRemainingTime, refreshExpiresIn, 5, "refreshExpiresIn should be close to the remaining time in the max lifetime")

	claims := verifyAndDecodeToken(t, refreshToken, publicKeyBytes)

	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, settings.Issuer, claims["aud"])
	assert.Equal(t, user.Subject, claims["sub"])
	assert.Equal(t, "Offline", claims["typ"])
	assert.Equal(t, code.Scope, claims["scope"])

	assertTimeClaimWithinRange(t, claims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, claims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, claims, "exp", time.Duration(expectedRemainingTime)*time.Second, "exp should be close to the remaining time in the max lifetime")
	assertTimeClaimWithinRange(t, claims, "offline_access_max_lifetime", time.Duration(expectedRemainingTime)*time.Second, "offline_access_max_lifetime is not correct")

	_, err = uuidtest.Parse(claims["jti"].(string))
	assert.NoError(t, err)

	mockDB.AssertExpectations(t)

	// Verify that the refresh token's expiration doesn't exceed the max lifetime
	expUnix := int64(claims["exp"].(float64))
	maxLifetimeUnix := int64(claims["offline_access_max_lifetime"].(float64))
	assert.LessOrEqual(t, expUnix, maxLifetimeUnix, "Refresh token expiration should not exceed the max lifetime")

	// Verify that the correct previous and first refresh token JTIs are used
	mockDB.AssertCalled(t, "CreateRefreshToken", mock.Anything, mock.Anything, mock.MatchedBy(func(rt *models.RefreshToken) bool {
		return rt.PreviousRefreshTokenJti == "second-jti" &&
			rt.FirstRefreshTokenJti == "first-jti"
	}))
}

func TestGetRefreshTokenExpiration(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	now := time.Now().UTC()
	settings := &models.Settings{
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		UserSessionIdleTimeoutInSeconds:         1800,
	}
	client := &models.Client{
		RefreshTokenOfflineIdleTimeoutInSeconds: 7200,
	}

	tests := []struct {
		name               string
		refreshTokenType   TokenType
		expectedExpiration int64
		expectedError      bool
	}{
		{
			name:               "Offline token with client override",
			refreshTokenType:   TokenTypeOffline,
			expectedExpiration: now.Add(7200 * time.Second).Unix(),
			expectedError:      false,
		},
		{
			name:               "Offline token without client override",
			refreshTokenType:   TokenTypeOffline,
			expectedExpiration: now.Add(3600 * time.Second).Unix(),
			expectedError:      false,
		},
		{
			name:               "Refresh token",
			refreshTokenType:   TokenTypeRefresh,
			expectedExpiration: now.Add(1800 * time.Second).Unix(),
			expectedError:      false,
		},
		{
			name:               "A type that is not a refresh token",
			refreshTokenType:   TokenTypeBearer,
			expectedExpiration: 0,
			expectedError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Offline token without client override" {
				client.RefreshTokenOfflineIdleTimeoutInSeconds = 0
			}

			exp, err := tokenIssuer.getRefreshTokenExpiration(tt.refreshTokenType, now, settings, client)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedExpiration, exp)
			}
		})
	}
}

func TestGetRefreshTokenMaxLifetime(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	now := time.Now().UTC()
	settings := &models.Settings{
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
		UserSessionMaxLifetimeInSeconds:         43200,
	}
	client := &models.Client{
		RefreshTokenOfflineMaxLifetimeInSeconds: 172800,
	}
	sessionIdentifier := "test-session-123"

	tests := []struct {
		name             string
		refreshTokenType TokenType
		expectedLifetime int64
		expectedError    bool
		mockUserSession  *models.UserSession
	}{
		{
			name:             "Offline token with client override",
			refreshTokenType: TokenTypeOffline,
			expectedLifetime: now.Add(172800 * time.Second).Unix(),
			expectedError:    false,
		},
		{
			name:             "Offline token without client override",
			refreshTokenType: TokenTypeOffline,
			expectedLifetime: now.Add(86400 * time.Second).Unix(),
			expectedError:    false,
		},
		{
			name:             "Refresh token",
			refreshTokenType: TokenTypeRefresh,
			expectedLifetime: now.Add(43200 * time.Second).Unix(),
			expectedError:    false,
			mockUserSession: &models.UserSession{
				Started: now,
			},
		},
		{
			name:             "A type that is not a refresh token",
			refreshTokenType: TokenTypeBearer,
			expectedLifetime: 0,
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Offline token without client override" {
				client.RefreshTokenOfflineMaxLifetimeInSeconds = 0
			}

			if tt.mockUserSession != nil {
				mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(tt.mockUserSession, nil)
			}

			maxLifetime, err := tokenIssuer.getRefreshTokenMaxLifetime(context.Background(), nil, tt.refreshTokenType, now, settings, client, sessionIdentifier)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedLifetime, maxLifetime)
			}

			mockDB.AssertExpectations(t)
		})
	}
}
