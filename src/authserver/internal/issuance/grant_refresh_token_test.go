package issuance

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/authserver/internal/uuidutil"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestMintCodeRefreshTokens(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200, // 20 minutes
		UserSessionMaxLifetimeInSeconds:         2400, // 40 minutes
		IncludeOpenIDConnectClaimsInIdToken:     true,
		IncludeOpenIDConnectClaimsInAccessToken: true,
	}

	ctx := context.Background()

	now := time.Now().UTC()
	sub := fake.UUID()
	sessionIdentifier := "test-session-123"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &models.Code{
		Id:                1,
		ClientId:          1,
		UserId:            1,
		Scope:             "openid profile resource1:read",
		Nonce:             "test-nonce",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "test-client",
		TokenExpirationInSeconds: 900,
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

	refreshToken := &models.RefreshToken{
		Id:                   1,
		RefreshTokenJti:      "existing-jti",
		FirstRefreshTokenJti: "first-jti",
		MaxLifetime:          sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
		Scope:                "openid profile resource1:read",
	}

	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, &code.User).Return(nil)
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, user.Id).Return(false, nil)
	var capturedRefreshToken *models.RefreshToken
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).
		Run(func(args mock.Arguments) {
			capturedRefreshToken = args.Get(2).(*models.RefreshToken)
		}).
		Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)
	// Add the missing mock expectation
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sessionIdentifier).Return(&models.UserSession{
		Id:           1,
		UserId:       1,
		Started:      now.Add(-30 * time.Minute),
		LastAccessed: now.Add(-5 * time.Minute),
	}, nil)

	response, err := tokenIssuer.mintCodeRefreshTokens(ctx, nil, settings, code, refreshToken, "openid profile resource1:read")

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(900), response.ExpiresIn) // client override
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "openid profile resource1:read", response.Scope)
	assert.InDelta(t, int64(600), response.RefreshExpiresIn, 1) // remaining time based on session max lifetime

	// validate Id token --------------------------------------------

	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, idClaims["iss"])
	assert.Equal(t, user.Subject, idClaims["sub"])
	assert.Equal(t, client.ClientIdentifier, idClaims["aud"])
	assert.Equal(t, code.Nonce, idClaims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), idClaims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), idClaims["amr"])
	assert.Equal(t, sessionIdentifier, idClaims["sid"])
	assertTimeClaimWithinRange(t, idClaims, "auth_time", -300*time.Second, "auth_time should be 300 seconds ago")
	assertTimeClaimWithinRange(t, idClaims, "exp", 900*time.Second, "exp should be 900 seconds from now")
	assertTimeClaimWithinRange(t, idClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, idClaims, "nbf", 0*time.Second, "nbf should be now")
	assert.Equal(t, user.FamilyName, idClaims["family_name"])
	assert.Equal(t, user.GivenName, idClaims["given_name"])
	assert.Equal(t, user.FullName(), idClaims["name"])
	assert.Equal(t, user.Username, idClaims["preferred_username"])
	assert.Equal(t, fmt.Sprintf("%v/account/profile", "http://localhost:8081"), idClaims["profile"])
	_, err = uuidutil.Parse(idClaims["jti"].(string))
	assert.NoError(t, err)
	assertTimeClaimWithinRange(t, idClaims, "updated_at", -1*time.Hour, "updated_at should be 1 hour ago")

	// validate Access token --------------------------------------------

	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, user.Subject, accessClaims["sub"])
	assert.ElementsMatch(t, []string{builtin.AuthServerResourceIdentifier, "resource1"}, accessClaims["aud"])
	assert.Equal(t, code.Nonce, accessClaims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), accessClaims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), accessClaims["amr"])
	assert.Equal(t, sessionIdentifier, accessClaims["sid"])
	assert.Equal(t, "Bearer", accessClaims["typ"])
	assert.Equal(t, user.FamilyName, accessClaims["family_name"])
	assert.Equal(t, user.GivenName, accessClaims["given_name"])
	assert.Equal(t, user.FullName(), accessClaims["name"])
	assert.Equal(t, user.Username, accessClaims["preferred_username"])
	assert.Equal(t, fmt.Sprintf("%v/account/profile", "http://localhost:8081"), accessClaims["profile"])
	assert.Equal(t, "openid profile resource1:read", accessClaims["scope"])
	_, err = uuidutil.Parse(accessClaims["jti"].(string))
	assert.NoError(t, err)
	assertTimeClaimWithinRange(t, accessClaims, "updated_at", -1*time.Hour, "updated_at should be 1 hour ago")

	assertTimeClaimWithinRange(t, accessClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, accessClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, accessClaims, "exp", 900*time.Second, "exp should be 900 seconds from now")
	assertTimeClaimWithinRange(t, accessClaims, "auth_time", -300*time.Second, "auth_time should be 300 seconds ago")

	// validate Refresh token --------------------------------------------
	// RFC 6749 Section 6: New refresh token scope MUST be identical to original refresh token's scope

	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, publicKeyBytes)
	assert.Equal(t, user.Subject, refreshClaims["sub"])
	assert.Equal(t, "https://test-issuer.com", refreshClaims["aud"])
	assert.Equal(t, "https://test-issuer.com", refreshClaims["iss"])
	assert.Equal(t, "Refresh", refreshClaims["typ"])
	assert.Equal(t, "openid profile resource1:read", refreshClaims["scope"])
	_, err = uuidutil.Parse(refreshClaims["jti"].(string))
	assert.NoError(t, err)
	assert.Equal(t, sessionIdentifier, refreshClaims["sid"])

	assertTimeClaimWithinRange(t, refreshClaims, "exp", 600*time.Second, "exp should be 600 seconds from now")
	assertTimeClaimWithinRange(t, refreshClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "nbf", 0*time.Second, "nbf should be now")

	// validate Refresh token passed to CreateRefreshToken --------------------------------------------
	// RFC 6749 Section 6: New refresh token scope MUST be identical to original refresh token's scope

	assert.NotNil(t, capturedRefreshToken)
	assert.True(t, capturedRefreshToken.CodeId.Valid)
	assert.Equal(t, code.Id, capturedRefreshToken.CodeId.Int64)
	assert.NotEmpty(t, capturedRefreshToken.RefreshTokenJti)
	assert.Equal(t, refreshToken.FirstRefreshTokenJti, capturedRefreshToken.FirstRefreshTokenJti)
	assert.Equal(t, refreshToken.RefreshTokenJti, capturedRefreshToken.PreviousRefreshTokenJti)
	assert.Equal(t, "Refresh", capturedRefreshToken.RefreshTokenType)
	assert.Equal(t, "openid profile resource1:read", capturedRefreshToken.Scope)
	assert.Equal(t, sessionIdentifier, capturedRefreshToken.SessionIdentifier)
	assert.False(t, capturedRefreshToken.Revoked)
	assert.True(t, capturedRefreshToken.IssuedAt.Valid)
	assert.WithinDuration(t, now, capturedRefreshToken.IssuedAt.Time, 1*time.Second)
	assert.True(t, capturedRefreshToken.ExpiresAt.Valid)
	assert.WithinDuration(t, now.Add(600*time.Second), capturedRefreshToken.ExpiresAt.Time, 1*time.Second)

	mockDB.AssertExpectations(t)
}

func TestMintCodeRefreshTokens_Offline_NoIdToken(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}

	ctx := context.Background()

	now := time.Now().UTC()
	sub := fake.UUID()
	sessionIdentifier := "test-session-offline"

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	code := &models.Code{
		Id:                1,
		ClientId:          1,
		UserId:            1,
		Scope:             "openid profile offline_access",
		Nonce:             "test-nonce-offline",
		AuthenticatedAt:   now.Add(-10 * time.Minute),
		SessionIdentifier: sessionIdentifier,
		AcrLevel:          "urn:goiabada:pwd",
		AuthMethods:       "pwd",
	}
	client := &models.Client{
		Id:                                      1,
		ClientIdentifier:                        "test-client-offline",
		TokenExpirationInSeconds:                1200,
		RefreshTokenOfflineIdleTimeoutInSeconds: 7200,
		RefreshTokenOfflineMaxLifetimeInSeconds: 172800,
	}
	user := &models.User{
		Id:            1,
		Subject:       sub,
		Email:         "test@example.com",
		EmailVerified: true,
		Username:      "testuser",
		GivenName:     "Test",
		FamilyName:    "User",
		UpdatedAt:     sql.NullTime{Time: now.Add(-2 * time.Hour), Valid: true},
	}

	refreshToken := &models.RefreshToken{
		Id:                   1,
		RefreshTokenJti:      "existing-jti-offline",
		FirstRefreshTokenJti: "first-jti-offline",
		MaxLifetime:          sql.NullTime{Time: now.Add(48 * time.Hour), Valid: true},
		Scope:                "openid profile offline_access",
		// Set explicitly. Without it this fixture was an empty string, which production
		// classifies as session-bound, so a test named for the offline case was exercising
		// the session-bound one and its sid assertion passed for the wrong reason.
		RefreshTokenType: TokenTypeOffline.String(),
		// Deliberately conflicting with the code's generation below, so this public entry
		// point proves the parent is forwarded rather than the code being re-read (#106
		// decision 13). The direct helper tables pass even if the wrapper stops forwarding.
		AuthStateGeneration: 7,
	}

	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
	code.Client = *client
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
	code.User = *user
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, &code.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, code.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, &code.User).Return(nil)
	var capturedRefreshToken *models.RefreshToken
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).
		Run(func(args mock.Arguments) {
			capturedRefreshToken = args.Get(2).(*models.RefreshToken)
		}).
		Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)

	response, err := tokenIssuer.mintCodeRefreshTokens(ctx, nil, settings, code, refreshToken, "resource1:write offline_access")

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(1200), response.ExpiresIn)
	assert.NotEmpty(t, response.AccessToken)
	assert.Empty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "resource1:write offline_access", response.Scope)
	assert.Equal(t, int64(7200), response.RefreshExpiresIn)

	// validate Access token --------------------------------------------

	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, settings.Issuer, accessClaims["iss"])
	assert.Equal(t, user.Subject, accessClaims["sub"])
	assert.Equal(t, "resource1", accessClaims["aud"])
	assert.Equal(t, code.Nonce, accessClaims["nonce"])
	assert.Equal(t, code.AcrLevel.String(), accessClaims["acr"])
	assert.ElementsMatch(t, strings.Fields(code.AuthMethods), accessClaims["amr"])
	// Reversed: the parent is genuinely Offline now, so no sid. An offline grant outlives
	// the browser session, and this is the public entry point proving the suppression is
	// wired through mintCodeRefreshTokens and not only in the helper (#106
	// decision 9).
	assert.NotContains(t, accessClaims, "sid")
	// Provenance at the public entry point: the PARENT is at 7 while the code stays at its
	// own value, so this fails if the wrapper stops forwarding the parent and the code gets
	// re-read (#106 decision 13).
	assert.EqualValues(t, 7, accessClaims["auth_state_generation"])
	assert.Equal(t, "Bearer", accessClaims["typ"])
	assert.Equal(t, "resource1:write offline_access", accessClaims["scope"])
	assertTimeClaimWithinRange(t, accessClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, accessClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, accessClaims, "exp", 1200*time.Second, "exp should be 1200 seconds from now")
	assertTimeClaimWithinRange(t, accessClaims, "auth_time", -600*time.Second, "auth_time should be 600 seconds ago")
	_, err = uuidutil.Parse(accessClaims["jti"].(string))
	assert.NoError(t, err, "Access token jti should be a valid UUID")

	// validate Refresh token --------------------------------------------
	// RFC 6749 Section 6: New refresh token scope MUST be identical to original refresh token's scope

	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, publicKeyBytes)
	assert.Equal(t, user.Subject, refreshClaims["sub"])
	assert.Equal(t, settings.Issuer, refreshClaims["aud"])
	assert.Equal(t, settings.Issuer, refreshClaims["iss"])
	assert.Equal(t, "Offline", refreshClaims["typ"])
	assert.Equal(t, "openid profile offline_access", refreshClaims["scope"]) // Original scope preserved
	assertTimeClaimWithinRange(t, refreshClaims, "iat", 0*time.Second, "iat should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "nbf", 0*time.Second, "nbf should be now")
	assertTimeClaimWithinRange(t, refreshClaims, "exp", 7200*time.Second, "exp should be 7200 seconds from now")
	assertTimeClaimWithinRange(t, refreshClaims, "offline_access_max_lifetime", 172800*time.Second, "offline_access_max_lifetime should be 172800 seconds from now")
	_, err = uuidutil.Parse(refreshClaims["jti"].(string))
	assert.NoError(t, err, "Refresh token jti should be a valid UUID")

	// validate Refresh token passed to CreateRefreshToken --------------------------------------------
	// RFC 6749 Section 6: New refresh token scope MUST be identical to original refresh token's scope

	assert.NotNil(t, capturedRefreshToken)
	assert.True(t, capturedRefreshToken.CodeId.Valid)
	assert.Equal(t, code.Id, capturedRefreshToken.CodeId.Int64)
	assert.NotEmpty(t, capturedRefreshToken.RefreshTokenJti)
	assert.Equal(t, refreshToken.FirstRefreshTokenJti, capturedRefreshToken.FirstRefreshTokenJti)
	assert.Equal(t, refreshToken.RefreshTokenJti, capturedRefreshToken.PreviousRefreshTokenJti)
	assert.Equal(t, "Offline", capturedRefreshToken.RefreshTokenType)
	// The CHILD token inherits the parent's generation, not the code's. Same reason as the
	// access-token assertion above: this is the seam the helper tables cannot reach.
	assert.EqualValues(t, 7, capturedRefreshToken.AuthStateGeneration)
	assert.Equal(t, "openid profile offline_access", capturedRefreshToken.Scope) // Original scope preserved
	assert.Empty(t, capturedRefreshToken.SessionIdentifier)
	assert.False(t, capturedRefreshToken.Revoked)
	assert.True(t, capturedRefreshToken.IssuedAt.Valid)
	assert.WithinDuration(t, now, capturedRefreshToken.IssuedAt.Time, 1*time.Second)
	assert.True(t, capturedRefreshToken.ExpiresAt.Valid)
	assert.WithinDuration(t, now.Add(7200*time.Second), capturedRefreshToken.ExpiresAt.Time, 1*time.Second)
	assert.True(t, capturedRefreshToken.MaxLifetime.Valid)
	assert.WithinDuration(t, now.Add(172800*time.Second), capturedRefreshToken.MaxLifetime.Time, 1*time.Second)

	mockDB.AssertExpectations(t)
}

// TestMintROPCRefreshTokens tests ROPC refresh token flow
func TestMintROPCRefreshTokens(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}

	ctx := context.Background()
	now := time.Now().UTC()
	authenticatedAt := now.Add(-72 * time.Hour).Truncate(time.Second)
	userSubject := fake.UUID()

	user := &models.User{
		Id:        1,
		Subject:   userSubject,
		Email:     "ropc@example.com",
		UpdatedAt: sql.NullTime{Time: now, Valid: true},
	}

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "ropc-client",
	}

	refreshToken := &models.RefreshToken{
		Id:                   1,
		RefreshTokenJti:      "original-jti",
		FirstRefreshTokenJti: "first-jti",
		UserId:               sql.NullInt64{Int64: user.Id, Valid: true},
		ClientId:             sql.NullInt64{Int64: client.Id, Valid: true},
		Scope:                "openid email resource:read",
		RefreshTokenType:     "Offline",
		MaxLifetime:          sql.NullTime{Time: now.Add(86400 * time.Second), Valid: true},
		// Deliberately conflicting with the user below, who is set to 9. The ROPC refresh
		// path RELOADS the user, so reading that reloaded user would stamp a grant
		// authenticated at 7 with 9 and launder it forward. This is the public entry point
		// proving the wrapper forwards the parent (#106 decision 13); the helper table
		// passes even if it stops.
		AuthStateGeneration: 7,
		// Three days before this refresh, when the family's password grant checked the password.
		// Every token the refresh issues has to report that, not the refresh (#125).
		AuthenticatedAt: sql.NullTime{Time: authenticatedAt, Valid: true},
		User:            *user,
		Client:          *client,
	}
	refreshToken.User.AuthStateGeneration = 9

	// Set up mocks
	mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, refreshToken).Return(nil)
	mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, refreshToken).Return(nil)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, &refreshToken.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, refreshToken.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, &refreshToken.User).Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)
	var capturedChild *models.RefreshToken
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).
		Run(func(args mock.Arguments) {
			capturedChild = args.Get(2).(*models.RefreshToken)
		}).
		Return(nil)
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()

	response, err := tokenIssuer.mintROPCRefreshTokens(ctx, nil, settings, refreshToken, "openid email resource:read")

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "Bearer", response.TokenType)

	// Verify access token claims
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, userSubject, accessClaims["sub"])
	// Level 1, the advertised meaning of password-only, not the unadvertised urn:goiabada:pwd (#433).
	assert.Equal(t, "urn:goiabada:level1", accessClaims["acr"])
	assert.ElementsMatch(t, []string{"pwd"}, accessClaims["amr"])
	// From the parent (7), not the reloaded user (9).
	assert.EqualValues(t, 7, accessClaims["auth_state_generation"])
	// The password grant's instant, which RFC 9068 section 2.2.1 holds fixed across refreshes,
	// while iat is this refresh.
	assert.EqualValues(t, authenticatedAt.Unix(), accessClaims["auth_time"])
	assert.GreaterOrEqual(t, accessClaims["iat"], float64(now.Unix()), "iat is the refresh")
	// ROPC is sessionless, so no sid on either token.
	assert.NotContains(t, accessClaims, "sid")

	// Verify id token claims
	idClaims := verifyAndDecodeToken(t, response.IdToken, publicKeyBytes)
	assert.Equal(t, userSubject, idClaims["sub"])
	assert.Equal(t, "ropc-client", idClaims["aud"])
	assert.Equal(t, "urn:goiabada:level1", idClaims["acr"])
	assert.ElementsMatch(t, []string{"pwd"}, idClaims["amr"])
	assert.NotContains(t, idClaims, "sid", "a ROPC ID token must never carry a session identifier")
	// OpenID Connect Core 1.0 section 12.2: "the time of the original authentication - not the
	// time that the new ID token is issued".
	assert.EqualValues(t, authenticatedAt.Unix(), idClaims["auth_time"])
	assert.GreaterOrEqual(t, idClaims["iat"], float64(now.Unix()), "iat is the refresh")

	// The CHILD refresh token must inherit the parent's generation too. Without this, a
	// regression that forwards the parent to generateROPCAccessToken but not to
	// generateRefreshTokenForROPC would pass: the access token would read 7 while the new
	// refresh token silently took the reloaded user's 9 and laundered the grant forward on
	// the NEXT refresh. Mirrors the auth-code offline test, which captures its child for the
	// same reason.
	require.NotNil(t, capturedChild, "CreateRefreshToken was never called")
	assert.EqualValues(t, 7, capturedChild.AuthStateGeneration,
		"the child refresh token must inherit the parent's generation, not the reloaded user's")
	// And the parent's instant, or the NEXT refresh would report this one (#125).
	assert.Equal(t, sql.NullTime{Time: authenticatedAt, Valid: true}, capturedChild.AuthenticatedAt,
		"the child refresh token must inherit the parent's authentication instant")

	mockDB.AssertExpectations(t)
}

// TestMintROPCRefreshTokens_ScopeDowngrade tests requesting fewer scopes on refresh
func TestMintROPCRefreshTokens_ScopeDowngrade(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	privateKeyBytes := getTestPrivateKey(t)
	publicKeyBytes := getTestPublicKey(t)

	settings := &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}

	ctx := context.Background()
	now := time.Now().UTC()
	userSubject := fake.UUID()

	user := &models.User{
		Id:        1,
		Subject:   userSubject,
		Email:     "ropc@example.com",
		UpdatedAt: sql.NullTime{Time: now, Valid: true},
	}

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "ropc-client",
	}

	refreshToken := &models.RefreshToken{
		Id:                   1,
		RefreshTokenJti:      "original-jti",
		FirstRefreshTokenJti: "first-jti",
		UserId:               sql.NullInt64{Int64: user.Id, Valid: true},
		ClientId:             sql.NullInt64{Int64: client.Id, Valid: true},
		AuthenticatedAt:      sql.NullTime{Time: now.Add(-time.Hour), Valid: true},
		Scope:                "openid email profile resource:read resource:write",
		RefreshTokenType:     "Offline",
		MaxLifetime:          sql.NullTime{Time: now.Add(86400 * time.Second), Valid: true},
		User:                 *user,
		Client:               *client,
	}

	mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, refreshToken).Return(nil)
	mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, refreshToken).Return(nil)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, &refreshToken.User).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, refreshToken.User.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, &refreshToken.User).Return(nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, privateKeyBytes),
	}, nil)
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*models.RefreshToken")).Return(nil)
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()

	// Request only a subset of the original scopes
	response, err := tokenIssuer.mintROPCRefreshTokens(ctx, nil, settings, refreshToken, "resource:read")

	assert.NoError(t, err)
	assert.NotNil(t, response)

	// Verify scope was downgraded
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, publicKeyBytes)
	assert.Equal(t, "resource:read", accessClaims["scope"])

	// Should not have id_token since openid scope not requested
	assert.Empty(t, response.IdToken)

	mockDB.AssertExpectations(t)
}
