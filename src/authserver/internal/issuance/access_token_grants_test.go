package issuance

// Every grant's access token, held whole: its header, every claim it carries and nothing else, and
// its lifetime. The grants build their tokens through one finishing step, which signs them and sets
// the claims they share, so a token the step writes a claim to by mistake, or one it leaves a claim
// off, fails here for the grant it reached.
//
// The expected values are literals and fixture values. The four claims that change on every issue
// are checked apart: jti is a UUID, iat and nbf are the moment of issue, exp is iat plus the
// lifetime the response reports.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/uuid/uuidtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// assertWholeAccessToken checks an access token's header and every claim it carries, given the
// claims that do not change from one issue to the next and the lifetime it must have.
func assertWholeAccessToken(t *testing.T, token string, testStart time.Time, lifetime int64,
	want map[string]interface{}) {
	t.Helper()

	assert.Equal(t, map[string]interface{}{"alg": "RS256", "typ": "at+jwt", "kid": "test-key-id"}, tokenHeader(t, token),
		"the access token's header")

	claims := verifyAndDecodeToken(t, token, getTestPublicKey(t))

	jti, ok := claims["jti"].(string)
	require.True(t, ok, "jti is a string")
	_, err := uuidtest.Parse(jti)
	require.NoError(t, err, "jti is a UUID")

	assertTimeClaimWithinRange(t, claims, "iat", 0, testStart, "iat is the moment of issue")
	assert.Equal(t, claims["iat"], claims["nbf"], "nbf is iat")
	iat, ok := claims["iat"].(float64)
	require.True(t, ok, "iat is a number")
	exp, ok := claims["exp"].(float64)
	require.True(t, ok, "exp is a number")
	assert.Equal(t, lifetime, int64(exp)-int64(iat), "exp is iat plus the lifetime")

	rest := map[string]interface{}{}
	for name, value := range claims {
		switch name {
		case "jti", "iat", "nbf", "exp":
			continue
		}
		rest[name] = value
	}
	assert.Equal(t, want, rest, "every other claim, and no claim besides")
}

func TestAccessToken_AuthorizationCodeGrant(t *testing.T) {
	testStart := time.Now().UTC()
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	code := sessionBoundCode(testStart)
	code.Scope = "openid email product-api:read"
	code.Nonce = "n-0S6_WzA2Mj"
	code.AuthStateGeneration = 4
	code.AuthMethods = "pwd otp"
	code.AcrLevel = record.AcrLevel2Optional
	code.Client.TokenExpirationInSeconds = 900
	code.Client.IncludeOpenIDConnectClaimsInAccessToken = record.ThreeStateSettingOn.String()
	code.User.Email = "ana@example.com"
	code.User.EmailVerified = true

	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "session-1").
		Return(&record.UserSession{Id: 1, UserId: 1, Started: testStart.Add(-10 * time.Minute)}, nil)
	expectSigningKeyAndUserLoads(t, mockDB)
	row := captureRefreshTokenRow(mockDB)

	response, err := tokenIssuer.mintAuthorizationCodeTokens(context.Background(), rfc9068Settings(), code)
	require.NoError(t, err)

	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(900), response.ExpiresIn, "the client's lifetime")
	require.NotEmpty(t, row.FirstRefreshTokenJti)
	assertWholeAccessToken(t, response.AccessToken, testStart, 900, map[string]interface{}{
		"iss":                   "https://test-issuer.com",
		"sub":                   code.User.Subject,
		"client_id":             "web-app",
		"grant_id":              row.FirstRefreshTokenJti,
		"auth_time":             float64(testStart.Add(-5 * time.Minute).Unix()),
		"acr":                   "urn:goiabada:level2_optional",
		"amr":                   []interface{}{"pwd", "otp"},
		"auth_state_generation": float64(4),
		"sid":                   "session-1",
		"aud":                   []interface{}{"authserver", "product-api"},
		"typ":                   "Bearer",
		"scope":                 "openid email product-api:read",
		"nonce":                 "n-0S6_WzA2Mj",
		"email":                 "ana@example.com",
		"email_verified":        true,
	})
}

func TestAccessToken_RefreshOfACodeGrant(t *testing.T) {
	testStart := time.Now().UTC()
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	code := sessionBoundCode(testStart)
	code.Nonce = "n-0S6_WzA2Mj"
	code.AuthStateGeneration = 4
	parent := &record.RefreshToken{
		Id:                   2,
		RefreshTokenJti:      "parent-jti",
		FirstRefreshTokenJti: "family-jti",
		Scope:                code.Scope,
		RefreshTokenType:     TokenTypeRefresh.String(),
		AuthStateGeneration:  6,
	}

	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "session-1").
		Return(&record.UserSession{Id: 1, UserId: 1, Started: testStart.Add(-10 * time.Minute)}, nil)
	expectSigningKeyAndUserLoads(t, mockDB)
	captureRefreshTokenRow(mockDB)

	response, err := tokenIssuer.mintCodeRefreshTokens(context.Background(), nil, rfc9068Settings(), code, parent, "")
	require.NoError(t, err)

	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(600), response.ExpiresIn, "the server's lifetime")
	assertWholeAccessToken(t, response.AccessToken, testStart, 600, map[string]interface{}{
		"iss":                   "https://test-issuer.com",
		"sub":                   code.User.Subject,
		"client_id":             "web-app",
		"grant_id":              "family-jti",
		"auth_time":             float64(testStart.Add(-5 * time.Minute).Unix()),
		"acr":                   "urn:goiabada:level1",
		"amr":                   []interface{}{"pwd"},
		"auth_state_generation": float64(6),
		"sid":                   "session-1",
		"aud":                   []interface{}{"authserver", "product-api"},
		"typ":                   "Bearer",
		"scope":                 "openid product-api:read",
		"nonce":                 "n-0S6_WzA2Mj",
	})
}

func TestAccessToken_PasswordGrant(t *testing.T) {
	testStart := time.Now().UTC()
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	expectSigningKeyAndUserLoads(t, mockDB)
	row := captureRefreshTokenRow(mockDB)
	user := &record.User{Id: 1, Subject: fake.UUID(), AuthStateGeneration: 2}

	response, err := tokenIssuer.IssuePasswordGrant(context.Background(), rfc9068Settings(), &ROPCGrantInput{
		Client: &record.Client{Id: 3, ClientIdentifier: "legacy-app", TokenExpirationInSeconds: 900},
		User:   user,
		Scope:  "openid product-api:read",
	})
	require.NoError(t, err)

	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(900), response.ExpiresIn, "the client's lifetime")
	require.NotEmpty(t, row.FirstRefreshTokenJti)
	claims := verifyAndDecodeToken(t, response.AccessToken, getTestPublicKey(t))
	assertWholeAccessToken(t, response.AccessToken, testStart, 900, map[string]interface{}{
		"iss":       "https://test-issuer.com",
		"sub":       user.Subject,
		"client_id": "legacy-app",
		"grant_id":  row.FirstRefreshTokenJti,
		// The password was checked for this request, so it was checked when the token was issued.
		"auth_time":             claims["iat"],
		"acr":                   "urn:goiabada:level1",
		"amr":                   []interface{}{"pwd"},
		"auth_state_generation": float64(2),
		"aud":                   []interface{}{"authserver", "product-api"},
		"typ":                   "Bearer",
		"scope":                 "openid product-api:read",
	})
}

func TestAccessToken_RefreshOfAPasswordGrant(t *testing.T) {
	testStart := time.Now().UTC()
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	authenticatedAt := testStart.Add(-time.Hour)
	parent := &record.RefreshToken{
		Id:                   2,
		RefreshTokenJti:      "parent-jti",
		FirstRefreshTokenJti: "family-jti",
		Scope:                "openid product-api:read",
		RefreshTokenType:     TokenTypeOffline.String(),
		AuthStateGeneration:  5,
		MaxLifetime:          sql.NullTime{Time: testStart.Add(time.Hour), Valid: true},
		AuthenticatedAt:      sql.NullTime{Time: authenticatedAt, Valid: true},
		User:                 record.User{Id: 1, Subject: fake.UUID(), AuthStateGeneration: 9},
		Client:               record.Client{Id: 3, ClientIdentifier: "legacy-app"},
	}
	mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, parent).Return(nil)
	mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, parent).Return(nil)
	expectSigningKeyAndUserLoads(t, mockDB)
	captureRefreshTokenRow(mockDB)

	response, err := tokenIssuer.mintROPCRefreshTokens(context.Background(), nil, rfc9068Settings(), parent, "")
	require.NoError(t, err)

	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(600), response.ExpiresIn, "the server's lifetime")
	assertWholeAccessToken(t, response.AccessToken, testStart, 600, map[string]interface{}{
		"iss":                   "https://test-issuer.com",
		"sub":                   parent.User.Subject,
		"client_id":             "legacy-app",
		"grant_id":              "family-jti",
		"auth_time":             float64(authenticatedAt.Unix()),
		"acr":                   "urn:goiabada:level1",
		"amr":                   []interface{}{"pwd"},
		"auth_state_generation": float64(5),
		"aud":                   []interface{}{"authserver", "product-api"},
		"typ":                   "Bearer",
		"scope":                 "openid product-api:read",
	})
}

// The client credentials token names the client as its subject and carries none of a user's
// claims. A claim scope in its request names no audience, unlike in a user grant's token.
func TestAccessToken_ClientCredentialsGrant(t *testing.T) {
	testStart := time.Now().UTC()
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, getTestPrivateKey(t)),
	}, nil)

	tests := []struct {
		name     string
		client   *record.Client
		scope    string
		lifetime int64
		wantAud  interface{}
	}{
		{
			name:     "one resource, the server's lifetime",
			client:   &record.Client{Id: 4, ClientIdentifier: "billing-service"},
			scope:    "product-api:read",
			lifetime: 600,
			wantAud:  "product-api",
		},
		{
			name:     "two resources and a claim scope, the client's lifetime",
			client:   &record.Client{Id: 4, ClientIdentifier: "billing-service", TokenExpirationInSeconds: 900},
			scope:    "product-api:read openid orders-api:write product-api:write",
			lifetime: 900,
			wantAud:  []interface{}{"product-api", "orders-api"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response, err := tokenIssuer.IssueClientCredentialsGrant(context.Background(), rfc9068Settings(), tc.client, tc.scope)
			require.NoError(t, err)

			assert.Equal(t, "Bearer", response.TokenType)
			assert.Equal(t, tc.lifetime, response.ExpiresIn)
			assert.Equal(t, tc.scope, response.Scope)
			assert.Empty(t, response.IdToken)
			assert.Empty(t, response.RefreshToken)
			assertWholeAccessToken(t, response.AccessToken, testStart, tc.lifetime, map[string]interface{}{
				"iss":       "https://test-issuer.com",
				"sub":       "billing-service",
				"client_id": "billing-service",
				"aud":       tc.wantAud,
				"typ":       "Bearer",
				"scope":     tc.scope,
			})
		})
	}
}

func TestAccessToken_ImplicitFlow(t *testing.T) {
	testStart := time.Now().UTC()
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	user := &record.User{Id: 1, Subject: fake.UUID()}
	mockDB.On("GetCurrentSigningKey", mock.Anything, issueTx).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, getTestPrivateKey(t)),
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, issueTx, user).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, issueTx, user.Groups).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, issueTx, user).Return(nil)
	authenticatedAt := testStart.Add(-2 * time.Minute)
	input := &ImplicitGrantInput{
		Client:              &record.Client{Id: 5, ClientIdentifier: "old-spa", TokenExpirationInSeconds: 900},
		User:                user,
		Scope:               "openid",
		AcrLevel:            record.AcrLevel2Mandatory,
		AuthMethods:         "pwd otp",
		SessionIdentifier:   "session-1",
		Nonce:               "n-0S6_WzA2Mj",
		AuthStateGeneration: 3,
		AuthenticatedAt:     authenticatedAt,
	}
	armImplicitTransaction(mockDB, input.SessionIdentifier)

	response, err := tokenIssuer.IssueImplicitTx(context.Background(), rfc9068Settings(), input, true, false)
	require.NoError(t, err)

	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(900), response.ExpiresIn, "the client's lifetime")
	assertWholeAccessToken(t, response.AccessToken, testStart, 900, map[string]interface{}{
		"iss":                   "https://test-issuer.com",
		"sub":                   user.Subject,
		"client_id":             "old-spa",
		"auth_time":             float64(authenticatedAt.Unix()),
		"acr":                   "urn:goiabada:level2_mandatory",
		"amr":                   []interface{}{"pwd", "otp"},
		"auth_state_generation": float64(3),
		"sid":                   "session-1",
		"aud":                   "authserver",
		"typ":                   "Bearer",
		"scope":                 "openid",
		"nonce":                 "n-0S6_WzA2Mj",
	})
}
