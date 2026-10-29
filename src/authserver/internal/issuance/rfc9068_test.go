package issuance

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Access tokens follow RFC 9068 (#676 decisions 2 and 3): every one carries the JOSE header typ
// at+jwt (section 2.1) and the client_id of the client it was issued to (section 2.2), and those of
// the grants that also issue a refresh token carry grant_id, the identifier their refresh token
// family shares, its first refresh token's jti. ID and refresh tokens keep the library's JWT header.

// tokenHeader decodes a JWT's JOSE header without verifying anything.
func tokenHeader(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	encoded, _, ok := strings.Cut(token, ".")
	require.True(t, ok, "a JWT has a header segment")
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	var header map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &header))
	return header
}

// assertAccessTokenHeader asserts an access token's header, and that the ID and refresh tokens
// issued beside it keep theirs.
func assertTokenHeaders(t *testing.T, accessToken, idToken, refreshToken string) {
	t.Helper()
	assert.Equal(t, map[string]interface{}{"alg": "RS256", "typ": "at+jwt", "kid": "test-key-id"}, tokenHeader(t, accessToken),
		"the access token's header")
	if idToken != "" {
		assert.Equal(t, "JWT", tokenHeader(t, idToken)["typ"], "the ID token's header")
	}
	if refreshToken != "" {
		assert.Equal(t, "JWT", tokenHeader(t, refreshToken)["typ"], "the refresh token's header")
	}
}

func rfc9068Settings() *record.Settings {
	return &record.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}
}

// expectSigningKeyAndUserLoads arms the reads every user grant makes besides its own.
func expectSigningKeyAndUserLoads(t *testing.T, mockDB *datamocks.Database) {
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, getTestPrivateKey(t)),
	}, nil)
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("UserLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
}

// captureRefreshTokenRow arms CreateRefreshToken and answers the row it is handed.
func captureRefreshTokenRow(mockDB *datamocks.Database) *record.RefreshToken {
	row := &record.RefreshToken{}
	mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything, mock.AnythingOfType("*record.RefreshToken")).
		Run(func(args mock.Arguments) { *row = *args.Get(2).(*record.RefreshToken) }).
		Return(nil).Once()
	return row
}

func sessionBoundCode(now time.Time) *record.Code {
	return &record.Code{
		Id:                1,
		ClientId:          1,
		UserId:            1,
		Scope:             "openid product-api:read",
		AuthenticatedAt:   now.Add(-5 * time.Minute),
		SessionIdentifier: "session-1",
		AcrLevel:          record.AcrLevel1,
		AuthMethods:       "pwd",
		Client:            record.Client{Id: 1, ClientIdentifier: "web-app"},
		User:              record.User{Id: 1, Subject: fake.UUID()},
	}
}

// The code exchange fixes the grant's identifier before it mints the access token: the access
// token's grant_id is the jti of the refresh token issued beside it, which the row records as its
// family's first.
func TestRFC9068_AuthorizationCodeGrant(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	now := time.Now().UTC()
	code := sessionBoundCode(now)

	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "session-1").
		Return(&record.UserSession{Id: 1, UserId: 1, Started: now.Add(-10 * time.Minute)}, nil)
	expectSigningKeyAndUserLoads(t, mockDB)
	row := captureRefreshTokenRow(mockDB)

	response, err := tokenIssuer.mintAuthorizationCodeTokens(context.Background(), rfc9068Settings(), code)
	require.NoError(t, err)

	assertTokenHeaders(t, response.AccessToken, response.IdToken, response.RefreshToken)
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, getTestPublicKey(t))
	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, getTestPublicKey(t))
	assert.Equal(t, "web-app", accessClaims["client_id"])
	require.NotEmpty(t, row.FirstRefreshTokenJti)
	assert.Equal(t, row.FirstRefreshTokenJti, accessClaims["grant_id"], "the family's identifier")
	assert.Equal(t, refreshClaims["jti"], accessClaims["grant_id"], "the first refresh token's jti")
	assert.Equal(t, row.RefreshTokenJti, row.FirstRefreshTokenJti, "the first refresh token starts its family")
}

// A refresh copies the grant's identifier from its parent, whatever the parent's own jti.
func TestRFC9068_RefreshOfACodeGrant(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	now := time.Now().UTC()
	code := sessionBoundCode(now)
	parent := &record.RefreshToken{
		Id:                   2,
		RefreshTokenJti:      "parent-jti",
		FirstRefreshTokenJti: "family-jti",
		Scope:                code.Scope,
		RefreshTokenType:     TokenTypeRefresh.String(),
	}

	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "session-1").
		Return(&record.UserSession{Id: 1, UserId: 1, Started: now.Add(-10 * time.Minute)}, nil)
	expectSigningKeyAndUserLoads(t, mockDB)
	row := captureRefreshTokenRow(mockDB)

	response, err := tokenIssuer.mintCodeRefreshTokens(context.Background(), nil, rfc9068Settings(), code, parent, "")
	require.NoError(t, err)

	assertTokenHeaders(t, response.AccessToken, response.IdToken, response.RefreshToken)
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, getTestPublicKey(t))
	assert.Equal(t, "web-app", accessClaims["client_id"])
	assert.Equal(t, "family-jti", accessClaims["grant_id"])
	assert.Equal(t, "family-jti", row.FirstRefreshTokenJti, "the child stays in its parent's family")
}

func TestRFC9068_PasswordGrant(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	expectSigningKeyAndUserLoads(t, mockDB)
	row := captureRefreshTokenRow(mockDB)

	response, err := tokenIssuer.IssuePasswordGrant(context.Background(), rfc9068Settings(), &ROPCGrantInput{
		Client: &record.Client{Id: 3, ClientIdentifier: "legacy-app"},
		User:   &record.User{Id: 1, Subject: fake.UUID()},
		Scope:  "openid product-api:read",
	})
	require.NoError(t, err)

	assertTokenHeaders(t, response.AccessToken, response.IdToken, response.RefreshToken)
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, getTestPublicKey(t))
	refreshClaims := verifyAndDecodeToken(t, response.RefreshToken, getTestPublicKey(t))
	assert.Equal(t, "legacy-app", accessClaims["client_id"])
	require.NotEmpty(t, row.FirstRefreshTokenJti)
	assert.Equal(t, row.FirstRefreshTokenJti, accessClaims["grant_id"])
	assert.Equal(t, refreshClaims["jti"], accessClaims["grant_id"])
}

func TestRFC9068_RefreshOfAPasswordGrant(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	now := time.Now().UTC()
	parent := &record.RefreshToken{
		Id:                   2,
		RefreshTokenJti:      "parent-jti",
		FirstRefreshTokenJti: "family-jti",
		Scope:                "openid product-api:read",
		RefreshTokenType:     TokenTypeOffline.String(),
		MaxLifetime:          sql.NullTime{Time: now.Add(time.Hour), Valid: true},
		AuthenticatedAt:      sql.NullTime{Time: now.Add(-time.Hour), Valid: true},
		User:                 record.User{Id: 1, Subject: fake.UUID()},
		Client:               record.Client{Id: 3, ClientIdentifier: "legacy-app"},
	}
	mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, parent).Return(nil)
	mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, parent).Return(nil)
	expectSigningKeyAndUserLoads(t, mockDB)
	row := captureRefreshTokenRow(mockDB)

	response, err := tokenIssuer.mintROPCRefreshTokens(context.Background(), nil, rfc9068Settings(), parent, "")
	require.NoError(t, err)

	assertTokenHeaders(t, response.AccessToken, response.IdToken, response.RefreshToken)
	accessClaims := verifyAndDecodeToken(t, response.AccessToken, getTestPublicKey(t))
	assert.Equal(t, "legacy-app", accessClaims["client_id"])
	assert.Equal(t, "family-jti", accessClaims["grant_id"])
	assert.Equal(t, "family-jti", row.FirstRefreshTokenJti)
}

// The client credentials grant issues no refresh token, so its token names no grant.
func TestRFC9068_ClientCredentialsGrant(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, getTestPrivateKey(t)),
	}, nil)

	response, err := tokenIssuer.IssueClientCredentialsGrant(context.Background(), rfc9068Settings(),
		&record.Client{Id: 4, ClientIdentifier: "billing-service"}, "product-api:read")
	require.NoError(t, err)

	assertTokenHeaders(t, response.AccessToken, "", "")
	claims := verifyAndDecodeToken(t, response.AccessToken, getTestPublicKey(t))
	assert.Equal(t, "billing-service", claims["client_id"])
	assert.Equal(t, "billing-service", claims["sub"])
	assert.NotContains(t, claims, "grant_id")
}

// The implicit flow issues no refresh token either.
func TestRFC9068_ImplicitFlow(t *testing.T) {
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
	input := &ImplicitGrantInput{
		Client:            &record.Client{Id: 5, ClientIdentifier: "old-spa"},
		User:              user,
		Scope:             "openid",
		AcrLevel:          record.AcrLevel1,
		AuthMethods:       "pwd",
		SessionIdentifier: "session-1",
		AuthenticatedAt:   time.Now().UTC(),
	}
	armImplicitTransaction(mockDB, input.SessionIdentifier)

	response, err := tokenIssuer.IssueImplicitTx(context.Background(), rfc9068Settings(), input, true, true)
	require.NoError(t, err)

	assertTokenHeaders(t, response.AccessToken, response.IdToken, "")
	claims := verifyAndDecodeToken(t, response.AccessToken, getTestPublicKey(t))
	assert.Equal(t, "old-spa", claims["client_id"])
	assert.NotContains(t, claims, "grant_id")
}

// offline_access names authserver as an audience, as the claim scopes do, since the auth server is
// the one resource it means anything to (#676 decision 3, RFC 9068 section 2.2.3). The scope itself
// is unchanged.
func TestRFC9068_OfflineAccessNamesTheAuthServer(t *testing.T) {
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(getTestPrivateKey(t))
	require.NoError(t, err)
	now := time.Now().UTC()

	tests := []struct {
		scope   string
		wantAud interface{}
	}{
		{scope: "offline_access product-api:read", wantAud: []interface{}{"authserver", "product-api"}},
		{scope: "product-api:read offline_access", wantAud: []interface{}{"product-api", "authserver"}},
		{scope: "openid offline_access product-api:read", wantAud: []interface{}{"authserver", "product-api"}},
		{scope: "openid offline_access", wantAud: "authserver"},
		{scope: "offline_access", wantAud: "authserver"},
		{scope: "product-api:read", wantAud: "product-api"},
	}

	for _, tc := range tests {
		t.Run(tc.scope, func(t *testing.T) {
			tokenIssuer := NewTokenIssuer(datamocks.NewDatabase(t), "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
			input := &tokenGenerationInput{
				User:            &record.User{Subject: fake.UUID()},
				Client:          &record.Client{ClientIdentifier: "web-app"},
				Scope:           tc.scope,
				AcrLevel:        record.AcrLevel1,
				AuthenticatedAt: now,
			}

			token, err := tokenIssuer.generateAccessTokenCore(context.Background(), nil, rfc9068Settings(), input, now, privKey, "test-key-id")
			require.NoError(t, err)

			claims := verifyAndDecodeToken(t, token, getTestPublicKey(t))
			assert.Equal(t, tc.wantAud, claims["aud"])
			assert.Equal(t, tc.scope, claims["scope"])
		})
	}
}
