package issuance

// An access token issued for a request that carried a valid DPoP proof is bound to the proof's key:
// it carries cnf.jkt, the key's thumbprint (RFC 9449 section 6.1), and the response says token_type
// DPoP (section 5). The body's typ stays Bearer, Goiabada's label for an access token, bound or not
// (#42 decisions 2 and 3). The ID and refresh tokens issued beside it carry no cnf. Every grant the
// token endpoint redeems is held here; without a thumbprint each grant's token is the one
// access_token_grants_test.go holds.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// boundThumbprint is the RFC 7638 thumbprint of RFC 7517 appendix A.2's P-256 key.
const boundThumbprint = "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s"

// assertBoundTokenResponse checks that response answers a bound access token: token_type DPoP,
// cnf.jkt the thumbprint, typ still Bearer, and no cnf on the ID or refresh token beside it.
func assertBoundTokenResponse(t *testing.T, response *oauth.TokenResponse) {
	t.Helper()
	assert.Equal(t, "DPoP", response.TokenType)

	claims := verifyAndDecodeToken(t, response.AccessToken, getTestPublicKey(t))
	assert.Equal(t, map[string]interface{}{"jkt": boundThumbprint}, claims["cnf"], "cnf.jkt is the key's thumbprint")
	assert.Equal(t, "Bearer", claims["typ"], "the body's typ is the access-token label, bound or not")

	for name, token := range map[string]string{"ID": response.IdToken, "refresh": response.RefreshToken} {
		if token == "" {
			continue
		}
		assert.NotContains(t, verifyAndDecodeToken(t, token, getTestPublicKey(t)), "cnf", "the %s token carries no cnf", name)
	}
}

func TestBoundAccessToken_AuthorizationCodeGrant(t *testing.T) {
	testStart := time.Now().UTC()
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	code := sessionBoundCode(testStart)

	mockDB.On("MarkCodeAsUsed", mock.Anything, mock.Anything, code.Id).Return(true, nil)
	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "session-1").
		Return(&record.UserSession{Id: 1, UserId: 1, Started: testStart.Add(-10 * time.Minute)}, nil)
	expectSigningKeyAndUserLoads(t, mockDB)
	row := captureRefreshTokenRow(mockDB)

	response, err := tokenIssuer.IssueAuthorizationCodeGrant(context.Background(), rfc9068Settings(), code, boundThumbprint)
	require.NoError(t, err)

	assertBoundTokenResponse(t, response)
	require.NotEmpty(t, response.IdToken)
	require.NotEmpty(t, response.RefreshToken)
	assertWholeAccessToken(t, response.AccessToken, testStart, 600, map[string]interface{}{
		"iss":                   "https://test-issuer.com",
		"sub":                   code.User.Subject,
		"client_id":             "web-app",
		"grant_id":              row.FirstRefreshTokenJti,
		"auth_time":             float64(testStart.Add(-5 * time.Minute).Unix()),
		"acr":                   "urn:goiabada:level1",
		"amr":                   []interface{}{"pwd"},
		"auth_state_generation": float64(0),
		"sid":                   "session-1",
		"aud":                   []interface{}{"authserver", "product-api"},
		"typ":                   "Bearer",
		"scope":                 "openid product-api:read",
		"cnf":                   map[string]interface{}{"jkt": boundThumbprint},
	})
}

func TestBoundAccessToken_RefreshOfACodeGrant(t *testing.T) {
	testStart := time.Now().UTC()
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	code := sessionBoundCode(testStart)
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
		Return(&record.UserSession{Id: 1, UserId: 1, Started: testStart.Add(-10 * time.Minute)}, nil)
	expectSigningKeyAndUserLoads(t, mockDB)
	captureRefreshTokenRow(mockDB)

	response, err := tokenIssuer.mintCodeRefreshTokens(context.Background(), nil, rfc9068Settings(), code, parent, "", boundThumbprint)
	require.NoError(t, err)

	assertBoundTokenResponse(t, response)
	require.NotEmpty(t, response.RefreshToken)
}

func TestBoundAccessToken_PasswordGrant(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	expectSigningKeyAndUserLoads(t, mockDB)
	captureRefreshTokenRow(mockDB)

	response, err := tokenIssuer.IssuePasswordGrant(context.Background(), rfc9068Settings(), &ROPCGrantInput{
		Client:         &record.Client{Id: 3, ClientIdentifier: "legacy-app"},
		User:           &record.User{Id: 1, Subject: fake.UUID()},
		Scope:          "openid product-api:read",
		DPoPThumbprint: boundThumbprint,
	})
	require.NoError(t, err)

	assertBoundTokenResponse(t, response)
	require.NotEmpty(t, response.RefreshToken)
}

func TestBoundAccessToken_RefreshOfAPasswordGrant(t *testing.T) {
	testStart := time.Now().UTC()
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	parent := &record.RefreshToken{
		Id:                   2,
		RefreshTokenJti:      "parent-jti",
		FirstRefreshTokenJti: "family-jti",
		Scope:                "openid product-api:read",
		RefreshTokenType:     TokenTypeOffline.String(),
		MaxLifetime:          sql.NullTime{Time: testStart.Add(time.Hour), Valid: true},
		AuthenticatedAt:      sql.NullTime{Time: testStart.Add(-time.Hour), Valid: true},
		User:                 record.User{Id: 1, Subject: fake.UUID()},
		Client:               record.Client{Id: 3, ClientIdentifier: "legacy-app"},
	}
	mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, parent).Return(nil)
	mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, parent).Return(nil)
	expectSigningKeyAndUserLoads(t, mockDB)
	captureRefreshTokenRow(mockDB)

	response, err := tokenIssuer.mintROPCRefreshTokens(context.Background(), nil, rfc9068Settings(), parent, "", boundThumbprint)
	require.NoError(t, err)

	assertBoundTokenResponse(t, response)
	require.NotEmpty(t, response.RefreshToken)
}

func TestBoundAccessToken_ClientCredentialsGrant(t *testing.T) {
	testStart := time.Now().UTC()
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	mockDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, getTestPrivateKey(t)),
	}, nil)

	response, err := tokenIssuer.IssueClientCredentialsGrant(context.Background(), rfc9068Settings(),
		&record.Client{Id: 4, ClientIdentifier: "billing-service"}, "product-api:read", boundThumbprint)
	require.NoError(t, err)

	assertBoundTokenResponse(t, response)
	assertWholeAccessToken(t, response.AccessToken, testStart, 600, map[string]interface{}{
		"iss":       "https://test-issuer.com",
		"sub":       "billing-service",
		"client_id": "billing-service",
		"aud":       "product-api",
		"typ":       "Bearer",
		"scope":     "product-api:read",
		"cnf":       map[string]interface{}{"jkt": boundThumbprint},
	})
}
