package issuance

import (
	"context"
	"testing"
	"time"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The tokens the server issues pass #709's structural check and the auth server's own parser, which
// runs that check before the signature: the access, ID and refresh tokens of a code exchange, and
// the access token of the client credentials grant, whose builder differed until the two shared
// one finishing step.
func TestIssuedTokensPassTheStructuralCheckAndTheParser(t *testing.T) {
	now := time.Now().UTC()
	mockDB := datamocks.NewDatabase(t)
	tokenIssuer := NewTokenIssuer(mockDB, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	code := sessionBoundCode(now)
	code.Scope = "openid profile email product-api:read"
	code.Nonce = "n-0S6_WzA2Mj"
	code.User.Email = "ana@example.com"

	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "session-1").
		Return(&record.UserSession{Id: 1, UserId: 1, Started: now.Add(-10 * time.Minute)}, nil)
	expectSigningKeyAndUserLoads(t, mockDB)
	captureRefreshTokenRow(mockDB)

	codeTokens, err := tokenIssuer.mintAuthorizationCodeTokens(context.Background(), rfc9068Settings(), code, "")
	require.NoError(t, err)
	clientTokens, err := tokenIssuer.IssueClientCredentialsGrant(context.Background(), rfc9068Settings(), &record.Client{Id: 4, ClientIdentifier: "billing-service"}, "product-api:read", "")

	require.NoError(t, err)

	parserDB := datamocks.NewDatabase(t)
	parserDB.On("GetCurrentSigningKey", mock.Anything, mock.Anything).
		Return(&record.KeyPair{PublicKeyPEM: getTestPublicKey(t)}, nil)
	parser := signingkeys.NewTokenParser(parserDB)

	for name, token := range map[string]string{
		"the code exchange's access token":     codeTokens.AccessToken,
		"the code exchange's ID token":         codeTokens.IdToken,
		"the code exchange's refresh token":    codeTokens.RefreshToken,
		"the client credentials grant's token": clientTokens.AccessToken,
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEmpty(t, token)
			require.NoError(t, oauth.CheckJWTStructure(token))

			parsed, err := parser.DecodeAndValidateTokenString(context.Background(), token, true)
			require.NoError(t, err)
			assert.Equal(t, "https://test-issuer.com", parsed.StringClaim("iss"))
		})
	}
}
