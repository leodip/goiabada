package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIAccount_ASubjectWithSurroundingWhitespaceNamesOneUser drives an account API token whose
// sub is the user's subject with whitespace around it. The bearer middleware looks the user up by
// the trimmed subject and the per-subject rate limiter keys on it; the account handlers used to
// read the raw claim, so the same token was authenticated as the user and then served as nobody.
// All three now read reqctx's one spelling. The auth server mints no such subject, so the token is
// a real one re-signed with the current signing key, its sub padded.
func TestAPIAccount_ASubjectWithSurroundingWhitespaceNamesOneUser(t *testing.T) {
	_, accessToken, code := getUserAccessTokenAndCodeForAccountScope(t)

	claims := jwt.MapClaims(decodeJWTPayload(t, accessToken))
	require.Equal(t, code.User.Subject, claims["sub"])
	claims["sub"] = " " + code.User.Subject + "\t"

	keyPair, err := database.GetCurrentSigningKey(context.Background(), nil)
	require.NoError(t, err)
	privKey, err := signingkeys.ParsePrivateKey(dataCipher, keyPair)
	require.NoError(t, err)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyPair.KeyIdentifier
	paddedToken, err := token.SignedString(privKey)
	require.NoError(t, err)

	t.Run("the profile is the user's", func(t *testing.T) {
		resp := makeAPIRequest(t, "GET", appConfig.AuthServer.BaseURL+"/api/v1/account/profile", paddedToken, nil)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var got api.GetUserResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, code.User.Id, got.User.Id)
	})

	t.Run("the logout hint names the user's subject", func(t *testing.T) {
		resp := makeAPIRequest(t, "POST", appConfig.AuthServer.BaseURL+"/api/v1/account/logout-request", paddedToken,
			api.AccountLogoutRequest{
				PostLogoutRedirectUri: code.RedirectURI,
				State:                 fake.LetterN(12),
				ResponseMode:          "redirect",
			})
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var out api.AccountLogoutRedirectResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
		logoutUrl, err := url.Parse(out.LogoutUrl)
		require.NoError(t, err)
		hint := logoutUrl.Query().Get("id_token_hint")
		require.NotEmpty(t, hint)
		assert.Equal(t, code.User.Subject, decodeJWTPayload(t, hint)["sub"])
	})
}
