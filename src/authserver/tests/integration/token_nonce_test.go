package integration

import (
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The nonce of the authorization request is in the ID token of the sign-in and in no other token:
// not in the code exchange's access token, and in neither token of a refresh. OpenID Connect Core
// 1.0 section 12.2 says a refreshed ID token SHOULD NOT have a nonce (#710 decision 6).
func TestToken_Nonce_OnlyInTheIDTokenOfTheCodeExchange(t *testing.T) {
	clientSecret := fake.Password(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile")
	require.NotEmpty(t, code.Nonce, "the authorization request sent a nonce")

	destURL := appConfig.AuthServer.BaseURL + "/auth/token/"
	exchanged := postToTokenEndpointWithBasicAuth(t, httpClient, destURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
	}, code.Client.ClientIdentifier, clientSecret)

	idToken, ok := exchanged["id_token"].(string)
	require.True(t, ok, "the code exchange issues an ID token: %v", exchanged)
	assert.Equal(t, code.Nonce, decodeJWTPayload(t, idToken)["nonce"], "the sign-in's ID token carries the request's nonce")
	accessToken, ok := exchanged["access_token"].(string)
	require.True(t, ok, "the code exchange issues an access token: %v", exchanged)
	assert.NotContains(t, decodeJWTPayload(t, accessToken), "nonce", "the code exchange's access token has no nonce")

	refreshToken, ok := exchanged["refresh_token"].(string)
	require.True(t, ok, "the code exchange issues a refresh token: %v", exchanged)
	refreshed := postToTokenEndpointWithBasicAuth(t, httpClient, destURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}, code.Client.ClientIdentifier, clientSecret)

	refreshedIDToken, ok := refreshed["id_token"].(string)
	require.True(t, ok, "the refresh issues an ID token: %v", refreshed)
	refreshedIDClaims := decodeJWTPayload(t, refreshedIDToken)
	assert.Equal(t, code.Client.ClientIdentifier, refreshedIDClaims["aud"], "the refreshed ID token is the client's")
	assert.NotContains(t, refreshedIDClaims, "nonce", "a refreshed ID token has no nonce")
	refreshedAccessToken, ok := refreshed["access_token"].(string)
	require.True(t, ok, "the refresh issues an access token: %v", refreshed)
	assert.NotContains(t, decodeJWTPayload(t, refreshedAccessToken), "nonce", "a refreshed access token has no nonce")
}

// The implicit flow's ID token carries the request's nonce, and its access token none (#710
// decision 6).
func TestImplicitFlow_NonceOnlyInTheIDToken(t *testing.T) {
	tokens, _, nonce := implicitTokenResponse(t, "id_token token", "openid")

	require.NotEmpty(t, tokens["id_token"], "the implicit flow issues an ID token")
	assert.Equal(t, nonce, decodeJWTPayload(t, tokens["id_token"])["nonce"], "the ID token carries the request's nonce")
	require.NotEmpty(t, tokens["access_token"], "the implicit flow issues an access token")
	assert.NotContains(t, decodeJWTPayload(t, tokens["access_token"]), "nonce", "the implicit flow's access token has no nonce")
}
