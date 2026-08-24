package integrationtests

import (
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The public-client PKCE mandate on the refresh arm (#245, decision 3), and decision 11's
// secret symmetry.
//
// This is where the durable exposure is. A code lives 60 seconds; a refresh token descended
// from a challenge-less code keeps minting access tokens for the whole life of the grant, and
// once the client is public nothing at all is presented to redeem it. The check costs nothing:
// the refresh arm already loads the code to read its user and its revocation marker, so the
// stored challenge is in hand.
//
// C1 and C2 use SEPARATE grants on purpose. A refresh token is one-shot under rotation (#128),
// so reusing one across the two rows would make the second fail for replay rather than for the
// rule under test, and it would pass either way.

// challengelessRefreshToken mints a grant with no PKCE binding and returns its refresh token
// along with the client's row id and identifier. The client is confidential at this point,
// which is what makes the grant legitimate when it is issued.
func challengelessRefreshToken(t *testing.T, clientSecret string) (string, int64, string, string) {
	t.Helper()

	requireChallengelessCodesAreStorable(t)

	pkceRequired := false
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email",
		authCodeOptions{noPKCE: true, pkceRequired: &pkceRequired})

	require.Empty(t, code.CodeChallenge.String,
		"the grant must descend from a code bound to no challenge")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	data := postToTokenEndpoint(t, httpClient, destUrl, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
	})
	require.Nil(t, data["error"], "unexpected refusal at redemption: %v", data["error_description"])
	require.NotEmpty(t, data["refresh_token"])

	return data["refresh_token"].(string), code.ClientId, code.Client.ClientIdentifier, destUrl
}

// C1. The grant outlives the configuration it was issued under, and this is what catches it.
func TestToken_Refresh_ChallengelessGrant_RefusedOnceTheClientIsPublic(t *testing.T) {
	refreshToken, clientId, clientIdentifier, destUrl := challengelessRefreshToken(t, gofakeit.LetterN(32))

	client, err := database.GetClientById(nil, clientId)
	require.NoError(t, err)
	client.IsPublic = true
	client.ClientSecretEncrypted = nil
	require.NoError(t, database.UpdateClient(nil, client))

	data := postToTokenEndpoint(t, createHttpClient(t), destUrl, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientIdentifier},
		"refresh_token": {refreshToken},
	})

	assert.Equal(t, "invalid_grant", data["error"])
	// Asserted on the description because more than one gate could refuse this token, and only
	// the description says which one ran.
	assert.Contains(t, data["error_description"], "public clients are required to use PKCE")
}

// C2. The positive control, on its own grant. The same challenge-less shape still refreshes
// while the client authenticates.
func TestToken_Refresh_ChallengelessGrant_ConfidentialClientStillRefreshes(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	refreshToken, _, clientIdentifier, destUrl := challengelessRefreshToken(t, clientSecret)

	data := postToTokenEndpoint(t, createHttpClient(t), destUrl, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientIdentifier},
		"client_secret": {clientSecret},
		"refresh_token": {refreshToken},
	})

	require.Nil(t, data["error"], "unexpected refusal: %v", data["error_description"])
	assert.NotEmpty(t, data["access_token"])
	assert.NotEmpty(t, data["refresh_token"])
}

// C3, decision 11. A public client that presents a client_secret on the refresh arm is now
// refused rather than having it silently ignored, which is what the authorization_code arm has
// always done.
//
// This is symmetry rather than a defect fix, and the population it breaks is real: an
// application whose administrator has just flipped it to public still holds the secret that was
// deleted server-side. The release note says so.
func TestToken_Refresh_PublicClient_PresentingASecret_IsRefused(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email",
		authCodeOptions{isPublic: true})

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	data := postToTokenEndpoint(t, httpClient, destUrl, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
	})
	require.Nil(t, data["error"], "unexpected refusal at redemption: %v", data["error_description"])
	refreshToken := data["refresh_token"].(string)

	data = postToTokenEndpoint(t, httpClient, destUrl, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {"a-secret-this-client-does-not-have"},
		"refresh_token": {refreshToken},
	})

	assert.Equal(t, "invalid_request", data["error"])
	assert.Contains(t, data["error_description"], "remove the client_secret from your request")
}
