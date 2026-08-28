package integrationtests

import (
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The public-client PKCE mandate at redemption (#245, decision 3).
//
// The rule at /auth/authorize closes new ceremonies. It cannot reach a code that already
// exists, and it cannot reach a code minted while the client was still confidential and
// redeemed a moment after it became public. That is what these rows are for: the check is
// keyed on whether the client is public NOW, read at the moment of use, so one rule covers the
// misconfiguration, the legacy row and the transition alike.
//
// B1 flips the client with database.UpdateClient rather than through the admin API. That is
// fixture setup, not an assertion about storage: the endpoint flip, its transaction and its
// revocation are stage 4's D series, and pinning them here would make this file fail for
// reasons that have nothing to do with the redemption rule.

// challengelessCode mints a code carrying no PKCE challenge, from a confidential client with
// PKCE turned off. Both are needed: the seeded Settings.PKCERequired is true, so the ceremony
// itself would be refused at /auth/authorize without the explicit false.
func challengelessCode(t *testing.T, clientSecret string) (*models.Code, string) {
	t.Helper()

	pkceRequired := false
	_, code := createAuthCode(t, clientSecret, "openid profile email",
		authCodeOptions{noPKCE: true, pkceRequired: &pkceRequired})

	require.Empty(t, code.CodeChallenge.String,
		"the fixture must carry no challenge, or none of these rows measures anything")

	return code, config.GetAuthServer().BaseURL + "/auth/token/"
}

// B1. The transition. The code was legitimate when it was minted, and the client's secret was
// what bound it. Once the secret stops being required the code is bound to nothing, and it has
// up to 60 seconds of life left in which anybody holding it can spend it.
func TestToken_AuthCode_ChallengelessCode_RefusedAfterClientBecomesPublic(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	code, destUrl := challengelessCode(t, clientSecret)

	client, err := database.GetClientById(nil, code.ClientId)
	require.NoError(t, err)
	client.IsPublic = true
	client.ClientSecretEncrypted = nil
	require.NoError(t, database.UpdateClient(nil, client))

	// No secret and no verifier, which is everything a public client has to present.
	data := postToTokenEndpoint(t, createHttpClient(t), destUrl, url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {code.Client.ClientIdentifier},
		"code":         {code.Code},
		"redirect_uri": {code.RedirectURI},
	})

	assert.Equal(t, "invalid_grant", data["error"],
		"RFC 6749 section 5.2 covers a grant that is invalid")
	assert.Contains(t, data["error_description"], "public clients are required to use PKCE")
}

// B2. The positive control. The same code, redeemed by the client that still authenticates,
// still works, so the refusal above is about the client being public and not about the code.
func TestToken_AuthCode_ChallengelessCode_ConfidentialClientStillSucceeds(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	code, destUrl := challengelessCode(t, clientSecret)

	data := postToTokenEndpoint(t, createHttpClient(t), destUrl, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
	})

	require.Nil(t, data["error"], "unexpected refusal: %v", data["error_description"])
	assert.NotEmpty(t, data["access_token"])
}

// B3. The row that pins decision 3's choice of IsPublic over IsPKCERequired. An administrator
// hardening a confidential client by turning PKCE on must not thereby invalidate every code
// and grant already outstanding: those are still authenticated by the secret, and refusing them
// would make a security improvement look like an outage.
func TestToken_AuthCode_ChallengelessCode_SurvivesTurningPKCEOnForAConfidentialClient(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	code, destUrl := challengelessCode(t, clientSecret)

	client, err := database.GetClientById(nil, code.ClientId)
	require.NoError(t, err)
	pkceRequired := true
	client.PKCERequired = &pkceRequired
	require.NoError(t, database.UpdateClient(nil, client))

	data := postToTokenEndpoint(t, createHttpClient(t), destUrl, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
	})

	require.Nil(t, data["error"], "unexpected refusal: %v", data["error_description"])
	assert.NotEmpty(t, data["access_token"])
}
