package integrationtests

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The public-client PKCE mandate at the authorization endpoint (#245).
//
// RFC 9700 section 4.8.1 is the attack these close: "The attacker intercepts the request and
// removes the entire code_challenge parameter from the request. ... If the authorization
// server allows for flows without PKCE, it will create a code that is not bound to any PKCE
// code challenge", which the attacker can then spend against a client that authenticates with
// nothing. RFC 7636 section 4.4.1 fixes the answer once the server does require it: the
// authorization endpoint "MUST return the authorization error response with the 'error' value
// set to 'invalid_request'".
//
// Before this change there was NO integration coverage of the public-client authorization code
// flow at all, in either direction, so A2 is as much of the point as A1: it is the first test
// that drives a public client through a whole ceremony and gets tokens out of it.
//
// The refusals arrive deferred rather than immediately. Per #213 /auth/authorize never
// redirects an unauthenticated browser to a client's redirect_uri on a failed request, so the
// error is parked on the auth context and emitted from /auth/level1completed once the password
// is verified. That is why every negative row here drives the ceremony instead of reading the
// first response.

// newPublicPKCEClient creates a public client with the given stored pkce_required, plus a
// redirect URI and a user able to complete a level 1 ceremony for it.
//
// pkceRequired is a pointer because nil is one of the states under test: it is what
// /connect/register leaves behind, and A4 is about it inheriting a global setting that is off.
func newPublicPKCEClient(t *testing.T, pkceRequired *bool) (*models.Client, string, *models.User, string) {
	t.Helper()

	client := &models.Client{
		ClientIdentifier:         "public-pkce-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
		PKCERequired:             pkceRequired,
	}
	require.NoError(t, database.CreateClient(nil, client))

	redirectURI := "https://public-pkce.example.com/callback"
	require.NoError(t, database.CreateRedirectURI(nil, &models.RedirectURI{
		ClientId: client.Id,
		URI:      redirectURI,
	}))

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	require.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	require.NoError(t, database.CreateUser(nil, user))

	return client, redirectURI, user, password
}

// authorizeURLWithoutChallenge is the request the attack in RFC 9700 4.8.1 produces: a
// well-formed authorization request with code_challenge and code_challenge_method stripped out.
func authorizeURLWithoutChallenge(clientIdentifier, redirectURI string) string {
	return config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + clientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile email") +
		"&state=" + gofakeit.LetterN(8) +
		"&nonce=" + gofakeit.LetterN(8)
}

// authorizeErrorFromLocation reads the error pair out of an emitted error redirect.
func authorizeErrorFromLocation(t *testing.T, resp *http.Response) (string, string) {
	t.Helper()

	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	return location.Query().Get("error"), location.Query().Get("error_description")
}

// assertRefusedForMissingChallenge drives the deferral to its end and asserts the refusal. The
// mechanism is authorize_validator's input.PKCERequired arm, which is reached only because the
// model rule makes IsPKCERequired return true for a public client whatever the row says.
func assertRefusedForMissingChallenge(t *testing.T, client *models.Client, redirectURI string,
	user *models.User, password string) {

	t.Helper()

	httpClient := createHttpClient(t)
	resp := driveDeferral(t, httpClient,
		authorizeURLWithoutChallenge(client.ClientIdentifier, redirectURI), user, password)
	defer func() { _ = resp.Body.Close() }()

	errCode, errDescription := authorizeErrorFromLocation(t, resp)
	assert.Equal(t, "invalid_request", errCode,
		"RFC 7636 section 4.4.1 fixes this error code once the server requires PKCE")
	assert.Contains(t, errDescription, "code_challenge")
}

// A1. The baseline refusal: a public client with the stored column left alone.
func TestAuthorize_PublicClient_WithoutCodeChallenge_IsRefused(t *testing.T) {
	client, redirectURI, user, password := newPublicPKCEClient(t, nil)

	assertRefusedForMissingChallenge(t, client, redirectURI, user, password)
}

// A3. The stored column says PKCE is not required, and the client is refused anyway. This is
// the first of the two ways into the defect: an explicit false override on a public client.
func TestAuthorize_PublicClient_StoredPKCERequiredFalse_IsStillRefused(t *testing.T) {
	pkceRequired := false
	client, redirectURI, user, password := newPublicPKCEClient(t, &pkceRequired)

	assertRefusedForMissingChallenge(t, client, redirectURI, user, password)
}

// A4. The second way in, and the one a migration alone cannot close: the column is NULL and the
// global setting is off, which is exactly what /connect/register leaves behind. A settings
// change made long after the migration ran must not reopen this.
func TestAuthorize_PublicClient_NullColumnAndGlobalPKCEOff_IsStillRefused(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	require.NoError(t, err)

	original := settings.PKCERequired
	settings.PKCERequired = false
	require.NoError(t, database.UpdateSettings(nil, settings))
	defer func() {
		settings.PKCERequired = original
		_ = database.UpdateSettings(nil, settings)
	}()

	client, redirectURI, user, password := newPublicPKCEClient(t, nil)

	assertRefusedForMissingChallenge(t, client, redirectURI, user, password)
}

// A2. The positive control, and the coverage that has never existed: a public client running
// the whole authorization code flow with PKCE, redeeming its code with a verifier and no
// secret, and getting tokens.
//
// Without this row every assertion above is satisfied by a server that refuses public clients
// outright, which is not what the mandate says.
func TestAuthorize_PublicClient_WithPKCE_CompletesAndIssuesTokens(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email",
		authCodeOptions{isPublic: true})

	assert.True(t, code.Client.IsPublic, "the fixture must be a public client")
	assert.NotEmpty(t, code.CodeChallenge.String, "the ceremony must have bound a challenge")

	data := postToTokenEndpoint(t, httpClient, config.GetAuthServer().BaseURL+"/auth/token/",
		url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {code.Client.ClientIdentifier},
			"code":          {code.Code},
			"redirect_uri":  {code.RedirectURI},
			"code_verifier": {"code-verifier"},
		})

	require.Nil(t, data["error"], "unexpected refusal: %v", data["error_description"])
	assert.NotEmpty(t, data["access_token"])
	assert.NotEmpty(t, data["id_token"])
	assert.Equal(t, "Bearer", data["token_type"])
}

// A5. The mandate is public-only. A confidential client with PKCE turned off still runs a
// challenge-less ceremony to completion, so nothing here has widened into the population #245
// is not about.
func TestAuthorize_ConfidentialClient_PKCEOff_WithoutCodeChallenge_Succeeds(t *testing.T) {
	requireChallengelessCodesAreStorable(t)

	pkceRequired := false
	_, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email",
		authCodeOptions{noPKCE: true, pkceRequired: &pkceRequired})

	assert.False(t, code.Client.IsPublic, "the fixture must be a confidential client")
	assert.Empty(t, code.CodeChallenge.String,
		"the ceremony must have minted a code bound to no challenge, which is the point of the row")

	// The challenge really is absent rather than merely unequal to a computed one.
	assert.NotEqual(t, oauth.GeneratePKCECodeChallenge("code-verifier"), code.CodeChallenge.String)
}
