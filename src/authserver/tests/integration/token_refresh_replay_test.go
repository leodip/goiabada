package integrationtests

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exchangeAuthCode redeems a code and returns the refresh token from the response.
func exchangeAuthCode(t *testing.T, httpClient *http.Client, clientIdentifier, clientSecret,
	code, redirectURI, codeVerifier string) string {
	t.Helper()

	data := postToTokenEndpoint(t, httpClient, config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientIdentifier},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
		"client_secret": {clientSecret},
	})
	require.NotNil(t, data["refresh_token"], "the authorization code exchange must return a refresh token")
	return data["refresh_token"].(string)
}

// rotateRefreshToken presents a refresh token and returns the successor from the response.
func rotateRefreshToken(t *testing.T, httpClient *http.Client, clientIdentifier, clientSecret,
	refreshToken string) string {
	t.Helper()

	data := postToTokenEndpoint(t, httpClient, config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientIdentifier},
		"refresh_token": {refreshToken},
		"client_secret": {clientSecret},
	})
	require.NotNil(t, data["refresh_token"], "a legitimate rotation must return a successor refresh token")
	return data["refresh_token"].(string)
}

// replayRefreshToken presents a refresh token expecting refusal, and returns the status and
// body so the caller can assert both. It uses concurrentTokenPost rather than
// postToTokenEndpoint because that helper hides the status code, and 400-versus-500 is
// exactly what these cases are about.
func replayRefreshToken(t *testing.T, httpClient *http.Client, clientIdentifier, clientSecret,
	refreshToken string) (int, map[string]interface{}) {
	t.Helper()

	status, body, err := concurrentTokenPost(httpClient, config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientIdentifier},
		"refresh_token": {refreshToken},
		"client_secret": {clientSecret},
	})
	require.NoError(t, err, "replay request failed at the transport level")
	return status, body
}

// assertRefusedAsInvalidGrant is the refusal every replay must produce: a 400 carrying
// invalid_grant, never a 500 and never token material.
func assertRefusedAsInvalidGrant(t *testing.T, status int, body map[string]interface{}, what string) {
	t.Helper()

	assert.Equalf(t, http.StatusBadRequest, status, "%s must be refused with 400", what)
	require.NotNilf(t, body, "%s must return a JSON error body, not an HTML error page", what)
	assert.Equalf(t, "invalid_grant", body["error"], "%s must be refused as invalid_grant", what)
	assert.Nilf(t, body["access_token"], "%s must not yield an access_token", what)
	assert.Nilf(t, body["refresh_token"], "%s must not yield a refresh_token", what)
}

// refreshTokenRowByJti loads the persisted row behind a serialized refresh token.
func refreshTokenRowByJti(t *testing.T, refreshToken string) *models.RefreshToken {
	t.Helper()

	row, err := database.GetRefreshTokenByJti(nil, refreshTokenJti(t, refreshToken))
	require.NoError(t, err)
	require.NotNil(t, row, "the refresh token row must exist")
	return row
}

// codeOnSameSessionForNewClient creates a SECOND confidential client and runs an
// authorization on the browser session httpClient already holds, returning an unredeemed
// code for it.
//
// prompt=none is deliberate: with a live session and no consent required it goes straight
// to /auth/issue, so the test does not depend on the exact interactive redirect chain.
// This is what produces two independent rotation families on one browser session, which is
// the fixture the family-scope boundary case needs.
func codeOnSameSessionForNewClient(t *testing.T, httpClient *http.Client, clientSecret string,
	scope string) (*models.Client, string, string) {
	t.Helper()

	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
	require.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "second-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 false,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	require.NoError(t, database.CreateClient(nil, client))

	redirectURI := &models.RedirectURI{ClientId: client.Id, URI: gofakeit.URL()}
	require.NoError(t, database.CreateRedirectURI(nil, redirectURI))

	const codeVerifier = "code-verifier-second-client"
	destURL := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code&code_challenge_method=S256" +
		"&code_challenge=" + oauth.GeneratePKCECodeChallenge(codeVerifier) +
		"&scope=" + url.QueryEscape(scope) +
		"&state=" + gofakeit.LetterN(8) + "&nonce=" + gofakeit.LetterN(8) +
		"&prompt=none"

	resp, err := httpClient.Get(destURL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	location := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, location)
	code, _ := getCodeAndStateFromUrl(t, resp)
	_ = resp.Body.Close()
	require.NotEmpty(t, code, "expected a code from the SSO path on the existing session")

	return client, redirectURI.URI, code
}

// TestToken_Refresh_Replay_ContainsFamily is the core of defect 2 (#128): replaying a
// retired refresh token must revoke the live member that superseded it.
//
// Before this landed, replay was refused and nothing else happened, so a thief who stole a
// token and lost the rotation race simply waited and kept using the family, while the
// legitimate holder was the one locked out. That is the inversion the issue exists to fix.
func TestToken_Refresh_Replay_ContainsFamily(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	rt1 := exchangeAuthCode(t, httpClient, code.Client.ClientIdentifier, clientSecret,
		code.Code, code.RedirectURI, "code-verifier")

	// A legitimate rotation: rt1 retires, rt2 is live.
	rt2 := rotateRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rt1)
	require.NotEqual(t, rt1, rt2, "rotation must return a different token")
	require.False(t, refreshTokenRowByJti(t, rt2).Revoked, "the successor must start out live")

	// Now replay the retired parent.
	status, body := replayRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rt1)
	assertRefusedAsInvalidGrant(t, status, body, "a replayed refresh token")

	// The containment that did not happen before: the live successor is revoked too.
	assert.True(t, refreshTokenRowByJti(t, rt2).Revoked,
		"replaying the retired parent must revoke the live successor")

	// And the successor is genuinely dead at the endpoint, not merely flagged.
	status, body = replayRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rt2)
	assertRefusedAsInvalidGrant(t, status, body, "the contained successor")
}

// TestToken_Refresh_Replay_DoesNotContainOtherFamilies pins decision 3: containment is
// scoped to the rotation family, NOT to the browser session.
//
// This is the only test that fails if containment is widened to session scope, which is
// what the authorization-code reuse path does (it revokes by session identifier and deletes
// the session). That is right for a code replay, which implicates the browser ceremony, and
// wrong for a refresh token replay, which implicates one grant's client-side storage.
// Widening it would punish the legitimate user for the thief's access.
func TestToken_Refresh_Replay_DoesNotContainOtherFamilies(t *testing.T) {
	secretA := gofakeit.Password(true, true, true, true, false, 32)
	httpClient, codeA := createAuthCode(t, secretA, "openid profile email")

	// A second client, federated onto the SAME browser session, with its own family.
	secretB := gofakeit.Password(true, true, true, true, false, 32)
	clientB, redirectB, rawCodeB := codeOnSameSessionForNewClient(t, httpClient, secretB, "openid profile")

	storedCodeA, err := database.GetCodeById(nil, codeA.Id)
	require.NoError(t, err)
	storedCodeB := loadCodeFromDatabase(t, rawCodeB)
	require.Equal(t, storedCodeA.SessionIdentifier, storedCodeB.SessionIdentifier,
		"the fixture is only meaningful if both codes share one browser session")

	rtA1 := exchangeAuthCode(t, httpClient, codeA.Client.ClientIdentifier, secretA,
		codeA.Code, codeA.RedirectURI, "code-verifier")
	rtB1 := exchangeAuthCode(t, httpClient, clientB.ClientIdentifier, secretB,
		rawCodeB, redirectB, "code-verifier-second-client")

	rtA2 := rotateRefreshToken(t, httpClient, codeA.Client.ClientIdentifier, secretA, rtA1)

	// Replay family A.
	status, body := replayRefreshToken(t, httpClient, codeA.Client.ClientIdentifier, secretA, rtA1)
	assertRefusedAsInvalidGrant(t, status, body, "a replayed refresh token")
	assert.True(t, refreshTokenRowByJti(t, rtA2).Revoked, "family A's live member must be revoked")

	// Family B must be untouched. The ORDER matters: B is exercised AFTER the replay, not
	// before, or it would prove nothing about what containment did.
	assert.False(t, refreshTokenRowByJti(t, rtB1).Revoked,
		"family B shares the browser session but not the family: it must stay live")
	rtB2 := rotateRefreshToken(t, httpClient, clientB.ClientIdentifier, secretB, rtB1)
	require.NotEqual(t, rtB1, rtB2, "family B must still rotate after family A was contained")

	// The browser session itself must survive. A third authorization riding the same
	// session is what proves it: containment must not have deleted or invalidated it.
	_, _, rawCodeC := codeOnSameSessionForNewClient(t, httpClient, gofakeit.Password(true, true, true, true, false, 32), "openid")
	storedCodeC := loadCodeFromDatabase(t, rawCodeC)
	assert.Equal(t, storedCodeA.SessionIdentifier, storedCodeC.SessionIdentifier,
		"the browser session must survive containment and still serve new authorizations")
}

// TestToken_Refresh_Replay_ContainsROPCFamily is decision 3 from the other side. A ROPC
// family has no authorization code at all, so a containment query scoped to code_id would
// find nothing here and this is the case that would expose it. The authorization-code test
// above cannot stand in for it.
func TestToken_Refresh_Replay_ContainsROPCFamily(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	require.NoError(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	require.NoError(t, database.UpdateSettings(nil, settings))
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	password := gofakeit.Password(true, true, true, true, false, 12)
	client := createROPCClient(t, clientSecret, false)
	user := createROPCUser(t, password)

	httpClient := createHttpClient(t)
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	data := postToTokenEndpoint(t, httpClient, destUrl, url.Values{
		"grant_type":    {"password"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"username":      {user.Email},
		"password":      {password},
		"scope":         {"openid"},
	})
	require.NotNil(t, data["refresh_token"], "the ROPC grant must return a refresh token")
	rt1 := data["refresh_token"].(string)

	// The shape that makes this case distinct: no code row behind the family.
	row1 := refreshTokenRowByJti(t, rt1)
	require.False(t, row1.CodeId.Valid, "a ROPC refresh token must have no code_id")
	require.NotEmpty(t, row1.FirstRefreshTokenJti, "the family identifier must still be stamped")

	rt2 := rotateRefreshToken(t, httpClient, client.ClientIdentifier, clientSecret, rt1)
	require.False(t, refreshTokenRowByJti(t, rt2).Revoked, "the ROPC successor must start out live")

	status, body := replayRefreshToken(t, httpClient, client.ClientIdentifier, clientSecret, rt1)
	assertRefusedAsInvalidGrant(t, status, body, "a replayed ROPC refresh token")

	assert.True(t, refreshTokenRowByJti(t, rt2).Revoked,
		"replaying a retired ROPC token must revoke the live successor")
}

// TestToken_Refresh_Replay_RepeatIsANoOp pins that containment is idempotent: a family with
// nothing left to revoke changes nothing on a further replay.
//
// updated_at is the assertion that carries weight. Both rows are already revoked, so the
// `revoked = false` predicate matches nothing and no row is touched; if the statement had
// matched, it would have bumped the timestamp. That is also what makes the zero count
// meaningful, since the count is what gates the audit event and stops a client from
// amplifying the log by replaying repeatedly.
//
// The ABSENCE of a second audit event is asserted at the unit tier
// (TestHandleTokenPost_Refresh_Replay_AuditsContainment and the already-revoked subtest),
// not here: this tier cannot see the audit logger.
func TestToken_Refresh_Replay_RepeatIsANoOp(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	rt1 := exchangeAuthCode(t, httpClient, code.Client.ClientIdentifier, clientSecret,
		code.Code, code.RedirectURI, "code-verifier")
	rt2 := rotateRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rt1)

	// First replay: this is the one that contains the family.
	status, body := replayRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rt1)
	assertRefusedAsInvalidGrant(t, status, body, "the first replay")

	before, err := database.GetRefreshTokensByCodeId(nil, code.Id)
	require.NoError(t, err)
	require.NotEmpty(t, before)
	snapshot := make(map[int64]models.RefreshToken, len(before))
	for _, rt := range before {
		require.Truef(t, rt.Revoked, "every family member must be revoked after the first replay (id %d)", rt.Id)
		snapshot[rt.Id] = *rt
	}

	// Second replay of the same token, and a replay of the already-contained successor.
	status, body = replayRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rt1)
	assertRefusedAsInvalidGrant(t, status, body, "a repeated replay")
	status, body = replayRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, rt2)
	assertRefusedAsInvalidGrant(t, status, body, "a replay of the contained successor")

	after, err := database.GetRefreshTokensByCodeId(nil, code.Id)
	require.NoError(t, err)
	require.Len(t, after, len(before), "no row may be added or removed by a repeated replay")

	for _, rt := range after {
		was, ok := snapshot[rt.Id]
		require.Truef(t, ok, "unexpected new refresh token row %d", rt.Id)
		assert.Equalf(t, was.Revoked, rt.Revoked, "row %d changed its revoked state", rt.Id)
		assert.Truef(t, was.UpdatedAt.Time.Equal(rt.UpdatedAt.Time),
			"row %d was written again by a no-op containment (updated_at %v -> %v)",
			rt.Id, was.UpdatedAt.Time, rt.UpdatedAt.Time)
	}
}
