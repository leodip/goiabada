package integrationtests

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/stringutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The confidential-to-public flip as a security action (#245, decision 4 as amended by decision
// 16), observed end to end through the admin API.
//
// Every row below observes the revocation through a SUBSEQUENT REFUSAL TO REFRESH rather than by
// reading refresh_tokens.revoked. Reading the column is a storage side channel: it passes with the
// endpoint broken, and what actually matters to a deployment is that the grant stops working.
//
// The boundary and the sweep are tested separately on purpose. D1 passes under either design,
// because the token it presents existed when the flip ran; D7 is the one that tests the boundary,
// because the token it presents was inserted after the flip committed.

// flipToPublic runs the admin API's confidential-to-public transition and returns the decoded
// response body. The status is asserted here so every caller below reads as one line.
func flipToPublic(t *testing.T, adminToken string, clientId int64) api.UpdateClientResponse {
	t.Helper()

	apiURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" +
		strconv.FormatInt(clientId, 10) + "/authentication"
	resp := makeAPIRequest(t, "PUT", apiURL, adminToken, api.UpdateClientAuthenticationRequest{IsPublic: true})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body api.UpdateClientResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body
}

// flipToConfidential is the reverse transition, which must NOT revoke. It returns the secret it
// set, because a confidential client has to present one afterwards.
func flipToConfidential(t *testing.T, adminToken string, clientId int64) string {
	t.Helper()

	secret := stringutil.GenerateSecurityRandomString(60)
	apiURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" +
		strconv.FormatInt(clientId, 10) + "/authentication"
	resp := makeAPIRequest(t, "PUT", apiURL, adminToken,
		api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: secret})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return secret
}

// redeemCode exchanges a code this package's helpers issued. clientSecret is omitted when empty,
// which is what a public client must do: decision 11 refuses a superfluous secret on every arm.
func redeemCode(t *testing.T, httpClient *http.Client, code *models.Code, clientSecret string) map[string]interface{} {
	t.Helper()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}

	data := postToTokenEndpoint(t, httpClient, config.GetAuthServer().BaseURL+"/auth/token/", form)
	require.Nil(t, data["error"], "unexpected refusal at redemption: %v", data["error_description"])
	return data
}

// presentRefreshToken posts a refresh_token grant, omitting client_secret when it is empty.
func presentRefreshToken(t *testing.T, clientIdentifier, refreshToken, clientSecret string) map[string]interface{} {
	t.Helper()

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientIdentifier},
		"refresh_token": {refreshToken},
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	return postToTokenEndpoint(t, createHttpClient(t), config.GetAuthServer().BaseURL+"/auth/token/", form)
}

// requireDatabaseAuditLogs makes the audit_logs table the observable it is supposed to be. The
// seeded default has database persistence on, but the settings endpoint is itself under test in
// this package, so a row asserting an audit event either enables it deliberately or is hostage to
// what ran before it.
func requireDatabaseAuditLogs(t *testing.T) {
	t.Helper()

	settings, err := database.GetSettingsById(nil, 1)
	require.NoError(t, err)
	if settings.AuditLogsInDatabaseEnabled {
		return
	}
	settings.AuditLogsInDatabaseEnabled = true
	require.NoError(t, database.UpdateSettings(nil, settings))
	t.Cleanup(func() {
		current, err := database.GetSettingsById(nil, 1)
		if err == nil {
			current.AuditLogsInDatabaseEnabled = false
			_ = database.UpdateSettings(nil, current)
		}
	})
}

// D1. The flip revokes, and the event says so.
//
// The grant presented here existed when the flip ran, so BOTH gates could refuse it: its own row
// was swept, and the code it descends from was marked in the same transaction. The description is
// what says which one answered, and it must be the marker's, because that check lives in the
// validator ahead of the handler's revoked-row branch.
func TestAPIClientAuthenticationPut_FlipToPublic_RevokesTheClientsGrants(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, _ := createAdminClientWithToken(t)

	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")
	defer func() { _ = database.DeleteClient(nil, code.ClientId) }()

	tokens := redeemCode(t, httpClient, code, clientSecret)
	refreshToken, ok := tokens["refresh_token"].(string)
	require.True(t, ok, "the grant must carry a refresh token: %v", tokens)

	// The positive control. Without it a refusal below could mean the grant never worked.
	before := presentRefreshToken(t, code.Client.ClientIdentifier, refreshToken, clientSecret)
	require.Nil(t, before["error"], "the grant must refresh before the flip: %v", before["error_description"])
	rotated, ok := before["refresh_token"].(string)
	require.True(t, ok, "rotation must return a replacement: %v", before)

	flipToPublic(t, adminToken, code.ClientId)

	// No secret: the client is public now, and presenting one would be refused by decision 11's
	// rule instead, which is a different gate and would prove nothing about the revocation.
	after := presentRefreshToken(t, code.Client.ClientIdentifier, rotated, "")
	assert.Equal(t, "invalid_grant", after["error"], "the flip must revoke the client's grants: %v", after)
	assert.Equal(t, terminatedGrantMessage, after["error_description"],
		"the revoked-code marker must be the gate that answers, ahead of the handler's revoked-row branch: %v", after)
	assert.Empty(t, after["access_token"])
	assert.Empty(t, after["refresh_token"])

	// The audit record of the action, which is what tells an administrator afterwards that the
	// flip did this rather than that the grants failed for some other reason.
	logs, resp := getAuditLogs(t, adminToken, "auditEvent="+constants.AuditRevokedClientGrants)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	found := false
	for _, entry := range logs.AuditLogs {
		var details map[string]interface{}
		if err := json.Unmarshal([]byte(entry.Details), &details); err != nil {
			continue
		}
		if int64(details["clientId"].(float64)) != code.ClientId {
			continue
		}
		found = true
		assert.Equal(t, "client_became_public", details["reason"])
		assert.GreaterOrEqual(t, details["revokedCodeCount"], float64(1),
			"the marker is the durable half of the action and its count belongs in the record")
		assert.NotEmpty(t, details["revokedRefreshTokenJtis"],
			"the sweep is what gives the event actual JTIs rather than a count")
	}
	assert.True(t, found, "the flip must emit %v for this client", constants.AuditRevokedClientGrants)
}

// D2. The action is client-scoped, and this is the assertion that says so. The same user holds a
// grant on a second client, which must survive untouched: revoking by user, or deleting the user's
// sessions, would sign them out of every application they hold, which is exactly what #135 exists
// to avoid and what decision 4 refuses to do here.
func TestAPIClientAuthenticationPut_FlipToPublic_LeavesTheUsersOtherClientAlone(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)

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

	flippedSecret := gofakeit.LetterN(32)
	flippedClient, flippedCode := createAuthCode(t, flippedSecret, "openid profile email",
		authCodeOptions{user: user, userPassword: password})
	defer func() { _ = database.DeleteClient(nil, flippedCode.ClientId) }()

	// A DIFFERENT DEVICE for the second grant, which is a fixture requirement rather than
	// decoration: two ceremonies for one user from the same device replace each other's session,
	// so without this the first grant would be dead before the flip ever ran and the refusal
	// below would prove nothing.
	otherSecret := gofakeit.LetterN(32)
	otherClient, otherCode := createAuthCode(t, otherSecret, "openid profile email",
		authCodeOptions{user: user, userPassword: password, userAgent: "goiabada-d2-second-device"})
	defer func() { _ = database.DeleteClient(nil, otherCode.ClientId) }()

	// Both grants belong to the same person, which is the whole point of the fixture.
	require.Equal(t, flippedCode.UserId, otherCode.UserId,
		"both grants must belong to one user, or this proves only that two clients are different")

	flippedTokens := redeemCode(t, flippedClient, flippedCode, flippedSecret)
	otherTokens := redeemCode(t, otherClient, otherCode, otherSecret)
	otherRefresh, ok := otherTokens["refresh_token"].(string)
	require.True(t, ok, "the untouched grant must carry a refresh token: %v", otherTokens)

	flipToPublic(t, adminToken, flippedCode.ClientId)

	// The flipped client's grant is gone.
	flippedRefresh, ok := flippedTokens["refresh_token"].(string)
	require.True(t, ok)
	gone := presentRefreshToken(t, flippedCode.Client.ClientIdentifier, flippedRefresh, "")
	require.Equal(t, "invalid_grant", gone["error"], "the flipped client's grant must be revoked: %v", gone)

	// The other one is not.
	survives := presentRefreshToken(t, otherCode.Client.ClientIdentifier, otherRefresh, otherSecret)
	assert.Nil(t, survives["error"],
		"the same user's grant on another client must survive the flip: %v", survives["error_description"])
	assert.NotEmpty(t, survives["access_token"])
	assert.NotEmpty(t, survives["refresh_token"])
}

// D3. The second linkage shape. An ROPC refresh token has a NULL code_id, so the code marker
// cannot reach it and only the sweep can, which is why decision 16 kept the sweep after making the
// marker the boundary.
func TestAPIClientAuthenticationPut_FlipToPublic_RevokesROPCGrantsToo(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)

	settings, err := database.GetSettingsById(nil, 1)
	require.NoError(t, err)
	originalROPC := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	require.NoError(t, database.UpdateSettings(nil, settings))
	defer func() {
		current, err := database.GetSettingsById(nil, 1)
		if err == nil {
			current.ResourceOwnerPasswordCredentialsEnabled = originalROPC
			_ = database.UpdateSettings(nil, current)
		}
	}()

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	password := gofakeit.Password(true, true, true, true, false, 12)
	client := createROPCClient(t, clientSecret, false)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()
	user := createROPCUser(t, password)

	destURL := config.GetAuthServer().BaseURL + "/auth/token/"
	data := postToTokenEndpoint(t, createHttpClient(t), destURL, url.Values{
		"grant_type":    {"password"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"username":      {user.Email},
		"password":      {password},
		"scope":         {"openid offline_access"},
	})
	require.Nil(t, data["error"], "the ROPC grant must be issued: %v", data["error_description"])
	refreshToken, ok := data["refresh_token"].(string)
	require.True(t, ok, "the ROPC grant must carry a refresh token: %v", data)

	flipToPublic(t, adminToken, client.Id)

	after := presentRefreshToken(t, client.ClientIdentifier, refreshToken, "")
	assert.Equal(t, "invalid_grant", after["error"], "the flip must revoke the client's ROPC grants: %v", after)
	// The handler's revoked-row branch, not the marker's: an ROPC token descends from no code, so
	// the validator's code check skips it and the swept row is what refuses it. Asserted because
	// it is the evidence that the SWEEP did this, which is the whole point of the row.
	assert.Equal(t, "This refresh token has been revoked.", after["error_description"],
		"an ROPC token has no code to mark, so the sweep must be what refuses it: %v", after)
}

// D4. The reverse transition ADDS a requirement rather than removing one, so it must not revoke.
// Signing users out to protect against a window that just closed is pure collateral damage.
func TestAPIClientAuthenticationPut_FlipToConfidential_DoesNotRevoke(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)

	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email",
		authCodeOptions{isPublic: true})
	defer func() { _ = database.DeleteClient(nil, code.ClientId) }()

	tokens := redeemCode(t, httpClient, code, "")
	refreshToken, ok := tokens["refresh_token"].(string)
	require.True(t, ok, "the grant must carry a refresh token: %v", tokens)

	newSecret := flipToConfidential(t, adminToken, code.ClientId)

	after := presentRefreshToken(t, code.Client.ClientIdentifier, refreshToken, newSecret)
	assert.Nil(t, after["error"],
		"public to confidential closes a window rather than opening one, and must not revoke: %v", after["error_description"])
	assert.NotEmpty(t, after["access_token"])
}

// D5. Rotating a confidential client's secret REPLACES the requirement rather than removing it, so
// it must not revoke either. This is the row that fails against an implementation keying on
// req.IsPublic instead of on the transition.
func TestAPIClientAuthenticationPut_RotatingAConfidentialSecret_DoesNotRevoke(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)

	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")
	defer func() { _ = database.DeleteClient(nil, code.ClientId) }()

	tokens := redeemCode(t, httpClient, code, clientSecret)
	refreshToken, ok := tokens["refresh_token"].(string)
	require.True(t, ok, "the grant must carry a refresh token: %v", tokens)

	rotatedSecret := flipToConfidential(t, adminToken, code.ClientId)

	after := presentRefreshToken(t, code.Client.ClientIdentifier, refreshToken, rotatedSecret)
	assert.Nil(t, after["error"],
		"rotating a secret leaves the requirement to authenticate in place, and must not revoke: %v", after["error_description"])
	assert.NotEmpty(t, after["access_token"])
}

// D5b. Saving an already-public client is not a transition at all, so it must not revoke either.
// This is the row that fails against a guard written as `req.IsPublic` rather than as
// `req.IsPublic && !wasPublic`: under that shape an idempotent save, which the admin console emits
// every time somebody presses save on the authentication page, signs the client's users out.
func TestAPIClientAuthenticationPut_SavingAnAlreadyPublicClient_DoesNotRevoke(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)

	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email",
		authCodeOptions{isPublic: true})
	defer func() { _ = database.DeleteClient(nil, code.ClientId) }()

	tokens := redeemCode(t, httpClient, code, "")
	refreshToken, ok := tokens["refresh_token"].(string)
	require.True(t, ok, "the grant must carry a refresh token: %v", tokens)

	flipToPublic(t, adminToken, code.ClientId)

	after := presentRefreshToken(t, code.Client.ClientIdentifier, refreshToken, "")
	assert.Nil(t, after["error"],
		"a save that changes nothing about authentication must not revoke: %v", after["error_description"])
	assert.NotEmpty(t, after["access_token"])
}

// D6. The flip sets the requirement in the same write, so the client cannot spend a moment public
// and PKCE-optional, and so the console and the API report what the server enforces. Observed in
// the response body rather than in the column, which is the seam this change committed to.
func TestAPIClientAuthenticationPut_FlipToPublic_SetsPKCERequired(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)

	// Explicitly optional beforehand, so the assertion below cannot pass by the column having
	// been left alone.
	pkceOptional := false
	client := &models.Client{
		ClientIdentifier:         "flip-pkce-" + strings.ToLower(gofakeit.LetterN(10)),
		Enabled:                  true,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		PKCERequired:             &pkceOptional,
	}
	require.NoError(t, database.CreateClient(nil, client))
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	body := flipToPublic(t, adminToken, client.Id)

	assert.True(t, body.Client.IsPublic)
	require.NotNil(t, body.Client.PKCERequired, "the flip must write the column, not leave it inheriting the global")
	assert.True(t, *body.Client.PKCERequired, "a public client always requires PKCE")
}

// D7. The boundary itself, and the only row here that tests decision 16's answer rather than the
// sweep it kept: D1 passes under either design, because the token it presents existed when the
// flip ran.
//
// It is TestToken_Refresh_ChildOfATerminatedGrantIsBornRejected with the flip substituted for the
// session termination, and it carries that test's two guards for the same reason. The grant must
// be offline, or the refresh arm's session lookup refuses the child whatever the marker did; and
// the child must hold no session identifier of its own, which is what makes the code the only
// thing that can reach it.
func TestAPIClientAuthenticationPut_FlipToPublic_ChildBornAfterTheFlipIsRejected(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	grant := createOfflineGrant(t)

	parentRow, err := database.GetRefreshTokenByJti(nil, refreshTokenJti(t, grant.refreshToken))
	require.NoError(t, err)
	require.NotNil(t, parentRow, "the redeemed grant must have a refresh token row")

	// Rotate once while the client is still confidential, so the child under test is a genuine
	// server-minted token written by rotation rather than a fixture.
	rotated := grant.refresh(t)
	require.NotEmpty(t, rotated["access_token"], "the grant must refresh before the flip: %v", rotated)
	childToken, ok := rotated["refresh_token"].(string)
	require.True(t, ok, "rotation must return a replacement refresh token: %v", rotated)

	childJti := refreshTokenJti(t, childToken)
	childRow, err := database.GetRefreshTokenByJti(nil, childJti)
	require.NoError(t, err)
	require.NotNil(t, childRow, "the rotated child must have been persisted")

	// Decision 16's load-bearing property, asserted rather than assumed: the child hangs off the
	// SAME code as its parent, which is what lets one marker reject a whole grant including a
	// member that does not exist yet.
	require.True(t, childRow.CodeId.Valid, "an auth-code-derived refresh token must carry a code id")
	require.Equal(t, parentRow.CodeId.Int64, childRow.CodeId.Int64,
		"the rotated child must inherit its parent's code id, or nothing below tests the marker")

	// And the two requirements that stop this being the benign member of its class.
	require.Equal(t, "Offline", childRow.RefreshTokenType,
		"the grant must be offline, or the Refresh branch's session check refuses it whatever the marker does")
	require.Empty(t, childRow.SessionIdentifier,
		"an offline token carries no session identifier of its own, which is why only the code can reach it")

	flipToPublic(t, adminToken, grant.client.Id)

	// One: the child that already existed when the flip ran. Its own row was swept and its code
	// was marked in the same transaction, so both gates could refuse it, and the description says
	// the marker did.
	afterSweep := presentRefreshToken(t, grant.client.ClientIdentifier, childToken, "")
	assert.Equal(t, "invalid_grant", afterSweep["error"],
		"the child of a flipped client's grant must not refresh: %v", afterSweep)
	assert.Equal(t, terminatedGrantMessage, afterSweep["error_description"],
		"the revoked-code marker must be the gate that answers, ahead of the handler's revoked-row branch: %v", afterSweep)

	// Two: the child the sweep never saw, which is the window decision 16 exists to close.
	//
	// THE ONE COLUMN CLEARED BELOW IS THE ONLY THING THE INTERLEAVING DECIDES. Rotation claims the
	// presented token and inserts its replacement in two separate autocommit operations, so a
	// refresh whose insert lands after the flip's sweep read refresh_tokens leaves exactly this
	// row state: revoked = false on the child, its code_id pointing at the code the same flip
	// marked. Nothing here fabricates a grant: the JWT was minted by the server, the row was
	// written by rotation, the code was marked by the real PUT above, and the client really is
	// public now.
	swept, err := database.GetRefreshTokenByJti(nil, childJti)
	require.NoError(t, err)
	require.NotNil(t, swept)
	require.True(t, swept.Revoked,
		"the flip's sweep must have revoked the child that existed when it ran, or the fixture below means nothing")

	swept.Revoked = false
	require.NoError(t, database.UpdateRefreshToken(nil, swept))
	relived, err := database.GetRefreshTokenByJti(nil, childJti)
	require.NoError(t, err)
	require.False(t, relived.Revoked, "the child must be live again, or this case proves nothing")

	familyBefore, err := database.GetRefreshTokensByCodeId(nil, childRow.CodeId.Int64)
	require.NoError(t, err)

	// This is the presentation that would succeed under a sweep alone: the row is live, so the
	// handler's compare-and-set claim wins and rotation mints a working replacement.
	born := presentRefreshToken(t, grant.client.ClientIdentifier, childToken, "")
	assert.Equal(t, "invalid_grant", born["error"],
		"a live child born after the flip committed must still be refused: %v", born)
	assert.Equal(t, terminatedGrantMessage, born["error_description"],
		"only the revoked-code marker can refuse a child whose own row is live: %v", born)
	assert.Empty(t, born["access_token"], "no access token may be issued for a revoked grant")
	assert.Empty(t, born["refresh_token"], "no replacement may be issued for a revoked grant")

	familyAfter, err := database.GetRefreshTokensByCodeId(nil, childRow.CodeId.Int64)
	require.NoError(t, err)
	assert.Len(t, familyAfter, len(familyBefore), "a refused presentation must mint no descendant")
}
