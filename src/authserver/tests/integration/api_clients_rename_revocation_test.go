package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A change of a client's identifier revokes the client's grants, in the settings save that writes
// it, and the audit log records it as revoked_client_grants with the reason
// client_identifier_changed (#710 decision 5). A refresh token names its client by row, not by
// identifier, so no check of the token could tell a rename happened: the revocation is what keeps a
// refreshed ID token's aud the original's (OpenID Connect Core 1.0 section 12.2).
//
// These follow the switch to public's tests in api_clients_flip_revocation_test.go case for case,
// and observe the revocation the same way: through the token endpoint's refusal to refresh, under
// the identifier the client now holds, having refreshed before.

// saveClientSettings runs the admin API's settings save of the client with its stored settings and
// the identifier given, and asserts it succeeded.
func saveClientSettings(t *testing.T, adminToken string, clientID int64, identifier string) {
	t.Helper()

	stored, err := database.GetClientByID(context.Background(), nil, clientID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	request := api.UpdateClientSettingsRequest{
		ClientIdentifier:  identifier,
		Description:       stored.Description,
		WebsiteURL:        stored.WebsiteURL,
		PrivacyPolicyURL:  stored.PrivacyPolicyURL,
		TermsOfServiceURL: stored.TermsOfServiceURL,
		DisplayName:       stored.DisplayName,
		Enabled:           stored.Enabled,
		ConsentRequired:   stored.ConsentRequired,
		ShowLogo:          stored.ShowLogo,
		ShowDisplayName:   stored.ShowDisplayName,
		ShowDescription:   stored.ShowDescription,
		ShowWebsiteURL:    stored.ShowWebsiteURL,
	}
	if stored.AuthorizationCodeEnabled {
		request.DefaultACRLevel = stored.DefaultACRLevel.String()
	}

	apiURL := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientID, 10)
	resp := makeAPIRequest(t, "PUT", apiURL, adminToken, request)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body api.UpdateClientResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, identifier, body.Client.ClientIdentifier)
}

// renamedIdentifier is a fresh identifier for a client to be renamed to.
func renamedIdentifier() string {
	return "renamed-" + fake.LetterN(10)
}

// revokedClientGrantsEvents answers the details of every revoked_client_grants event of the client.
func revokedClientGrantsEvents(t *testing.T, adminToken string, clientID int64) []map[string]interface{} {
	t.Helper()

	logs, resp := getAuditLogs(t, adminToken, "auditEvent="+audit.EventRevokedClientGrants)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var events []map[string]interface{}
	for _, entry := range logs.AuditLogs {
		var details map[string]interface{}
		if err := json.Unmarshal([]byte(entry.Details), &details); err != nil {
			continue
		}
		if id, ok := details["client_id"].(float64); ok && int64(id) == clientID {
			events = append(events, details)
		}
	}
	return events
}

// R1. A rename revokes the client's grants, and the event says why. The refresh token presented
// existed when the rename ran, so both the swept row and the marked code could refuse it, and the
// description says the marker did, as for the switch to public.
func TestAPIClientUpdatePut_Rename_RevokesTheClientsGrants(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, _ := createAdminClientWithToken(t)

	clientSecret := fake.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")
	defer func() { _ = database.DeleteClient(context.Background(), nil, code.ClientID) }()

	tokens := redeemCode(t, httpClient, code, clientSecret)
	refreshToken, ok := tokens["refresh_token"].(string)
	require.True(t, ok, "the grant must carry a refresh token: %v", tokens)

	before := presentRefreshToken(t, code.Client.ClientIdentifier, refreshToken, clientSecret)
	require.Nil(t, before["error"], "the grant must refresh before the rename: %v", before["error_description"])
	rotated, ok := before["refresh_token"].(string)
	require.True(t, ok, "rotation must return a replacement: %v", before)

	renamed := renamedIdentifier()
	saveClientSettings(t, adminToken, code.ClientID, renamed)

	after := presentRefreshToken(t, renamed, rotated, clientSecret)
	assert.Equal(t, "invalid_grant", after["error"], "the rename must revoke the client's grants: %v", after)
	assert.Equal(t, terminatedGrantMessage, after["error_description"],
		"the revoked-code marker must be the gate that answers: %v", after)
	assert.Empty(t, after["access_token"])
	assert.Empty(t, after["refresh_token"])

	// The identifier the rename gave up names no client any more.
	underOldName := presentRefreshToken(t, code.Client.ClientIdentifier, rotated, clientSecret)
	assert.Equal(t, "invalid_client", underOldName["error"], "%v", underOldName)

	events := revokedClientGrantsEvents(t, adminToken, code.ClientID)
	require.Len(t, events, 1, "the rename must emit %v for this client", audit.EventRevokedClientGrants)
	assert.Equal(t, "client_identifier_changed", events[0]["reason"])
	assert.GreaterOrEqual(t, events[0]["revoked_code_count"], float64(1))
	assert.Equal(t, []interface{}{refreshTokenJTI(t, rotated)}, events[0]["revoked_refresh_token_jtis"],
		"the live refresh token the rename revoked, and not the one rotation had already revoked")
}

// R2. The revocation is the client's: the same user's grant on another client survives.
func TestAPIClientUpdatePut_Rename_LeavesTheUsersOtherClientAlone(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: fake.Email(), PasswordHash: passwordHashed}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))

	renamedSecret := fake.LetterN(32)
	renamedClient, renamedCode := createAuthCode(t, renamedSecret, "openid profile email",
		authCodeOptions{user: user, userPassword: password})
	defer func() { _ = database.DeleteClient(context.Background(), nil, renamedCode.ClientID) }()

	otherSecret := fake.LetterN(32)
	otherClient, otherCode := createAuthCode(t, otherSecret, "openid profile email",
		authCodeOptions{user: user, userPassword: password})
	defer func() { _ = database.DeleteClient(context.Background(), nil, otherCode.ClientID) }()
	require.Equal(t, renamedCode.UserID, otherCode.UserID)

	renamedTokens := redeemCode(t, renamedClient, renamedCode, renamedSecret)
	otherTokens := redeemCode(t, otherClient, otherCode, otherSecret)
	otherRefresh, ok := otherTokens["refresh_token"].(string)
	require.True(t, ok, "the untouched grant must carry a refresh token: %v", otherTokens)

	renamed := renamedIdentifier()
	saveClientSettings(t, adminToken, renamedCode.ClientID, renamed)

	renamedRefresh, ok := renamedTokens["refresh_token"].(string)
	require.True(t, ok)
	gone := presentRefreshToken(t, renamed, renamedRefresh, renamedSecret)
	require.Equal(t, "invalid_grant", gone["error"], "the renamed client's grant must be revoked: %v", gone)

	survives := presentRefreshToken(t, otherCode.Client.ClientIdentifier, otherRefresh, otherSecret)
	assert.Nil(t, survives["error"],
		"the same user's grant on another client must survive the rename: %v", survives["error_description"])
	assert.NotEmpty(t, survives["access_token"])
	assert.NotEmpty(t, survives["refresh_token"])
}

// R3. A password grant has no code to mark, so the sweep is what revokes its refresh token.
func TestAPIClientUpdatePut_Rename_RevokesPasswordGrantsToo(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	changeSettings(t, func(settings *record.Settings) { settings.ResourceOwnerPasswordCredentialsEnabled = true })

	clientSecret := fake.Password(32)
	password := fake.Password(12)
	client := createROPCClient(t, clientSecret, false)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.ID) }()
	user := createROPCUser(t, password)

	data := postToTokenEndpoint(t, createHTTPClient(t), appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"password"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"username":      {user.Email},
		"password":      {password},
		"scope":         {"openid offline_access"},
	})
	require.Nil(t, data["error"], "the password grant must be issued: %v", data["error_description"])
	refreshToken, ok := data["refresh_token"].(string)
	require.True(t, ok, "the password grant must carry a refresh token: %v", data)

	renamed := renamedIdentifier()
	saveClientSettings(t, adminToken, client.ID, renamed)

	after := presentRefreshToken(t, renamed, refreshToken, clientSecret)
	assert.Equal(t, "invalid_grant", after["error"], "the rename must revoke the client's password grants: %v", after)
	assert.Equal(t, "This refresh token has been revoked.", after["error_description"],
		"a password grant's token has no code to mark, so the sweep must be what refuses it: %v", after)

	// A new password grant under the new identifier is issued as normal.
	again := postToTokenEndpoint(t, createHTTPClient(t), appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"password"},
		"client_id":     {renamed},
		"client_secret": {clientSecret},
		"username":      {user.Email},
		"password":      {password},
		"scope":         {"openid offline_access"},
	})
	assert.Nil(t, again["error"], "a sign-in under the new identifier works: %v", again["error_description"])
	assert.NotEmpty(t, again["refresh_token"])
}

// R4. A save whose identifier is the one the client holds changes no identifier, so it revokes
// nothing and records no revocation: an administrator pressing save on the settings tab does not
// sign the client's users out.
func TestAPIClientUpdatePut_UnchangedIdentifier_DoesNotRevoke(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, _ := createAdminClientWithToken(t)

	clientSecret := fake.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")
	defer func() { _ = database.DeleteClient(context.Background(), nil, code.ClientID) }()

	tokens := redeemCode(t, httpClient, code, clientSecret)
	refreshToken, ok := tokens["refresh_token"].(string)
	require.True(t, ok, "the grant must carry a refresh token: %v", tokens)

	saveClientSettings(t, adminToken, code.ClientID, code.Client.ClientIdentifier)

	after := presentRefreshToken(t, code.Client.ClientIdentifier, refreshToken, clientSecret)
	assert.Nil(t, after["error"], "a save that keeps the identifier must not revoke: %v", after["error_description"])
	assert.NotEmpty(t, after["access_token"])
	assert.Empty(t, revokedClientGrantsEvents(t, adminToken, code.ClientID),
		"and must not record a revocation")
}

// R5. The boundary: a child born after the rename committed, into the grant the rename revoked, is
// refused by the mark on its code, as after a switch to public. The fixture is the one
// TestAPIClientAuthenticationPut_FlipToPublic_ChildBornAfterTheFlipIsRejected builds, for its
// reasons: an offline grant, whose child carries no session identifier of its own.
func TestAPIClientUpdatePut_Rename_ChildBornAfterTheRenameIsRejected(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	grant := createOfflineGrant(t)

	rotated := grant.refresh(t)
	require.NotEmpty(t, rotated["access_token"], "the grant must refresh before the rename: %v", rotated)
	childToken, ok := rotated["refresh_token"].(string)
	require.True(t, ok, "rotation must return a replacement refresh token: %v", rotated)
	childJTI := refreshTokenJTI(t, childToken)

	renamed := renamedIdentifier()
	saveClientSettings(t, adminToken, grant.client.ID, renamed)

	afterSweep := presentRefreshToken(t, renamed, childToken, grant.clientSecret)
	assert.Equal(t, "invalid_grant", afterSweep["error"], "%v", afterSweep)
	assert.Equal(t, terminatedGrantMessage, afterSweep["error_description"], "%v", afterSweep)

	// The row state a rotation that inserted its child after the rename's sweep read the tokens
	// leaves: live, its code marked by the same rename.
	swept, err := database.GetRefreshTokenByJTI(context.Background(), nil, childJTI)
	require.NoError(t, err)
	require.NotNil(t, swept)
	require.True(t, swept.Revoked, "the rename's sweep must have revoked the child that existed when it ran")
	swept.Revoked = false
	require.NoError(t, database.UpdateRefreshToken(context.Background(), nil, swept))

	born := presentRefreshToken(t, renamed, childToken, grant.clientSecret)
	assert.Equal(t, "invalid_grant", born["error"],
		"a live child born after the rename committed must still be refused: %v", born)
	assert.Equal(t, terminatedGrantMessage, born["error_description"],
		"only the revoked-code marker can refuse a child whose own row is live: %v", born)
	assert.Empty(t, born["access_token"])
	assert.Empty(t, born["refresh_token"])
}
