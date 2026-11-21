package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Account API's connected clients (#135 decisions 2, 4 and 5): GET
// /api/v1/account/connected-clients lists every client the caller holds a stored consent or a live
// refresh token with, and DELETE /api/v1/account/connected-clients/{clientId} disconnects one. The
// cases here are the ones the consent endpoints cannot reach, clients with no consent: two apps
// with Consent required off, a password grant, and the caller's own client, the admin console.
// Disconnecting one refuses its refresh and access tokens, leaves the user's other clients and
// their browser session alone, and a fresh authorization to it succeeds: a disconnect is not a
// ban.

const accountConnectedClientsPath = "/api/v1/account/connected-clients"

// connectedApp is an app with Consent required off that a browser signs in to, asking for scope.
type connectedApp struct {
	client *record.Client
	signIn signInClient
}

// newConnectedApp creates the app. It asks for no consent: neither its setting nor its scope does.
func newConnectedApp(t *testing.T, scope string) connectedApp {
	t.Helper()
	secret := fake.LetterN(32)
	secretEncrypted, err := dataCipher.Encrypt(secret)
	require.NoError(t, err)
	client := &record.Client{
		ClientIdentifier:         "connected-app-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultACRLevel:          record.ACRLevel1,
		ClientSecretEncrypted:    secretEncrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.ID) })
	redirectURI := "https://" + fake.LetterN(10) + ".example.com/callback"
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil,
		&record.RedirectURI{ClientID: client.ID, URI: redirectURI}))
	return connectedApp{client: client, signIn: signInClient{
		identifier: client.ClientIdentifier, redirectURI: redirectURI, secret: secret, scope: scope,
	}}
}

// connectedUser is one user on one browser session, signed in there to the admin console, whose
// token calls the Account API, and to two apps, and holding a password grant with a fourth client.
// None of the four holds a consent.
type connectedUser struct {
	user    *record.User
	browser *http.Client
	sid     string
	console signIn
	x, y    connectedApp
	xTokens signIn
	yTokens signIn

	ropc        *record.Client
	ropcSecret  string
	ropcRefresh string
}

func newConnectedUser(t *testing.T) *connectedUser {
	t.Helper()
	requireDatabaseAuditLogs(t)
	enableROPCGlobally(t)

	c := &connectedUser{user: consoleSignInUser(t, "en"), browser: createHTTPClient(t)}
	c.console = signInOn(t, c.browser, consoleSignInClient(t), c.user, nil, nil)
	require.True(t, c.console.askedPassword, "the first sign-in asks for the password")
	c.sid = claimString(t, c.console.accessToken(t), "sid")
	require.NotEmpty(t, c.sid)

	c.x = newConnectedApp(t, "openid profile")
	c.y = newConnectedApp(t, "openid email")
	c.xTokens = signInOn(t, c.browser, c.x.signIn, c.user, nil, nil)
	c.yTokens = signInOn(t, c.browser, c.y.signIn, c.user, nil, nil)
	for _, s := range []signIn{c.xTokens, c.yTokens} {
		require.False(t, s.askedPassword, "the apps sign in on the console's session")
		require.Equal(t, c.sid, claimString(t, s.accessToken(t), "sid"), "every app is on the one session")
	}

	c.ropcSecret = fake.Password(32)
	c.ropc = createROPCClient(t, c.ropcSecret, false)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, c.ropc.ID) })
	status, body := passwordGrant(t, c.ropc, c.ropcSecret, c.user, deletionUserPassword, "openid")
	require.Equal(t, http.StatusOK, status, "%v", body)
	var ok bool
	c.ropcRefresh, ok = body["refresh_token"].(string)
	require.True(t, ok, "the password grant issues a refresh token: %v", body)
	return c
}

func signInRefreshToken(t *testing.T, s signIn) string {
	t.Helper()
	token, ok := s.tokens["refresh_token"].(string)
	require.True(t, ok, "a refresh token is issued: %v", s.tokens)
	return token
}

// assertRefreshRevoked holds that the token endpoint refuses refreshToken as revoked.
func assertRefreshRevoked(t *testing.T, clientIdentifier, refreshToken, secret string) {
	t.Helper()
	answer := presentRefreshToken(t, clientIdentifier, refreshToken, secret)
	assert.Equal(t, "invalid_grant", answer["error"], "the disconnected client's refresh is refused: %v", answer)
	assert.Equal(t, "This refresh token has been revoked.", answer["error_description"])
	assert.Empty(t, answer["access_token"])
}

// assertRefreshes holds that refreshToken still refreshes, and answers its replacement.
func assertRefreshes(t *testing.T, clientIdentifier, refreshToken, secret string) string {
	t.Helper()
	answer := presentRefreshToken(t, clientIdentifier, refreshToken, secret)
	require.Nil(t, answer["error"], "the grant still refreshes: %v", answer["error_description"])
	require.NotEmpty(t, answer["access_token"])
	replacement, ok := answer["refresh_token"].(string)
	require.True(t, ok, "rotation hands back a replacement: %v", answer)
	return replacement
}

// listConnectedClients is the caller's list, required to answer 200, keyed by client id, with the
// raw body to check that the array is never null.
func listConnectedClients(t *testing.T, accessToken string) (map[int64]api.ConnectedClientResponse, string) {
	t.Helper()
	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+accountConnectedClientsPath, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var list api.GetConnectedClientsResponse
	require.NoError(t, json.Unmarshal(body, &list))
	rows := map[int64]api.ConnectedClientResponse{}
	for _, row := range list.Clients {
		_, repeated := rows[row.ClientID]
		require.False(t, repeated, "a client is listed once: %s", body)
		rows[row.ClientID] = row
	}
	return rows, string(body)
}

func clientIDsOf(rows map[int64]api.ConnectedClientResponse) []int64 {
	ids := make([]int64, 0, len(rows))
	for id := range rows {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// disconnect sends the DELETE for clientID with accessToken and answers the status, the decoded
// body and the request id its audit rows carry.
func disconnect(t *testing.T, accessToken string, clientID string) (int, map[string]interface{}, string) {
	t.Helper()
	resp, requestID := sendAdminRequest(t, accessToken, http.MethodDelete, accountConnectedClientsPath+"/"+clientID, nil)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &decoded), "%s", body)
	return resp.StatusCode, decoded, requestID
}

func disconnectID(t *testing.T, accessToken string, clientID int64) (int, map[string]interface{}, string) {
	t.Helper()
	return disconnect(t, accessToken, strconv.FormatInt(clientID, 10))
}

// disconnectedClientEntries is the disconnected_client entries naming the user and the client.
func disconnectedClientEntries(t *testing.T, userID, clientID int64) []map[string]interface{} {
	t.Helper()
	adminToken, _ := createAdminClientWithToken(t)
	logs, resp := getAuditLogs(t, adminToken, "auditEvent="+audit.EventDisconnectedClient)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var entries []map[string]interface{}
	for _, entry := range logs.AuditLogs {
		var details map[string]interface{}
		if err := json.Unmarshal([]byte(entry.Details), &details); err != nil {
			continue
		}
		if details["user_id"] == float64(userID) && details["client_id"] == float64(clientID) {
			entries = append(entries, details)
		}
	}
	return entries
}

// TestAPIAccountConnectedClients_ListsEveryClientWithNoConsent: the list names the console, both
// apps and the password-grant client, none with a consent, each with the scopes its live refresh
// token records, and marks the console, whose token made the call, as the current one.
func TestAPIAccountConnectedClients_ListsEveryClientWithNoConsent(t *testing.T) {
	c := newConnectedUser(t)
	console, err := database.GetClientByClientIdentifier(context.Background(), nil, builtin.AdminConsoleClientIdentifier)
	require.NoError(t, err)

	rows, _ := listConnectedClients(t, c.console.accessToken(t))
	want := map[int64]api.ConnectedClientResponse{
		console.ID: {ClientID: console.ID, ClientIdentifier: builtin.AdminConsoleClientIdentifier,
			GrantScope: "openid authserver:manage-account", IsCurrent: true},
		c.x.client.ID: {ClientID: c.x.client.ID, ClientIdentifier: c.x.client.ClientIdentifier,
			ClientName: c.x.client.ClientIdentifier, GrantScope: "openid profile"},
		c.y.client.ID: {ClientID: c.y.client.ID, ClientIdentifier: c.y.client.ClientIdentifier,
			ClientName: c.y.client.ClientIdentifier, GrantScope: "openid email"},
		c.ropc.ID: {ClientID: c.ropc.ID, ClientIdentifier: c.ropc.ClientIdentifier,
			ClientName: c.ropc.ClientIdentifier, GrantScope: "openid"},
	}
	require.ElementsMatch(t, clientIDsOf(want), clientIDsOf(rows))
	for id, row := range rows {
		if id == console.ID {
			// The console's name is whatever its seeded row shows users; the rest is asserted.
			row.ClientName = ""
			row.ClientNameUnverified = false
			row.ClientDescription = ""
		}
		assert.Equal(t, want[id], row, "client %s", row.ClientIdentifier)
	}
}

// TestAPIAccountConnectedClients_DisconnectAnAppWithNoConsent is the issue's four assertions for an
// app with Consent required off: its refresh token is refused, and its access token at /userinfo;
// the other app's token on the same session still refreshes; the browser session survives; and a
// fresh authorization to the app succeeds. One disconnected_client entry says what was revoked, and
// a repeated DELETE has nothing left to end: 404, and nothing written.
func TestAPIAccountConnectedClients_DisconnectAnAppWithNoConsent(t *testing.T) {
	c := newConnectedUser(t)

	status, body, _ := disconnectID(t, c.console.accessToken(t), c.x.client.ID)
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, map[string]interface{}{"success": true}, body)

	assertRefreshRevoked(t, c.x.client.ClientIdentifier, signInRefreshToken(t, c.xTokens), c.x.signIn.secret)
	assertUserinfoRefusesTheToken(t, c.xTokens.accessToken(t))
	assertRefreshes(t, c.y.client.ClientIdentifier, signInRefreshToken(t, c.yTokens), c.y.signIn.secret)
	assertUserinfoAdmits(t, c.yTokens.accessToken(t), c.user.Subject)

	session, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, c.sid)
	require.NoError(t, err)
	require.NotNil(t, session, "the browser session survives the disconnect")

	rows, _ := listConnectedClients(t, c.console.accessToken(t))
	assert.NotContains(t, clientIDsOf(rows), c.x.client.ID, "the disconnected app is listed no more")
	assert.Contains(t, clientIDsOf(rows), c.y.client.ID)

	entries := disconnectedClientEntries(t, c.user.ID, c.x.client.ID)
	require.Len(t, entries, 1, "the disconnect is recorded once")
	assert.Equal(t, c.user.Subject, entries[0]["logged_in_user"])
	assert.Len(t, entries[0]["revoked_refresh_token_jtis"], 1, "the app's one live refresh token")
	assert.InDelta(t, float64(0), entries[0]["revoked_code_count"], 0, "its code was redeemed")

	status, body, requestID := disconnectID(t, c.console.accessToken(t), c.x.client.ID)
	assert.Equal(t, http.StatusNotFound, status, "a repeated disconnect has nothing to end")
	assert.Equal(t, "NOT_FOUND", body["error_code"])
	adminToken, _ := createAdminClientWithToken(t)
	assert.Zero(t, auditRowsOfRequest(t, adminToken, requestID), "a disconnect with nothing to end writes nothing")
	assert.Len(t, disconnectedClientEntries(t, c.user.ID, c.x.client.ID), 1)

	// Not a ban: the browser signs the app in again on the surviving session, asking nothing.
	again := signInOn(t, c.browser, c.x.signIn, c.user, nil, nil)
	assert.False(t, again.askedPassword, "the session still signs the user in")
	assertRefreshes(t, c.x.client.ClientIdentifier, signInRefreshToken(t, again), c.x.signIn.secret)
	rows, _ = listConnectedClients(t, c.console.accessToken(t))
	assert.Contains(t, clientIDsOf(rows), c.x.client.ID, "the app is connected again")
}

// TestAPIAccountConnectedClients_DisconnectAPasswordGrant: a password grant appears on no session and
// holds no consent, and a disconnect ends it all the same; the app on the session is untouched, and
// a fresh password grant connects the client again.
func TestAPIAccountConnectedClients_DisconnectAPasswordGrant(t *testing.T) {
	c := newConnectedUser(t)

	status, body, _ := disconnectID(t, c.console.accessToken(t), c.ropc.ID)
	require.Equal(t, http.StatusOK, status, "%v", body)

	assertRefreshRevoked(t, c.ropc.ClientIdentifier, c.ropcRefresh, c.ropcSecret)
	assertRefreshes(t, c.x.client.ClientIdentifier, signInRefreshToken(t, c.xTokens), c.x.signIn.secret)
	rows, _ := listConnectedClients(t, c.console.accessToken(t))
	assert.NotContains(t, clientIDsOf(rows), c.ropc.ID)
	require.Len(t, disconnectedClientEntries(t, c.user.ID, c.ropc.ID), 1)

	status, answer := passwordGrant(t, c.ropc, c.ropcSecret, c.user, deletionUserPassword, "openid")
	require.Equal(t, http.StatusOK, status, "the client can use the password grant again: %v", answer)
}

// TestAPIAccountConnectedClients_DisconnectTheCallersOwnClient: the API disconnects the client the
// calling token was issued to like any other (decision 5). The calling token is refused from then
// on, and so is the console's refresh token, while both apps keep refreshing and the session stays;
// a fresh console sign-in on the browser asks nothing and lists the console again as current.
func TestAPIAccountConnectedClients_DisconnectTheCallersOwnClient(t *testing.T) {
	c := newConnectedUser(t)
	console := consoleSignInClient(t)
	consoleRow, err := database.GetClientByClientIdentifier(context.Background(), nil, builtin.AdminConsoleClientIdentifier)
	require.NoError(t, err)

	status, body, _ := disconnectID(t, c.console.accessToken(t), consoleRow.ID)
	require.Equal(t, http.StatusOK, status, "%v", body)

	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+accountConnectedClientsPath, c.console.accessToken(t), nil)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "the disconnected console's token is refused at once")
	assertRefreshRevoked(t, console.identifier, signInRefreshToken(t, c.console), console.secret)
	assertRefreshes(t, c.x.client.ClientIdentifier, signInRefreshToken(t, c.xTokens), c.x.signIn.secret)
	assertRefreshes(t, c.y.client.ClientIdentifier, signInRefreshToken(t, c.yTokens), c.y.signIn.secret)

	again := signInOn(t, c.browser, console, c.user, nil, nil)
	assert.False(t, again.askedPassword, "the session survives the console's own disconnect")
	rows, _ := listConnectedClients(t, again.accessToken(t))
	require.Contains(t, rows, consoleRow.ID)
	assert.True(t, rows[consoleRow.ID].IsCurrent)
}

// TestAPIAccountConnectedClients_AConsentIsPartOfItsClientsRow: a client the user consented to is
// listed with its consent, as the consent screen named the client; one with a consent and no live
// grant is listed with an empty grantScope, its consent recording no time with a null grantedAt.
// Disconnecting it deletes the consent and writes deleted_own_user_consent beside
// disconnected_client.
func TestAPIAccountConnectedClients_AConsentIsPartOfItsClientsRow(t *testing.T) {
	c := newConnectedUser(t)
	grantedAt := time.Now().UTC().Truncate(time.Second)
	xConsent := &record.UserConsent{UserID: c.user.ID, ClientID: c.x.client.ID, Scope: "openid profile email",
		GrantedAt: sql.NullTime{Time: grantedAt, Valid: true}}
	require.NoError(t, database.CreateUserConsent(context.Background(), nil, xConsent))

	named := &record.Client{
		ClientIdentifier: "connected-named-" + fake.LetterN(8),
		DisplayName:      "Customer portal",
		ShowDisplayName:  true,
		Description:      "Orders and invoices",
		ShowDescription:  true,
		Enabled:          true,
		IsPublic:         true,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, named))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, named.ID) })
	namedConsent := &record.UserConsent{UserID: c.user.ID, ClientID: named.ID, Scope: "openid"}
	require.NoError(t, database.CreateUserConsent(context.Background(), nil, namedConsent))

	rows, raw := listConnectedClients(t, c.console.accessToken(t))
	require.Contains(t, rows, c.x.client.ID)
	require.NotNil(t, rows[c.x.client.ID].Consent)
	assert.Equal(t, xConsent.ID, rows[c.x.client.ID].Consent.ID)
	assert.Equal(t, "openid profile email", rows[c.x.client.ID].Consent.Scope)
	require.NotNil(t, rows[c.x.client.ID].Consent.GrantedAt)
	assert.WithinDuration(t, grantedAt, *rows[c.x.client.ID].Consent.GrantedAt, time.Second)
	assert.Equal(t, "openid profile", rows[c.x.client.ID].GrantScope, "the consent and the grant each keep their own scopes")

	require.Contains(t, rows, named.ID)
	assert.Equal(t, api.ConnectedClientResponse{
		ClientID:          named.ID,
		ClientIdentifier:  named.ClientIdentifier,
		ClientName:        "Customer portal",
		ClientDescription: "Orders and invoices",
		Consent:           &api.ConnectedClientConsentResponse{ID: namedConsent.ID, Scope: "openid"},
		GrantScope:        "",
	}, rows[named.ID])
	assert.Contains(t, raw, `"grantedAt":null`, "a consent that recorded no time says so")
	assert.Nil(t, rows[c.y.client.ID].Consent)
	assert.Contains(t, raw, `"consent":null`, "a client with no consent carries null")

	status, body, _ := disconnectID(t, c.console.accessToken(t), named.ID)
	require.Equal(t, http.StatusOK, status, "a consent with no grant behind it is something to end: %v", body)
	got, err := database.GetUserConsentByID(context.Background(), nil, namedConsent.ID)
	require.NoError(t, err)
	assert.Nil(t, got, "the consent is deleted")
	require.Len(t, disconnectedClientEntries(t, c.user.ID, named.ID), 1)

	adminToken, _ := createAdminClientWithToken(t)
	deletions, resp := getAuditLogs(t, adminToken, "auditEvent="+audit.EventDeletedOwnUserConsent)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	found := 0
	for _, entry := range deletions.AuditLogs {
		var details map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(entry.Details), &details))
		if details["consent_id"] == float64(namedConsent.ID) {
			found++
			assert.Equal(t, c.user.ID, int64(details["user_id"].(float64)))
			assert.Equal(t, c.user.Subject, details["logged_in_user"])
		}
	}
	assert.Equal(t, 1, found, "the consent's deletion is recorded once")
}

// TestAPIAccountConnectedClients_AnExpiredGrantIsNotListed: a refresh token past its expiry is no
// live grant, so a user whose one grant has expired has no connected client, and the list is an
// empty array, not null. The access token of that grant still calls the API: its grant was not
// revoked.
func TestAPIAccountConnectedClients_AnExpiredGrantIsNotListed(t *testing.T) {
	user := consoleSignInUser(t, "en")
	console := signInOn(t, createHTTPClient(t), consoleSignInClient(t), user, nil, nil)

	tokens, err := database.GetRefreshTokensByUserID(context.Background(), nil, user.ID)
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	tokens[0].ExpiresAt = sql.NullTime{Time: time.Now().UTC().Add(-time.Minute), Valid: true}
	require.NoError(t, database.UpdateRefreshToken(context.Background(), nil, tokens[0]))

	rows, raw := listConnectedClients(t, console.accessToken(t))
	assert.Empty(t, rows)
	assert.JSONEq(t, `{"clients": []}`, raw)
}

// TestAPIAccountConnectedClientDelete_NothingToEndIs404: a client that does not exist, and one the
// caller holds nothing with, are 404 NOT_FOUND and write nothing, and another user's grant with that
// client is not the caller's to end. A malformed id is 400 VALIDATION_ERROR.
func TestAPIAccountConnectedClientDelete_NothingToEndIs404(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, _ := createAdminClientWithToken(t)
	accessToken, _ := getUserAccessTokenWithAccountScope(t)

	other := consoleSignInUser(t, "en")
	app := newConnectedApp(t, "openid")
	othersGrant := signInOn(t, createHTTPClient(t), app.signIn, other, nil, nil)

	status, body, requestID := disconnectID(t, accessToken, app.client.ID)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "NOT_FOUND", body["error_code"])
	assert.Zero(t, auditRowsOfRequest(t, adminToken, requestID))
	assertRefreshes(t, app.client.ClientIdentifier, signInRefreshToken(t, othersGrant), app.signIn.secret)

	gone := newConnectedApp(t, "openid")
	require.NoError(t, database.DeleteClient(context.Background(), nil, gone.client.ID))
	status, body, requestID = disconnectID(t, accessToken, gone.client.ID)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "NOT_FOUND", body["error_code"])
	assert.Zero(t, auditRowsOfRequest(t, adminToken, requestID))

	status, body, _ = disconnect(t, accessToken, "not-a-number")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "VALIDATION_ERROR", body["error_code"])
}

// TestAPIAccountConnectedClients_RequiresAnAccountToken: both operations refuse a request with no
// token as 401 and a token without authserver:manage-account as 403.
func TestAPIAccountConnectedClients_RequiresAnAccountToken(t *testing.T) {
	tok := createClientCredentialsTokenWithoutRouteScope(t)
	for _, op := range []struct{ method, path string }{
		{http.MethodGet, accountConnectedClientsPath},
		{http.MethodDelete, accountConnectedClientsPath + "/1"},
	} {
		req, err := http.NewRequest(op.method, appConfig.AuthServer.BaseURL+op.path, nil)
		require.NoError(t, err)
		resp, err := createHTTPClient(t).Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "%s %s with no token", op.method, op.path)

		resp = makeAPIRequest(t, op.method, appConfig.AuthServer.BaseURL+op.path, tok, nil)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "%s %s without the scope", op.method, op.path)
	}
}
