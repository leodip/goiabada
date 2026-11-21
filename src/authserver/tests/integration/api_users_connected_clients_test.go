package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// The Admin API's connected clients (#135 decisions 2, 4 and 5): GET
// /api/v1/admin/users/{id}/connected-clients lists every client a user holds a stored consent or a
// live refresh token with, and DELETE /api/v1/admin/users/{id}/connected-clients/{clientId}
// disconnects one. The list takes admin-read, manage-users or manage; the DELETE manage-users or
// manage, and only manage when the user is an administrator (api_target_ceiling_test.go holds that
// ceiling). A row is isCurrent only on the caller's own user, for the client its token was issued
// to.

func userConnectedClientsPath(userID any) string {
	return fmt.Sprintf("/api/v1/admin/users/%v/connected-clients", userID)
}

// listUserConnectedClients is the user's list as accessToken reads it, required to answer 200,
// keyed by client id, with the raw body.
func listUserConnectedClients(t *testing.T, accessToken string, userID int64) (map[int64]api.ConnectedClientResponse, string) {
	t.Helper()
	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+userConnectedClientsPath(userID), accessToken, nil)
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

// disconnectUser sends the Admin DELETE with path values as given and answers the status, the
// decoded body and the request id its audit rows carry.
func disconnectUser(t *testing.T, accessToken string, userID, clientID any) (int, map[string]interface{}, string) {
	t.Helper()
	resp, requestID := sendAdminRequest(t, accessToken, http.MethodDelete,
		fmt.Sprintf("%s/%v", userConnectedClientsPath(userID), clientID), nil)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &decoded), "%s", body)
	return resp.StatusCode, decoded, requestID
}

// TestAPIUserConnectedClients_ListsEveryClientOfTheUser: an administrator's list of a user names
// the console, both apps and the password-grant client, none with a consent, each with the scopes
// its live refresh token records, and a client with a consent and no grant. Names are as the
// admin consent list gives them: the description an administrator kept off the sign-in screens is
// still shown. A client credentials token is no user's, so nothing is current.
func TestAPIUserConnectedClients_ListsEveryClientOfTheUser(t *testing.T) {
	c := newConnectedUser(t)
	adminToken, _ := createAdminClientWithToken(t)
	console, err := database.GetClientByClientIdentifier(context.Background(), nil, builtin.AdminConsoleClientIdentifier)
	require.NoError(t, err)

	hidden := &record.Client{
		ClientIdentifier: "connected-hidden-" + fake.LetterN(8),
		DisplayName:      "Billing",
		ShowDisplayName:  true,
		Description:      "Internal billing tool",
		ShowDescription:  false,
		Enabled:          true,
		IsPublic:         true,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, hidden))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, hidden.ID) })
	hiddenConsent := &record.UserConsent{UserID: c.user.ID, ClientID: hidden.ID, Scope: "openid email"}
	require.NoError(t, database.CreateUserConsent(context.Background(), nil, hiddenConsent))

	rows, raw := listUserConnectedClients(t, adminToken, c.user.ID)
	want := map[int64]api.ConnectedClientResponse{
		console.ID: {ClientID: console.ID, ClientIdentifier: builtin.AdminConsoleClientIdentifier,
			GrantScope: "openid authserver:manage-account"},
		c.x.client.ID: {ClientID: c.x.client.ID, ClientIdentifier: c.x.client.ClientIdentifier,
			ClientName: c.x.client.ClientIdentifier, GrantScope: "openid profile"},
		c.y.client.ID: {ClientID: c.y.client.ID, ClientIdentifier: c.y.client.ClientIdentifier,
			ClientName: c.y.client.ClientIdentifier, GrantScope: "openid email"},
		c.ropc.ID: {ClientID: c.ropc.ID, ClientIdentifier: c.ropc.ClientIdentifier,
			ClientName: c.ropc.ClientIdentifier, GrantScope: "openid"},
		hidden.ID: {ClientID: hidden.ID, ClientIdentifier: hidden.ClientIdentifier, ClientName: "Billing",
			ClientDescription: "Internal billing tool",
			Consent:           &api.ConnectedClientConsentResponse{ID: hiddenConsent.ID, Scope: "openid email"}},
	}
	require.ElementsMatch(t, clientIDsOf(want), clientIDsOf(rows))
	for id, row := range rows {
		if id == console.ID {
			// The console's name is whatever its seeded row shows; the rest is asserted.
			row.ClientName = ""
			row.ClientNameUnverified = false
			row.ClientDescription = ""
		}
		assert.Equal(t, want[id], row, "client %s", row.ClientIdentifier)
	}
	assert.Contains(t, raw, `"consent":null`)
	assert.Contains(t, raw, `"grantedAt":null`)
}

// TestAPIUserConnectedClients_IsCurrentOnlyOnTheCallersOwnUser: a user-bound admin token's client
// is current on the caller's own row, and not on another user's row for the same client.
func TestAPIUserConnectedClients_IsCurrentOnlyOnTheCallersOwnUser(t *testing.T) {
	scope := "openid " + builtin.AuthServerResourceIdentifier + ":" + builtin.ManagePermissionIdentifier
	data, code, _, _ := userTokenResponseWithScope(t, scope, nil)
	accessToken, ok := data["access_token"].(string)
	require.True(t, ok, "%v", data)
	caller := &code.User
	t.Cleanup(func() {
		_ = database.DeleteUser(context.Background(), nil, caller.ID)
		_ = database.DeleteClient(context.Background(), nil, code.ClientID)
	})

	other := &record.User{Subject: fake.UUID(), Enabled: true, Email: uniqueEmail("other@connected-clients.test")}
	require.NoError(t, database.CreateUser(context.Background(), nil, other))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, other.ID) })
	holdRefreshToken(t, other, &code.Client, false, time.Now().UTC().Add(time.Hour))

	own, _ := listUserConnectedClients(t, accessToken, caller.ID)
	require.Contains(t, own, code.ClientID)
	assert.True(t, own[code.ClientID].IsCurrent, "the caller's own client on the caller's own user")

	theirs, _ := listUserConnectedClients(t, accessToken, other.ID)
	require.Contains(t, theirs, code.ClientID)
	assert.False(t, theirs[code.ClientID].IsCurrent, "the same client on another user is not the caller's")
}

// TestAPIUserConnectedClientDelete_DisconnectsAnAppWithNoConsent: the administrator disconnects an
// app with Consent required off. Its refresh and access tokens are refused, the other app on the
// session still refreshes, the session survives, and one disconnected_client entry names the
// administrator. A repeated DELETE has nothing left to end: 404, and nothing written. A fresh
// authorization connects the app again.
func TestAPIUserConnectedClientDelete_DisconnectsAnAppWithNoConsent(t *testing.T) {
	c := newConnectedUser(t)
	adminToken, adminClient := createAdminClientWithToken(t)

	status, body, _ := disconnectUser(t, adminToken, c.user.ID, c.x.client.ID)
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, map[string]interface{}{"success": true}, body)

	assertRefreshRevoked(t, c.x.client.ClientIdentifier, signInRefreshToken(t, c.xTokens), c.x.signIn.secret)
	assertUserinfoRefusesTheToken(t, c.xTokens.accessToken(t))
	assertRefreshes(t, c.y.client.ClientIdentifier, signInRefreshToken(t, c.yTokens), c.y.signIn.secret)

	session, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, c.sid)
	require.NoError(t, err)
	require.NotNil(t, session, "the browser session survives the disconnect")

	rows, _ := listUserConnectedClients(t, adminToken, c.user.ID)
	assert.NotContains(t, clientIDsOf(rows), c.x.client.ID, "the disconnected app is listed no more")
	assert.Contains(t, clientIDsOf(rows), c.y.client.ID)

	entries := disconnectedClientEntries(t, c.user.ID, c.x.client.ID)
	require.Len(t, entries, 1, "the disconnect is recorded once")
	assert.Equal(t, adminClient.ClientIdentifier, entries[0]["logged_in_user"])
	assert.Len(t, entries[0]["revoked_refresh_token_jtis"], 1, "the app's one live refresh token")

	status, body, requestID := disconnectUser(t, adminToken, c.user.ID, c.x.client.ID)
	assert.Equal(t, http.StatusNotFound, status, "a repeated disconnect has nothing to end")
	assert.Equal(t, "NOT_FOUND", body["error_code"])
	assert.Zero(t, auditRowsOfRequest(t, adminToken, requestID), "a disconnect with nothing to end writes nothing")
	assert.Len(t, disconnectedClientEntries(t, c.user.ID, c.x.client.ID), 1)

	again := signInOn(t, c.browser, c.x.signIn, c.user, nil, nil)
	assert.False(t, again.askedPassword, "the session still signs the user in")
	assertRefreshes(t, c.x.client.ClientIdentifier, signInRefreshToken(t, again), c.x.signIn.secret)
}

// TestAPIUserConnectedClientDelete_DeletesTheConsent: disconnecting a client the user consented to
// deletes the consent, and writes deleted_user_consent beside disconnected_client.
func TestAPIUserConnectedClientDelete_DeletesTheConsent(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, adminClient := createAdminClientWithToken(t)
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: uniqueEmail("consent@connected-clients.test")}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.ID) })
	client := createTestClient(t, "connected-consent-"+fake.LetterN(8))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.ID) })
	consent := createTestUserConsent(t, user.ID, client.ID)

	status, body, _ := disconnectUser(t, adminToken, user.ID, client.ID)
	require.Equal(t, http.StatusOK, status, "%v", body)

	got, err := database.GetUserConsentByID(context.Background(), nil, consent.ID)
	require.NoError(t, err)
	assert.Nil(t, got, "the consent is deleted")
	require.Len(t, disconnectedClientEntries(t, user.ID, client.ID), 1)

	deletions, resp := getAuditLogs(t, adminToken, "auditEvent="+audit.EventDeletedUserConsent)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	found := 0
	for _, entry := range deletions.AuditLogs {
		var details map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(entry.Details), &details))
		if details["consent_id"] == float64(consent.ID) {
			found++
			assert.InDelta(t, float64(user.ID), details["user_id"], 0)
			assert.Equal(t, adminClient.ClientIdentifier, details["logged_in_user"])
		}
	}
	assert.Equal(t, 1, found, "the consent's deletion is recorded once")
}

// TestAPIUserConnectedClients_NotFoundAndMalformed: a user that does not exist is 404 on both
// operations; a client that does not exist, and one the user holds nothing with, are 404 on the
// DELETE and write nothing, leaving another user's grant with that client alone; a malformed id is
// 400 VALIDATION_ERROR. A user with nothing connected lists an empty array.
func TestAPIUserConnectedClients_NotFoundAndMalformed(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, _ := createAdminClientWithToken(t)
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: uniqueEmail("nothing@connected-clients.test")}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.ID) })

	rows, raw := listUserConnectedClients(t, adminToken, user.ID)
	assert.Empty(t, rows)
	assert.JSONEq(t, `{"clients": []}`, raw)

	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+userConnectedClientsPath(99999999), adminToken, nil)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "the list of a user that does not exist")
	resp = makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+userConnectedClientsPath("not-a-number"), adminToken, nil)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "the list under a malformed user id")

	other := consoleSignInUser(t, "en")
	app := newConnectedApp(t, "openid")
	othersGrant := signInOn(t, createHTTPClient(t), app.signIn, other, nil, nil)

	status, body, requestID := disconnectUser(t, adminToken, user.ID, app.client.ID)
	assert.Equal(t, http.StatusNotFound, status, "the user holds nothing with the client")
	assert.Equal(t, "NOT_FOUND", body["error_code"])
	assert.Zero(t, auditRowsOfRequest(t, adminToken, requestID))
	othersRefresh := assertRefreshes(t, app.client.ClientIdentifier, signInRefreshToken(t, othersGrant), app.signIn.secret)

	status, body, requestID = disconnectUser(t, adminToken, 99999999, app.client.ID)
	assert.Equal(t, http.StatusNotFound, status, "a user that does not exist")
	assert.Equal(t, "NOT_FOUND", body["error_code"])
	assert.Zero(t, auditRowsOfRequest(t, adminToken, requestID))

	status, body, requestID = disconnectUser(t, adminToken, other.ID, 99999999)
	assert.Equal(t, http.StatusNotFound, status, "a client that does not exist")
	assert.Equal(t, "NOT_FOUND", body["error_code"])
	assert.Zero(t, auditRowsOfRequest(t, adminToken, requestID))

	status, body, _ = disconnectUser(t, adminToken, "not-a-number", app.client.ID)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "VALIDATION_ERROR", body["error_code"])
	status, body, _ = disconnectUser(t, adminToken, other.ID, "not-a-number")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "VALIDATION_ERROR", body["error_code"])
	assertRefreshes(t, app.client.ClientIdentifier, othersRefresh, app.signIn.secret)
}

// TestAPIUserConnectedClients_Scopes: admin-read lists and cannot disconnect; manage-users lists and
// disconnects an ordinary user; no token is 401 and a token with no admin scope 403 on both.
func TestAPIUserConnectedClients_Scopes(t *testing.T) {
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: uniqueEmail("scopes@connected-clients.test")}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.ID) })
	client := createTestClient(t, "connected-scopes-"+fake.LetterN(8))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.ID) })
	holdRefreshToken(t, user, client, false, time.Now().UTC().Add(time.Hour))
	listPath := appConfig.AuthServer.BaseURL + userConnectedClientsPath(user.ID)
	deletePath := listPath + "/" + strconv.FormatInt(client.ID, 10)

	readToken, readClient := createClientWithGranularScope(t, builtin.AdminReadPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, readClient.ID) })
	rows, _ := listUserConnectedClients(t, readToken, user.ID)
	assert.Contains(t, rows, client.ID, "admin-read lists")
	resp := makeAPIRequest(t, http.MethodDelete, deletePath, readToken, nil)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "admin-read cannot disconnect")

	usersToken, usersClient := createClientWithGranularScope(t, builtin.ManageUsersPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, usersClient.ID) })
	rows, _ = listUserConnectedClients(t, usersToken, user.ID)
	assert.Contains(t, rows, client.ID, "manage-users lists")
	resp = makeAPIRequest(t, http.MethodDelete, deletePath, usersToken, nil)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "manage-users disconnects an ordinary user")
	rows, _ = listUserConnectedClients(t, usersToken, user.ID)
	assert.NotContains(t, rows, client.ID)

	noScope := createClientCredentialsTokenWithoutRouteScope(t)
	for _, op := range []struct{ method, url string }{
		{http.MethodGet, listPath},
		{http.MethodDelete, deletePath},
	} {
		req, err := http.NewRequest(op.method, op.url, nil)
		require.NoError(t, err)
		resp, err := createHTTPClient(t).Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "%s with no token", op.method)

		resp = makeAPIRequest(t, op.method, op.url, noScope, nil)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "%s without an admin scope", op.method)
	}
}

// TestAPIUserConnectedClientDelete_EndsTheClientOnEverySessionAndTellsIt: one client holds an
// authorization-code offline grant and a session-bound grant on each of two of the user's sessions,
// and a second app shares the first session. An administrator disconnects the client through the
// client-keyed Admin DELETE. Its four refresh tokens are refused, offline and session-bound alike,
// and so are their access tokens at /userinfo; the other app still refreshes, both sessions stay,
// and the client, alone, is sent one logout token naming the user and no session (#135 decisions 1
// and 3).
func TestAPIUserConnectedClientDelete_EndsTheClientOnEverySessionAndTellsIt(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, adminClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, adminClient.ID) })

	sessionBoundScope := "openid " + builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier
	first := createOfflineGrant(t)
	second := secondOfflineGrantForSameUser(t, first, first.password)
	require.NotEqual(t, first.sessionIdentifier, second.sessionIdentifier, "two sessions of the user")

	type grant struct {
		label         string
		accessToken   string
		refreshToken  string
		wantTokenType string
	}
	grants := []grant{
		{"the offline grant on the first session", first.accessToken, first.refreshToken, "Offline"},
		{"the offline grant on the second session", second.accessToken, second.refreshToken, "Offline"},
	}
	for i, g := range []*offlineGrant{first, second} {
		verifier := testCodeVerifier + "-session-bound-" + strconv.Itoa(i)
		exchanged := g.exchange(t, g.codeFromSameSession(t, sessionBoundScope, verifier), verifier)
		accessToken, ok := exchanged["access_token"].(string)
		require.True(t, ok, "%v", exchanged)
		refreshToken, ok := exchanged["refresh_token"].(string)
		require.True(t, ok, "%v", exchanged)
		require.Equal(t, g.sessionIdentifier, claimString(t, accessToken, "sid"))
		grants = append(grants, grant{"the session-bound grant on session " + strconv.Itoa(i+1),
			accessToken, refreshToken, "Refresh"})
	}
	for _, g := range grants {
		require.Equal(t, g.wantTokenType, claimString(t, g.refreshToken, "typ"), g.label)
	}

	other := newConnectedApp(t, "openid")
	otherTokens := signInOn(t, first.httpClient, other.signIn, first.user, nil, nil)
	require.False(t, otherTokens.askedPassword, "the other app signs in on the first session")

	told := newLogoutReceiver(t, http.StatusOK)
	require.NoError(t, database.SetClientBackchannelLogout(context.Background(), nil, first.client.ID, told.uri(), false))
	untold := newLogoutReceiver(t, http.StatusOK)
	require.NoError(t, database.SetClientBackchannelLogout(context.Background(), nil, other.client.ID, untold.uri(), false))

	status, body, requestID := disconnectUser(t, adminToken, first.user.ID, first.client.ID)
	require.Equal(t, http.StatusOK, status, "%v", body)

	for _, g := range grants {
		t.Run(g.label, func(t *testing.T) {
			// An offline refresh is checked against the stored consent before its row, and the
			// disconnect deleted that consent, so it is refused for the consent; the row is revoked
			// all the same.
			answer := presentRefreshToken(t, first.client.ClientIdentifier, g.refreshToken, first.clientSecret)
			assert.Equal(t, "invalid_grant", answer["error"], "the disconnected client's refresh is refused: %v", answer)
			assert.Empty(t, answer["access_token"])
			stored, err := database.GetRefreshTokenByJTI(context.Background(), nil, claimString(t, g.refreshToken, "jti"))
			require.NoError(t, err)
			require.NotNil(t, stored)
			assert.True(t, stored.Revoked, "the refresh token's row is revoked")
			if g.wantTokenType == "Refresh" {
				assertRefreshRevoked(t, first.client.ClientIdentifier, g.refreshToken, first.clientSecret)
			}
			assertUserinfoRefusesTheToken(t, g.accessToken)
		})
	}
	assertRefreshes(t, other.client.ClientIdentifier, signInRefreshToken(t, otherTokens), other.signIn.secret)

	for _, sid := range []string{first.sessionIdentifier, second.sessionIdentifier} {
		session, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, sid)
		require.NoError(t, err)
		assert.NotNil(t, session, "a disconnect ends no session")
	}

	posts := told.waitFor(t, 1, 10*time.Second)
	assertLogoutToken(t, posts[0], first.client.ClientIdentifier, first.user.Subject, "")
	sentLogoutTokenRow(t, requestID, 10*time.Second)
	// Every delivery has started by now; any further one would have arrived meanwhile.
	time.Sleep(2 * time.Second)
	assert.Len(t, told.received(), 1, "the client is told once, about every session of the user")
	assert.Empty(t, untold.received(), "the other app is told nothing")

	entries := disconnectedClientEntries(t, first.user.ID, first.client.ID)
	require.Len(t, entries, 1)
	assert.Len(t, entries[0]["revoked_refresh_token_jtis"], 4, "the four live refresh tokens, on both sessions")
}
