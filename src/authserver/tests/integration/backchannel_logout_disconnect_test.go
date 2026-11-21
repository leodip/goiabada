package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A disconnect tells the client (#135 decision 3), as the client sees it. Withdrawing a consent is a
// disconnect of the consent's client, so each consent DELETE sends the client with a back-channel
// logout URI a logout token naming the user alone, or, for a client that requires sid, one for each
// still-valid session of the user it is on. The user's sessions stay exactly as they were.

// disconnectedUser is a user with a consent to a client whose back-channel logout URI is a receiver,
// a refresh token with it, and a valid session the client and a second app with a URI are on.
type disconnectedUser struct {
	adminToken string
	user       *record.User
	session    *record.UserSession
	consent    *record.UserConsent

	client *record.Client
	told   *logoutReceiver
	other  *record.Client
	untold *logoutReceiver
}

// newDisconnectedUser builds it for user, or for a new user when user is nil.
func newDisconnectedUser(t *testing.T, user *record.User) *disconnectedUser {
	t.Helper()
	requireDatabaseAuditLogs(t)
	adminToken, adminClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, adminClient.ID) })

	if user == nil {
		user = &record.User{Subject: fake.UUID(), Enabled: true, Email: uniqueEmail("bcl@disconnect.test")}
		require.NoError(t, database.CreateUser(context.Background(), nil, user))
		t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.ID) })
	}

	d := &disconnectedUser{adminToken: adminToken, user: user}
	d.session = createTestUserSession(t, user.ID, fake.UUID())
	d.told = newLogoutReceiver(t, http.StatusOK)
	d.client = backchannelClient(t, adminToken, d.told.uri())
	onSession(t, d.session, d.client)
	holdRefreshToken(t, user, d.client, false, time.Now().UTC().Add(time.Hour))
	d.consent = createTestUserConsent(t, user.ID, d.client.ID)

	d.untold = newLogoutReceiver(t, http.StatusOK)
	d.other = backchannelClient(t, adminToken, d.untold.uri())
	onSession(t, d.session, d.other)
	return d
}

// assertToldAboutTheUser holds what arrived to one token naming the user and no session, to the
// disconnected client alone, recorded by the request requestID.
func (d *disconnectedUser) assertToldAboutTheUser(t *testing.T, requestID string) {
	t.Helper()
	posts := d.told.waitFor(t, 1, 10*time.Second)
	claims := assertLogoutToken(t, posts[0], d.client.ClientIdentifier, d.user.Subject, "")

	row, details := sentLogoutTokenRow(t, requestID, 10*time.Second)
	assert.Equal(t, map[string]interface{}{
		"client_id":          float64(d.client.ID),
		"user_id":            float64(d.user.ID),
		"session_identifier": "",
		"jti":                claims["jti"],
		"outcome":            "delivered",
		"attempts":           float64(1),
	}, details)
	assert.Equal(t, d.user.ID, row.UserID.Int64)

	// Every delivery has started by now; any further one would have arrived meanwhile.
	time.Sleep(2 * time.Second)
	assert.Len(t, d.told.received(), 1, "the client is told once, about every session of the user")
	assert.Empty(t, d.untold.received(), "the other app on the session is told nothing")
}

// assertSessionUntouched holds the user's session to what it was: still there, with the
// disconnected client still on it beside the other app.
func (d *disconnectedUser) assertSessionUntouched(t *testing.T) {
	t.Helper()
	session, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, d.session.SessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, session, "a disconnect ends no session")
	sessionClients, err := database.GetUserSessionClientsByUserSessionID(context.Background(), nil, session.ID)
	require.NoError(t, err)
	var onIt []int64
	for _, sessionClient := range sessionClients {
		onIt = append(onIt, sessionClient.ClientID)
	}
	assert.ElementsMatch(t, []int64{d.client.ID, d.other.ID}, onIt, "the client stays on the session")
}

// TestBackchannelLogout_AnAdministratorWithdrawingAConsentTellsTheClient: an administrator withdraws
// the user's consent, and the client is sent one logout token naming the user and no session, which
// asks it to end every session it has for them. A repeated DELETE is 404 and sends nothing.
func TestBackchannelLogout_AnAdministratorWithdrawingAConsentTellsTheClient(t *testing.T) {
	d := newDisconnectedUser(t, nil)
	path := "/api/v1/admin/user-consents/" + strconv.FormatInt(d.consent.ID, 10)

	resp, requestID := sendAdminRequest(t, d.adminToken, http.MethodDelete, path, nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	d.assertToldAboutTheUser(t, requestID)
	d.assertSessionUntouched(t)

	again, _ := sendAdminRequest(t, d.adminToken, http.MethodDelete, path, nil)
	_ = again.Body.Close()
	require.Equal(t, http.StatusNotFound, again.StatusCode)
	time.Sleep(2 * time.Second)
	assert.Len(t, d.told.received(), 1, "a repeated DELETE tells nobody")
}

// TestBackchannelLogout_AUserWithdrawingTheirConsentTellsTheClient: the user withdraws their own
// consent under Account, and the client is told as above.
func TestBackchannelLogout_AUserWithdrawingTheirConsentTellsTheClient(t *testing.T) {
	accessToken, user := getUserAccessTokenWithAccountScope(t)
	d := newDisconnectedUser(t, user)

	resp, requestID := sendAdminRequest(t, accessToken, http.MethodDelete,
		"/api/v1/account/consents/"+strconv.FormatInt(d.consent.ID, 10), nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	d.assertToldAboutTheUser(t, requestID)
	d.assertSessionUntouched(t)
}

// TestBackchannelLogout_WithdrawingAConsentTellsASidRequiringClientOfEachValidSession: a client that
// requires sid is sent a token for each still-valid session of the user it is on: the valid one, not
// the expired one, and not the valid one it is not on.
func TestBackchannelLogout_WithdrawingAConsentTellsASidRequiringClientOfEachValidSession(t *testing.T) {
	d := newDisconnectedUser(t, nil)
	require.NoError(t, database.SetClientBackchannelLogout(context.Background(), nil, d.client.ID, d.told.uri(), true))

	expired := createTestUserSession(t, d.user.ID, fake.UUID())
	dead := deadSessionCases(t)[0]
	expired.Started = dead.started
	expired.LastAccessed = dead.lastAccessed
	require.NoError(t, database.UpdateUserSession(context.Background(), nil, expired))
	onSession(t, expired, d.client)
	elsewhere := createTestUserSession(t, d.user.ID, fake.UUID())
	onSession(t, elsewhere, d.other)

	resp, requestID := sendAdminRequest(t, d.adminToken, http.MethodDelete,
		"/api/v1/admin/user-consents/"+strconv.FormatInt(d.consent.ID, 10), nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	posts := d.told.waitFor(t, 1, 10*time.Second)
	assertLogoutToken(t, posts[0], d.client.ClientIdentifier, d.user.Subject, d.session.SessionIdentifier)
	rows := sentLogoutTokenRows(t, requestID, 1, 10*time.Second)
	var details map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(rows[0].Details), &details))
	assert.Equal(t, d.session.SessionIdentifier, details["session_identifier"])

	time.Sleep(2 * time.Second)
	assert.Len(t, d.told.received(), 1, "the expired session, and the session the client is not on, tell it nothing")
	assert.Empty(t, d.untold.received())
	d.assertSessionUntouched(t)
}

// TestBackchannelLogout_WithdrawingAConsentTellsASidRequiringClientOnNoValidSessionNothing: a client
// that requires sid and is on no valid session of the user is told nothing, though its grant is
// still revoked.
func TestBackchannelLogout_WithdrawingAConsentTellsASidRequiringClientOnNoValidSessionNothing(t *testing.T) {
	d := newDisconnectedUser(t, nil)
	require.NoError(t, database.SetClientBackchannelLogout(context.Background(), nil, d.client.ID, d.told.uri(), true))
	dead := deadSessionCases(t)[0]
	d.session.Started = dead.started
	d.session.LastAccessed = dead.lastAccessed
	require.NoError(t, database.UpdateUserSession(context.Background(), nil, d.session))

	resp, _ := sendAdminRequest(t, d.adminToken, http.MethodDelete,
		"/api/v1/admin/user-consents/"+strconv.FormatInt(d.consent.ID, 10), nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	tokens, err := database.GetRefreshTokensByUserIDAndClientID(context.Background(), nil, d.user.ID, d.client.ID)
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.True(t, tokens[0].Revoked, "the grant is revoked whether or not the client is told")

	time.Sleep(2 * time.Second)
	assert.Empty(t, d.told.received())
}

// TestBackchannelLogout_DisconnectingAConnectedClientTellsIt: the user disconnects the client under
// Account's connected clients, and the client is told as for a consent withdrawal, its consent
// deleted with the rest.
func TestBackchannelLogout_DisconnectingAConnectedClientTellsIt(t *testing.T) {
	accessToken, user := getUserAccessTokenWithAccountScope(t)
	d := newDisconnectedUser(t, user)

	resp, requestID := sendAdminRequest(t, accessToken, http.MethodDelete,
		"/api/v1/account/connected-clients/"+strconv.FormatInt(d.client.ID, 10), nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	d.assertToldAboutTheUser(t, requestID)
	d.assertSessionUntouched(t)
	consent, err := database.GetUserConsentByID(context.Background(), nil, d.consent.ID)
	require.NoError(t, err)
	assert.Nil(t, consent, "the client's consent is deleted")
}
