package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The user-wide ends of #784 decision 3, and the user's own password change, as the apps see them.
// A user-wide end (disabling or deleting the user, a password reset, an administrator setting the
// password) sends one sub-only token to each app that was on any of the user's stored sessions,
// valid or not, or held one of the user's unrevoked, unexpired refresh tokens; an app that requires
// sid gets a sub+sid token for each valid session it was on, and nothing for a grant alone.

// userWideApps is a user and the apps that knew them, each app with a receiver of its own.
type userWideApps struct {
	adminToken string
	user       *record.User
	// live is a valid session, expired one past its idle timeout.
	live, expired *record.UserSession

	// onBoth is on both sessions; onExpired only on the expired one; grantOnly holds a usable refresh
	// token and is on no session; revokedGrant and expiredGrant hold only a revoked or an expired one.
	onBoth, onExpired, grantOnly, revokedGrant, expiredGrant *logoutReceiver
	// sidRequired requires sid: it is on both sessions and holds a usable refresh token.
	sidRequired       *logoutReceiver
	sidRequiredClient *record.Client
	clients           map[*logoutReceiver]*record.Client
}

// holdRefreshToken stores a refresh token of the user's with the client, in the password grant's
// shape (refresh_tokens.user_id and client_id), revoked or expiring as asked.
func holdRefreshToken(t *testing.T, user *record.User, client *record.Client, revoked bool, expiresAt time.Time) {
	t.Helper()
	now := time.Now().UTC()
	jti := fake.UUID()
	require.NoError(t, database.CreateRefreshToken(context.Background(), nil, &record.RefreshToken{
		UserId:               sql.NullInt64{Int64: user.Id, Valid: true},
		ClientId:             sql.NullInt64{Int64: client.Id, Valid: true},
		RefreshTokenJti:      jti,
		FirstRefreshTokenJti: jti,
		RefreshTokenType:     "Offline",
		Scope:                "openid",
		IssuedAt:             sql.NullTime{Time: now.Add(-2 * time.Hour), Valid: true},
		ExpiresAt:            sql.NullTime{Time: expiresAt, Valid: true},
		MaxLifetime:          sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
		Revoked:              revoked,
		AuthStateGeneration:  user.AuthStateGeneration,
	}))
}

// newUserWideApps builds the user, the two sessions and the apps. user is the user to build them
// for, or nil for a new one.
func newUserWideApps(t *testing.T, user *record.User) *userWideApps {
	t.Helper()
	requireDatabaseAuditLogs(t)
	adminToken, adminClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, adminClient.Id) })

	if user == nil {
		user = &record.User{Subject: fake.UUID(), Enabled: true, Email: uniqueEmail("bcl@user-wide.test")}
		require.NoError(t, database.CreateUser(context.Background(), nil, user))
		t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	}

	a := &userWideApps{adminToken: adminToken, user: user, clients: map[*logoutReceiver]*record.Client{}}
	a.live = createTestUserSession(t, user.Id, fake.UUID())
	a.expired = createTestUserSession(t, user.Id, fake.UUID())
	dead := deadSessionCases(t)[0]
	a.expired.Started = dead.started
	a.expired.LastAccessed = dead.lastAccessed
	require.NoError(t, database.UpdateUserSession(context.Background(), nil, a.expired))

	app := func() *logoutReceiver {
		rc := newLogoutReceiver(t, http.StatusOK)
		a.clients[rc] = backchannelClient(t, adminToken, rc.uri())
		return rc
	}
	a.onBoth = app()
	onSession(t, a.live, a.clients[a.onBoth])
	onSession(t, a.expired, a.clients[a.onBoth])
	a.onExpired = app()
	onSession(t, a.expired, a.clients[a.onExpired])
	a.grantOnly = app()
	holdRefreshToken(t, user, a.clients[a.grantOnly], false, time.Now().UTC().Add(time.Hour))
	a.revokedGrant = app()
	holdRefreshToken(t, user, a.clients[a.revokedGrant], true, time.Now().UTC().Add(time.Hour))
	a.expiredGrant = app()
	holdRefreshToken(t, user, a.clients[a.expiredGrant], false, time.Now().UTC().Add(-time.Minute))

	a.sidRequired = app()
	a.sidRequiredClient = a.clients[a.sidRequired]
	require.NoError(t, database.SetClientBackchannelLogout(context.Background(), nil, a.sidRequiredClient.Id,
		a.sidRequired.uri(), true))
	onSession(t, a.live, a.sidRequiredClient)
	onSession(t, a.expired, a.sidRequiredClient)
	holdRefreshToken(t, user, a.sidRequiredClient, false, time.Now().UTC().Add(time.Hour))

	// An app on the live session with no back-channel logout URI, which is told nothing.
	onSession(t, a.live, backchannelClient(t, adminToken, ""))
	return a
}

// assertToldEverywhere holds what the apps received to decision 3's user-wide shape: one sub-only
// token to each app that knew the user, a sub+sid token for the valid session to the app requiring
// sid, and nothing to the apps whose only grant was revoked or expired. requestId is the request
// that ended the sessions, whose sent_logout_token rows are checked when the audit log is the
// database.
func (a *userWideApps) assertToldEverywhere(t *testing.T, requestId string) {
	t.Helper()
	for _, rc := range []*logoutReceiver{a.onBoth, a.onExpired, a.grantOnly} {
		posts := rc.waitFor(t, 1, 10*time.Second)
		assertLogoutToken(t, posts[0], a.clients[rc].ClientIdentifier, a.user.Subject, "")
	}
	posts := a.sidRequired.waitFor(t, 1, 10*time.Second)
	assertLogoutToken(t, posts[0], a.sidRequiredClient.ClientIdentifier, a.user.Subject, a.live.SessionIdentifier)

	// Every delivery has started by now; any further one would have arrived meanwhile.
	time.Sleep(2 * time.Second)
	assert.Len(t, a.onBoth.received(), 1, "an app on two sessions is told once, about every session")
	assert.Len(t, a.onExpired.received(), 1)
	assert.Len(t, a.grantOnly.received(), 1)
	assert.Len(t, a.sidRequired.received(), 1,
		"an app requiring sid is told of the valid session only, and nothing for its grant")
	assert.Empty(t, a.revokedGrant.received(), "a revoked grant is no app that knew the user")
	assert.Empty(t, a.expiredGrant.received(), "an expired grant is no app that knew the user")

	if requestId == "" {
		return
	}
	rows, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 20,
		record.AuditLogFilter{AuditEvent: "sent_logout_token", RequestId: requestId})
	require.NoError(t, err)
	require.Equal(t, 4, total, "one sent_logout_token row per delivery")
	sids := map[string]int{}
	for _, row := range rows {
		assert.Equal(t, a.user.Id, row.UserId.Int64)
		var details map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(row.Details), &details))
		assert.Equal(t, "delivered", details["outcome"])
		sids[details["session_identifier"].(string)]++
	}
	assert.Equal(t, map[string]int{"": 3, a.live.SessionIdentifier: 1}, sids)
}

// TestBackchannelLogout_DisablingAUserTellsEveryAppThatKnewThem: an administrator disables the user.
func TestBackchannelLogout_DisablingAUserTellsEveryAppThatKnewThem(t *testing.T) {
	a := newUserWideApps(t, nil)

	resp, requestId := sendAdminRequest(t, a.adminToken, http.MethodPut,
		"/api/v1/admin/users/"+strconv.FormatInt(a.user.Id, 10)+"/enabled", api.UpdateUserEnabledRequest{Enabled: false})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	a.assertToldEverywhere(t, requestId)
}

// TestBackchannelLogout_DisablingADisabledUserTellsNobody: a second disable ends nothing, so it
// tells nobody.
func TestBackchannelLogout_DisablingADisabledUserTellsNobody(t *testing.T) {
	a := newUserWideApps(t, nil)
	require.NoError(t, database.UpdateUser(context.Background(), nil, func() *record.User {
		u, err := database.GetUserById(context.Background(), nil, a.user.Id)
		require.NoError(t, err)
		u.Enabled = false
		return u
	}()))

	resp, _ := sendAdminRequest(t, a.adminToken, http.MethodPut,
		"/api/v1/admin/users/"+strconv.FormatInt(a.user.Id, 10)+"/enabled", api.UpdateUserEnabledRequest{Enabled: false})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	time.Sleep(2 * time.Second)
	assert.Empty(t, a.onBoth.received())
	assert.Empty(t, a.grantOnly.received())
	assert.Empty(t, a.sidRequired.received())
}

// TestBackchannelLogout_DeletingAUserTellsEveryAppThatKnewThem: an administrator deletes the user,
// whose deletion takes the sessions and the grants with it; they are read inside the deletion's
// transaction, before it.
func TestBackchannelLogout_DeletingAUserTellsEveryAppThatKnewThem(t *testing.T) {
	a := newUserWideApps(t, nil)

	resp, _ := sendAdminRequest(t, a.adminToken, http.MethodDelete,
		"/api/v1/admin/users/"+strconv.FormatInt(a.user.Id, 10), nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// The user is gone, so the audit rows are not checked by user.
	a.assertToldEverywhere(t, "")
}

// TestBackchannelLogout_AnAdministratorSettingThePasswordTellsEveryAppThatKnewTheUser: an
// administrator sets the user's password.
func TestBackchannelLogout_AnAdministratorSettingThePasswordTellsEveryAppThatKnewTheUser(t *testing.T) {
	a := newUserWideApps(t, nil)

	resp, requestId := sendAdminRequest(t, a.adminToken, http.MethodPut,
		"/api/v1/admin/users/"+strconv.FormatInt(a.user.Id, 10)+"/password",
		api.UpdateUserPasswordRequest{NewPassword: fake.Password(20)})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	a.assertToldEverywhere(t, requestId)
}

// TestBackchannelLogout_APasswordResetTellsEveryAppThatKnewTheUser: the user resets a forgotten
// password through the emailed link.
func TestBackchannelLogout_APasswordResetTellsEveryAppThatKnewTheUser(t *testing.T) {
	user := &record.User{Subject: fake.UUID(), Enabled: true, EmailVerified: true,
		Email: uniqueEmail("bcl@reset.test")}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	a := newUserWideApps(t, user)

	resetPasswordFor(t, user, fake.Password(20))

	a.assertToldEverywhere(t, "")
}

// TestBackchannelLogout_TheUsersOwnPasswordChangeTellsTheOtherSessionsApps: the user changes their
// own password, which keeps the session they changed it from and ends the others (#784 decision 3's
// session-specific shape). Each app on an ended session that was still valid gets a sub+sid token
// for it, whether or not it requires sid; the expired session's apps, the kept session's apps and an
// app holding only a grant are told nothing.
func TestBackchannelLogout_TheUsersOwnPasswordChangeTellsTheOtherSessionsApps(t *testing.T) {
	accessToken, user := getUserAccessTokenWithAccountScope(t)
	current := "Curr3ntP4ss!"
	setUserPassword(t, user, current)
	kept, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, extractSidClaim(t, accessToken))
	require.NoError(t, err)
	require.NotNil(t, kept, "the caller's token names its session")

	a := newUserWideApps(t, user)
	onKept := newLogoutReceiver(t, http.StatusOK)
	onSession(t, kept, backchannelClient(t, a.adminToken, onKept.uri()))

	resp := makeAPIRequest(t, http.MethodPut, appConfig.AuthServer.BaseURL+"/api/v1/account/password", accessToken,
		api.UpdateAccountPasswordRequest{CurrentPassword: current, NewPassword: fake.Password(20)})
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)

	posts := a.onBoth.waitFor(t, 1, 10*time.Second)
	assertLogoutToken(t, posts[0], a.clients[a.onBoth].ClientIdentifier, user.Subject, a.live.SessionIdentifier)
	posts = a.sidRequired.waitFor(t, 1, 10*time.Second)
	assertLogoutToken(t, posts[0], a.sidRequiredClient.ClientIdentifier, user.Subject, a.live.SessionIdentifier)

	time.Sleep(2 * time.Second)
	assert.Len(t, a.onBoth.received(), 1, "the expired session tells nobody")
	assert.Len(t, a.sidRequired.received(), 1)
	assert.Empty(t, a.onExpired.received(), "the expired session tells nobody")
	assert.Empty(t, a.grantOnly.received(), "a grant alone is told nothing when particular sessions end")
	assert.Empty(t, onKept.received(), "the session the password was changed from is kept")
}
