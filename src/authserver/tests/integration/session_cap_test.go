package integration

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The per-user session cap (#564 decision 5): when a sign-in starts a new session and the user would
// then hold more than the cap, it ends their expired and then least recently accessed sessions, never
// the new one, each with a deleted_user_session row whose reason is session_cap. Each browser here is
// a device of its own, so the device sweep removes nothing and only the cap is at work.

// withSessionCap sets the cap for the rest of the test, and puts the settings row back after it.
func withSessionCap(t *testing.T, maxSessions int) *record.Settings {
	t.Helper()
	return changeSettings(t, func(settings *record.Settings) { settings.MaxUserSessionsPerUser = maxSessions })
}

// storedSessionIds is the ids of sessions, in the order given.
func storedSessionIds(sessions []record.UserSession) []int64 {
	ids := []int64{}
	for _, session := range sessions {
		ids = append(ids, session.Id)
	}
	return ids
}

// Under a cap of two, a third browser's sign-in ends the session least recently used, the first
// browser's, and keeps the second's and its own.
func TestSessionCap_ASignInOverTheCapEndsTheLeastRecentlyUsedSession(t *testing.T) {
	f := newDeviceFixture(t)
	withSessionCap(t, 2)

	f.signIn(t, newDeviceBrowser(t))
	first := f.storedSessions(t)
	require.Len(t, first, 1)
	f.signIn(t, newDeviceBrowser(t))
	require.Len(t, f.storedSessions(t), 2)

	requestId := f.signIn(t, newDeviceBrowser(t))

	sessions := f.storedSessions(t)
	require.Len(t, sessions, 2, "the user holds no more than the cap")
	assert.NotContains(t, storedSessionIds(sessions), first[0].Id, "the first browser's session is the one ended")
	assert.Len(t, sessionsThroughAdminAPI(t, f.adminToken, f.user.Id), 2)
	assert.Equal(t, []map[string]any{{
		"user_session_id": float64(first[0].Id),
		"logged_in_user":  "",
		"reason":          "session_cap",
	}}, auditRows(t, f.adminToken, "deleted_user_session", requestId))
}

// An expired session goes before a valid one even when it was used more recently: here the second
// browser's session is past the max lifetime but used just now, and it is ended rather than the first
// browser's, which is valid and was used longer ago.
func TestSessionCap_ExpiredSessionsGoFirst(t *testing.T) {
	f := newDeviceFixture(t)
	settings := withSessionCap(t, 2)

	f.signIn(t, newDeviceBrowser(t))
	f.signIn(t, newDeviceBrowser(t))
	sessions := f.storedSessions(t)
	require.Len(t, sessions, 2)
	valid, expired := sessions[0], sessions[1]
	if valid.Id > expired.Id {
		valid, expired = expired, valid
	}
	now := time.Now().UTC()
	expired.Started = now.Add(-time.Duration(settings.UserSessionMaxLifetimeInSeconds+3600) * time.Second)
	expired.LastAccessed = now
	require.NoError(t, database.UpdateUserSession(context.Background(), nil, &expired))
	valid.LastAccessed = now.Add(-10 * time.Minute)
	require.NoError(t, database.UpdateUserSession(context.Background(), nil, &valid))

	requestId := f.signIn(t, newDeviceBrowser(t))

	after := f.storedSessions(t)
	require.Len(t, after, 2)
	assert.Contains(t, storedSessionIds(after), valid.Id, "the valid session stays")
	assert.NotContains(t, storedSessionIds(after), expired.Id, "the expired session is the one ended")
	assert.Equal(t, []map[string]any{{
		"user_session_id": float64(expired.Id),
		"logged_in_user":  "",
		"reason":          "session_cap",
	}}, auditRows(t, f.adminToken, "deleted_user_session", requestId))
}

// A cap of 0 is no limit: three browsers keep three sessions.
func TestSessionCap_ACapOfZeroEndsNothing(t *testing.T) {
	f := newDeviceFixture(t)
	withSessionCap(t, 0)

	f.signIn(t, newDeviceBrowser(t))
	f.signIn(t, newDeviceBrowser(t))
	requestId := f.signIn(t, newDeviceBrowser(t))

	assert.Len(t, f.storedSessions(t), 3)
	assert.Empty(t, auditRows(t, f.adminToken, "deleted_user_session", requestId))
}
