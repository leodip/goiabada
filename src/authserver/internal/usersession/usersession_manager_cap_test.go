package usersession

import (
	"context"
	"database/sql"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
)

// -----------------------------------------------------------------------------
// The per-user session cap (#564 decision 5)
//
// When a sign-in starts a new session and the user would then hold more sessions than the cap, it
// deletes as many of their other sessions as it takes, in the same transaction, never the new one:
// expired sessions first, then the least recently accessed, the lower id breaking a tie. It counts
// what rule 1 and the device sweep left, and every stored session of the user, expired ones the
// background job has not removed yet included.
// -----------------------------------------------------------------------------

// capLimits is a cap of maxSessions under the lifetimes every case below judges expiry by: an
// hour idle, a day in all.
func capLimits(maxSessions int) SessionLimits {
	return SessionLimits{IdleTimeoutInSeconds: 3600, MaxLifetimeInSeconds: 86400, MaxSessionsPerUser: maxSessions}
}

// otherBrowser is a session of the user from another device, started startedAgo and last used
// usedAgo, which the device sweep leaves alone.
func otherBrowser(id int64, startedAgo, usedAgo time.Duration) record.UserSession {
	now := time.Now().UTC()
	return record.UserSession{
		Id:                id,
		SessionIdentifier: fmt.Sprintf("other-browser-%d", id),
		UserId:            123,
		Started:           now.Add(-startedAgo),
		LastAccessed:      now.Add(-usedAgo),
		DeviceId:          otherDeviceId,
	}
}

// startCapped signs user 123 in with existing as the user's other sessions and limits as the
// settings, expecting a delete of each id in deleted, and returns what it reported removed.
func startCapped(t *testing.T, existing []record.UserSession, limits SessionLimits, deleted ...int64) []Removal {
	t.Helper()
	m := newStartSessionMocks(t)
	m.expectPersistThroughCommit(123, existing)
	for _, id := range deleted {
		m.db.On("DeleteUserSession", mock.Anything, txSentinel, id).Return(nil).Once()
	}

	_, removed, err := m.manager.StartNewUserSession(httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, "192.168.1.50", nil, limits)

	require.NoError(t, err)
	return removed
}

// With the new session the user would hold four under a cap of three, so one other goes, and it is
// the least recently accessed, whatever order the database listed them in or when each started.
func TestStartNewUserSession_OverTheCapEndsTheLeastRecentlyAccessed(t *testing.T) {
	removed := startCapped(t, []record.UserSession{
		otherBrowser(41, 2*time.Hour, 10*time.Minute),
		otherBrowser(42, 3*time.Minute, 30*time.Minute),
		otherBrowser(43, 20*time.Hour, 1*time.Minute),
	}, capLimits(3), 42)

	assert.Equal(t, map[int64]string{42: "session_cap"}, removedReasons(removed))
}

// At the cap exactly, counting the new session, nothing goes.
func TestStartNewUserSession_AtTheCapEndsNothing(t *testing.T) {
	removed := startCapped(t, []record.UserSession{
		otherBrowser(41, time.Hour, 10*time.Minute),
		otherBrowser(42, time.Hour, 30*time.Minute),
	}, capLimits(3))

	assert.Empty(t, removed)
}

// A cap of 0 is no limit at all.
func TestStartNewUserSession_ACapOfZeroEndsNothing(t *testing.T) {
	var existing []record.UserSession
	for id := int64(1); id <= 30; id++ {
		existing = append(existing, otherBrowser(id, time.Hour, time.Duration(id)*time.Minute))
	}

	removed := startCapped(t, existing, capLimits(0))

	assert.Empty(t, removed)
}

// A cap of 1 is one session per user: every other session goes, and the new one stays.
func TestStartNewUserSession_ACapOfOneLeavesOnlyTheNewSession(t *testing.T) {
	removed := startCapped(t, []record.UserSession{
		otherBrowser(41, time.Hour, 10*time.Minute),
		otherBrowser(42, time.Hour, 30*time.Minute),
	}, capLimits(1), 42, 41)

	assert.Equal(t, []int64{42, 41}, removedIds(removed), "least recently accessed first")
	assert.Equal(t, map[int64]string{41: "session_cap", 42: "session_cap"}, removedReasons(removed))
}

// Expired sessions go before any valid one, even when they were used more recently: a session past
// its max lifetime can have been used a minute ago, and ending the valid session in its place would
// end one still in use and keep a dead one. Idle past the timeout counts as expired as well.
func TestStartNewUserSession_TheCapEndsExpiredSessionsFirst(t *testing.T) {
	removed := startCapped(t, []record.UserSession{
		otherBrowser(41, 2*time.Hour, 50*time.Minute), // valid, the least recently accessed
		otherBrowser(42, 25*time.Hour, 1*time.Minute), // past the max lifetime, used a minute ago
		otherBrowser(43, 3*time.Hour, 2*time.Hour),    // idle past the timeout
		otherBrowser(44, 2*time.Hour, 20*time.Minute), // valid
		otherBrowser(45, 2*time.Hour, 40*time.Minute), // valid
	}, capLimits(4), 43, 42)

	assert.Equal(t, []int64{43, 42}, removedIds(removed),
		"the two expired sessions, the less recently accessed of them first, and no valid one")
	assert.Equal(t, map[int64]string{42: "session_cap", 43: "session_cap"}, removedReasons(removed))
}

// Past the expired ones, the cap goes on to the valid sessions, least recently accessed first.
func TestStartNewUserSession_TheCapGoesOnToValidSessionsOnceTheExpiredAreGone(t *testing.T) {
	removed := startCapped(t, []record.UserSession{
		otherBrowser(41, 2*time.Hour, 50*time.Minute),
		otherBrowser(42, 25*time.Hour, 1*time.Minute),
		otherBrowser(43, 2*time.Hour, 20*time.Minute),
	}, capLimits(2), 42, 41)

	assert.Equal(t, []int64{42, 41}, removedIds(removed))
}

// Two sessions last accessed at the same instant are told apart by id, the lower one going first.
func TestStartNewUserSession_TheCapBreaksATieByTheLowerId(t *testing.T) {
	tied := time.Now().UTC().Add(-30 * time.Minute)
	sessionAt := func(id int64) record.UserSession {
		s := otherBrowser(id, time.Hour, 0)
		s.LastAccessed = tied
		return s
	}

	removed := startCapped(t, []record.UserSession{sessionAt(52), sessionAt(51), otherBrowser(53, time.Hour, 5*time.Minute)},
		capLimits(3), 51)

	assert.Equal(t, []int64{51}, removedIds(removed))
}

// The cap counts what rule 1 and the device sweep left: a sign-in that replaced the browser's own
// session and swept one from the same device is already back under the cap, so nothing goes for
// it, and each row keeps the reason it went for.
func TestStartNewUserSession_TheCapCountsWhatTheSweepsLeft(t *testing.T) {
	m := newStartSessionMocks(t)
	replaced := otherBrowser(41, time.Hour, 50*time.Minute)
	sameDevice := otherBrowser(42, time.Hour, 45*time.Minute)
	sameDevice.DeviceId = thisDeviceId
	m.expectPersistThroughCommit(123, []record.UserSession{
		replaced,
		sameDevice,
		otherBrowser(43, time.Hour, 40*time.Minute),
		otherBrowser(44, time.Hour, 30*time.Minute),
	})
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(41)).Return(nil).Once()
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()

	_, removed, err := m.manager.StartNewUserSession(httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, "192.168.1.50", &replaced, capLimits(3))

	require.NoError(t, err)
	assert.Equal(t, map[int64]string{41: "replaced_by_sign_in", 42: "same_device"}, removedReasons(removed))
}

// The sweeps and the cap together: the cap ends what is still over it after the sweeps, and only
// that, reporting each row once under the reason it went for.
func TestStartNewUserSession_TheCapEndsWhatIsStillOverItAfterTheSweeps(t *testing.T) {
	m := newStartSessionMocks(t)
	sameDevice := otherBrowser(42, time.Hour, time.Minute)
	sameDevice.DeviceId = thisDeviceId
	m.expectPersistThroughCommit(123, []record.UserSession{
		otherBrowser(41, time.Hour, 50*time.Minute),
		sameDevice,
		otherBrowser(43, time.Hour, 40*time.Minute),
		otherBrowser(44, time.Hour, 30*time.Minute),
	})
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(41)).Return(nil).Once()

	_, removed, err := m.manager.StartNewUserSession(httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, "192.168.1.50", nil, capLimits(3))

	require.NoError(t, err)
	assert.Equal(t, []int64{42, 41}, removedIds(removed), "the sweep's row, then the cap's")
	assert.Equal(t, map[int64]string{42: "same_device", 41: "session_cap"}, removedReasons(removed))
}

// The new session is never one the cap ends, though the database lists it among the user's sessions
// and it was, like the others, accessed: with a cap of 1 every other session goes and it stays.
func TestStartNewUserSession_TheCapNeverEndsTheNewSession(t *testing.T) {
	m := newStartSessionMocks(t)
	var created *record.UserSession
	datamocks.ExpectRunInTransaction(m.db, txSentinel)
	m.db.On("CreateUserSession", mock.Anything, txSentinel, mock.Anything).Run(func(args mock.Arguments) {
		created = args.Get(2).(*record.UserSession)
		created.Id = 99
	}).Return(nil).Once()
	m.db.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()
	m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return(
		func(_ context.Context, _ *sql.Tx, _ int64) ([]record.UserSession, error) {
			// The new row as the database lists it: the lowest id here and the oldest last access,
			// so an ordering that did not exclude it would pick it first.
			self := *created
			self.Id = 1
			self.LastAccessed = time.Now().UTC().Add(-50 * time.Minute)
			return []record.UserSession{self, otherBrowser(41, time.Hour, 10*time.Minute)}, nil
		}).Once()
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(41)).Return(nil).Once()

	_, removed, err := m.manager.StartNewUserSession(httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, "192.168.1.50", nil, capLimits(1))

	require.NoError(t, err)
	assert.Equal(t, []int64{41}, removedIds(removed))
}

// A rerun after a deadlock reports the committed attempt's cap removals once, as it does the
// sweep's: the first attempt ended 41 and 42, and by the rerun something else had removed 41, so the
// committed attempt ends 42 and 43 to get back under the cap.
func TestStartNewUserSession_ARerunReportsTheCommittedAttemptsCapRemovalsOnce(t *testing.T) {
	m := newStartSessionMocks(t)

	datamocks.ExpectRunInTransactionRerun(m.db, txSentinel)
	m.db.On("CreateUserSession", mock.Anything, txSentinel, mock.Anything).Run(func(args mock.Arguments) {
		args.Get(2).(*record.UserSession).Id = 99
	}).Return(nil).Twice()
	m.db.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Twice()
	m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return([]record.UserSession{
		otherBrowser(41, time.Hour, 50*time.Minute),
		otherBrowser(42, time.Hour, 40*time.Minute),
		otherBrowser(43, time.Hour, 30*time.Minute),
		otherBrowser(44, time.Hour, 20*time.Minute),
	}, nil).Once()
	m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return([]record.UserSession{
		otherBrowser(42, time.Hour, 40*time.Minute),
		otherBrowser(43, time.Hour, 30*time.Minute),
		otherBrowser(44, time.Hour, 20*time.Minute),
		otherBrowser(45, time.Hour, 10*time.Minute),
	}, nil).Once()
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(41)).Return(nil).Once()
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Twice()
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(43)).Return(nil).Once()

	_, removed, err := m.manager.StartNewUserSession(httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, "192.168.1.50", nil, capLimits(3))

	require.NoError(t, err)
	assert.Equal(t, []int64{42, 43}, removedIds(removed))
}
