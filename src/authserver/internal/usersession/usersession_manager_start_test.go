package usersession

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/uuid/uuidtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
)

// =============================================================================
// Tests for StartNewUserSession
//
// This is what creates the SSO session row after a successful login. Everything downstream (idle
// timeout, max lifetime, ACR step-up) reads the fields it sets here. Binding the row to the browser
// session is the caller's, after this returns: ceremony.Store.RegenerateSessionAndBind, and
// AbandonUserSession below when that fails.
// =============================================================================

// txSentinel is the transaction the shared stub hands the body. It is non-nil and the mock
// database never dereferences it, which is the whole of what it has to be: an expectation
// written against txSentinel matches a call the body made and no call made before or after the
// transaction, where the manager passes nil. datamocks.ExpectRunInTransaction refuses a nil
// outright, so a sweep moved back outside the transaction cannot pass on call count alone (#422).
var txSentinel = &sql.Tx{}

// chromeUserAgent is a desktop UA string, so the device fields are populated
// rather than empty.
const chromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// firefoxUserAgent is the second device of the sweep table: a different browser on a different OS,
// so the raw header differs from chromeUserAgent well before its end.
const firefoxUserAgent = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"

// startSessionMocks is the strict database mock and the manager over it. The manager touches no
// browser session, so there is no store here.
type startSessionMocks struct {
	db      *datamocks.Database
	manager *Manager
}

func newStartSessionMocks(t *testing.T) *startSessionMocks {
	t.Helper()
	db := datamocks.NewDatabase(t)
	return &startSessionMocks{db: db, manager: &Manager{database: db}}
}

// someCredentialInstant is the captured credential instant for the tests that are not about
// AuthTime. StartNewUserSession refuses nil and zero, so every legitimate call carries one; a
// fixed offset into the past rather than now, so no assertion in those tests can lean on
// AuthTime coinciding with the clock.
func someCredentialInstant() *time.Time {
	instant := time.Now().UTC().Add(-5 * time.Minute)
	return &instant
}

// thisBrowser is a sign-in from the browser holding thisDevice, the device identifier whose digest
// the sweep's same-device rows carry as thisDeviceId, with Chrome's labels.
func thisBrowser() Device {
	return Device{Identifier: thisDevice, Name: "Chrome 120.0.0.0", Type: "Desktop", OS: "Windows 10.0",
		UserAgent: chromeUserAgent}
}

// aNewDevice is a sign-in from a browser that presented no device identifier, for which the HTTP
// side minted thisDevice: the same value, so a sweep that matched it anyway would show.
func aNewDevice() Device {
	device := thisBrowser()
	device.New = true
	return device
}

// expectPersistThroughCommit sets up everything up to and including the commit: the transaction,
// the session row, its client association and the sibling read the sweep runs on. The
// browser-session read before it and the rotation after it are the real store's, and a case
// testing either one's failure arms the backend instead.
//
// The sibling read is matched on txSentinel rather than mock.Anything, so it is an assertion
// and not just a stub: a read moved back outside the transaction arrives with a nil tx and the
// strict mock fails it as unexpected.
//
// The returned pointer receives the session that was handed to CreateUserSession.
func (m *startSessionMocks) expectPersistThroughCommit(userId int64, existingSessions []record.UserSession) **record.UserSession {
	captured := new(*record.UserSession)

	datamocks.ExpectRunInTransaction(m.db, txSentinel)
	m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		created := args.Get(2).(*record.UserSession)
		created.Id = 99 // stand in for the generated primary key
		*captured = created
	}).Return(nil).Once()
	m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, userId).Return(existingSessions, nil).Once()

	return captured
}

func TestStartNewUserSession_PopulatesSessionFields(t *testing.T) {
	m := newStartSessionMocks(t)
	device := thisBrowser()

	captured := m.expectPersistThroughCommit(123, nil)
	credentialAcceptedAt := someCredentialInstant()

	before := time.Now().UTC()
	result, _, err := m.manager.StartNewUserSession(context.Background(), 7, authenticationOf(123, "pwd otp", record.AcrLevel2Mandatory, credentialAcceptedAt), 0, nil, device, "192.168.1.50", nil, SessionLimits{})
	after := time.Now().UTC()

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Same(t, *captured, result, "the persisted session must be the one returned")

	assert.Equal(t, int64(123), result.UserId)
	assert.Equal(t, "pwd otp", result.AuthMethods)
	assert.Equal(t, record.AcrLevel2Mandatory, result.AcrLevel)
	assert.Equal(t, "192.168.1.50", result.IpAddress, "the address is the one the caller passed")

	// The identifier must be a fresh UUID, since it is what the browser cookie
	// carries and what every later lookup keys on.
	parsed, parseErr := uuidtest.Parse(result.SessionIdentifier)
	require.NoError(t, parseErr, "the session identifier must be a valid UUID")
	// uuidtest.Parse accepts the nil UUID, so "non-empty" would pass against a hard-coded
	// one. Compare against the nil spelling itself.
	assert.NotEqual(t, "00000000-0000-0000-0000-000000000000", parsed)

	// Started and LastAccessed are stamped with the same UTC now: they measure the session's
	// own life. AuthTime is the captured credential instant, never this call's clock;
	// TestStartNewUserSession_AuthTimeIsTheCapturedCredentialInstant pins the distance
	// between the two, and TestStartNewUserSession_RefusesAMissingCredentialInstant that no
	// call runs without one.
	for name, value := range map[string]time.Time{
		"Started":      result.Started,
		"LastAccessed": result.LastAccessed,
	} {
		assert.False(t, value.Before(before), "%s must not predate the call", name)
		assert.False(t, value.After(after), "%s must not postdate the call", name)
		assert.Equal(t, time.UTC, value.Location(), "%s must be stored in UTC", name)
	}
	assert.Equal(t, result.Started, result.LastAccessed)
	assert.True(t, result.AuthTime.Equal(*credentialAcceptedAt), "AuthTime must be the captured instant")
	assert.Equal(t, time.UTC, result.AuthTime.Location(), "AuthTime must be stored in UTC")

	assert.EqualValues(t, 0, result.OtpConfigGeneration,
		"a nil capture must land the session at generation 0, which is the fail-closed value: "+
			"it owes a level 2 re-prompt as soon as the user's counter is above 0")

	// The three display labels are the ones the caller read from the request (useragent.Labels,
	// whose table lives at its own seam), stored as given.
	assert.Equal(t, "Chrome 120.0.0.0", result.DeviceName)
	assert.Equal(t, "Desktop", result.DeviceType)
	assert.Equal(t, "Windows 10.0", result.DeviceOS)

	// The raw header is stored beside them, for display as they are. Unlike the three labels it is
	// the string the browser sent, not a parse of it. The sweep reads none of the four: it keys on
	// the device identifier's digest, never the identifier itself (#564 decision 4).
	assert.Equal(t, chromeUserAgent, result.UserAgent)
	assert.Equal(t, thisDeviceId, result.DeviceId)
	assert.NotEqual(t, thisDevice, result.DeviceId)
}

// The header reaches the row through useragent.BoundRaw, so a browser sending more than the column
// holds cannot make the insert fail. 600 bytes rather than 513, so a cut at the wrong width shows
// up in the assertion rather than being off by one.
func TestStartNewUserSession_BoundsTheUserAgentToTheColumnWidth(t *testing.T) {
	m := newStartSessionMocks(t)
	overlong := strings.Repeat("a", 600)
	device := thisBrowser()
	device.UserAgent = overlong

	captured := m.expectPersistThroughCommit(123, nil)

	result, _, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, device, "192.168.1.50", nil, SessionLimits{})

	require.NoError(t, err)
	assert.Same(t, *captured, result)
	assert.Len(t, result.UserAgent, 512, "the persisted header must be cut to the column width")
	assert.True(t, strings.HasPrefix(overlong, result.UserAgent),
		"the cut must keep the start of the header the browser sent, not rewrite it")
}

func TestStartNewUserSession_RecordsTheClient(t *testing.T) {
	m := newStartSessionMocks(t)
	var capturedClient *record.UserSessionClient
	datamocks.ExpectRunInTransaction(m.db, txSentinel)
	m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		args.Get(2).(*record.UserSession).Id = 99
	}).Return(nil).Once()
	m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		capturedClient = args.Get(2).(*record.UserSessionClient)
	}).Return(nil).Once()
	m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return(nil, nil).Once()

	result, _, err := m.manager.StartNewUserSession(context.Background(), 7, authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, thisBrowser(), "192.168.1.50", nil, SessionLimits{})

	require.NoError(t, err)
	assert.Len(t, result.Clients, 1)
	assert.Equal(t, int64(7), result.Clients[0].ClientId)

	assert.NotNil(t, capturedClient)
	assert.Equal(t, int64(7), capturedClient.ClientId)
	assert.Equal(t, int64(99), capturedClient.UserSessionId,
		"the client row must point at the session's generated id")
	assert.Equal(t, result.Started, capturedClient.Started)
	assert.Equal(t, result.Started, capturedClient.LastAccessed)
}

// -----------------------------------------------------------------------------
// Superseding sessions from the same device
//
// After creating the new session, any other session of the same user recorded with the same
// device identifier is deleted, so a re-login from one browser replaces rather than accumulates.
// The identifier is the browser's device cookie, compared by its digest; the user agent and the
// address are recorded and no longer compared, so two browsers sending one header from one address
// are two devices (#564 decision 4).
// -----------------------------------------------------------------------------

// A session recorded with this browser's identifier is the same device's, whatever header and
// address it was last seen with.
func TestStartNewUserSession_DeletesTheSessionsOfTheSameDevice(t *testing.T) {
	m := newStartSessionMocks(t)
	device := thisBrowser()

	stale := record.UserSession{
		Id:                42,
		SessionIdentifier: "an-older-session",
		IpAddress:         "10.0.0.9",
		UserAgent:         firefoxUserAgent,
		DeviceId:          thisDeviceId,
	}

	m.expectPersistThroughCommit(123, []record.UserSession{stale})
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()

	_, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, device, "192.168.1.50", nil, SessionLimits{})

	require.NoError(t, err)
	assert.Equal(t, []int64{42}, removedIds(removed), "the swept row is reported so the caller can audit it")
	assert.Equal(t, map[int64]string{42: "same_device"}, removedReasons(removed),
		"a row the sweep matched is reported as the same device's")
}

// removedIds is the ids of the rows StartNewUserSession reported removed, in order: the row id is
// what the caller's audit event names.
func removedIds(removed []Removal) []int64 {
	ids := []int64{}
	for _, removal := range removed {
		ids = append(ids, removal.Session.Id)
	}
	return ids
}

// removedReasons is each reported row's id beside the reason its deleted_user_session event is to
// carry, in order (#564 decision 7).
func removedReasons(removed []Removal) map[int64]string {
	reasons := map[int64]string{}
	for _, removal := range removed {
		reasons[removal.Session.Id] = removal.Reason
	}
	return reasons
}

// Anything recorded with another identifier, or with none, is a separate sign-in and must survive.
// NewDatabase(t) fails on an unexpected DeleteUserSession, which is the assertion.
func TestStartNewUserSession_KeepsTheSessionsOfOtherDevices(t *testing.T) {
	// Every case below is compared against a request from thisDevice, sending chromeUserAgent from
	// 192.168.1.50.
	testCases := []struct {
		name    string
		session record.UserSession
	}{
		{
			// The whole of #564's second part: two windows, two profiles, or two machines behind
			// one router on one browser version send the same pair, and are still two devices.
			name: "another device with the same header and address",
			session: record.UserSession{
				Id: 42, SessionIdentifier: "other", IpAddress: "192.168.1.50",
				UserAgent: chromeUserAgent, DeviceId: otherDeviceId,
			},
		},
		{
			// A session stored before the upgrade carries no identifier and there is nothing to
			// backfill it from, so it matches nothing and expires on its own.
			name: "a session stored before the upgrade, from the same header and address",
			session: record.UserSession{
				Id: 42, SessionIdentifier: "legacy", IpAddress: "192.168.1.50",
				UserAgent: chromeUserAgent, DeviceId: "",
			},
		},
		{
			// The three labels were never the key and are display only.
			name: "the three labels match but the identifier does not",
			session: record.UserSession{
				Id: 42, SessionIdentifier: "other", IpAddress: "192.168.1.50",
				UserAgent: chromeUserAgent, DeviceId: otherDeviceId,
				DeviceName: "Chrome 120.0.0.0", DeviceType: "Desktop", DeviceOS: "Windows 10.0",
			},
		},
		{
			// The sweep compares digests, so a row holding the browser's raw value, which no
			// session is written with, is not the same device: a database reader cannot turn what
			// it reads into a cookie that sweeps the row it read.
			name: "a session holding the cookie's value rather than its digest",
			session: record.UserSession{
				Id: 42, SessionIdentifier: "other", IpAddress: "192.168.1.50",
				UserAgent: chromeUserAgent, DeviceId: thisDevice,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := newStartSessionMocks(t)
			m.expectPersistThroughCommit(123, []record.UserSession{tc.session})

			_, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
				authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, thisBrowser(), "192.168.1.50", nil, SessionLimits{})

			require.NoError(t, err)
			assert.Empty(t, removed)
		})
	}
}

// A browser that sends no device cookie is given a new identifier, so it is a new device: it matches
// neither another device's session nor one stored before the upgrade, header-less or not. The
// identifier here is the one row 41 was recorded with, so it is New, not the value, that sweeps
// nothing.
func TestStartNewUserSession_ABrowserWithNoDeviceCookieSweepsNothing(t *testing.T) {
	m := newStartSessionMocks(t)
	device := aNewDevice()
	device.UserAgent = ""
	m.expectPersistThroughCommit(123, []record.UserSession{
		{Id: 41, SessionIdentifier: "this-browser-before-its-cookies-were-cleared", IpAddress: "192.168.1.50", DeviceId: thisDeviceId},
		{Id: 42, SessionIdentifier: "legacy", IpAddress: "192.168.1.50", UserAgent: "", DeviceId: ""},
	})

	_, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, device, "192.168.1.50", nil, SessionLimits{})

	require.NoError(t, err)
	assert.Empty(t, removed)
}

// The session just created must never delete itself, even though it matches its
// own device and IP on every other field.
func TestStartNewUserSession_DoesNotDeleteTheSessionItJustCreated(t *testing.T) {
	m := newStartSessionMocks(t)
	device := thisBrowser()

	var newIdentifier string
	datamocks.ExpectRunInTransaction(m.db, txSentinel)
	m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		created := args.Get(2).(*record.UserSession)
		created.Id = 99
		newIdentifier = created.SessionIdentifier
	}).Return(nil).Once()
	m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	// Return the freshly created session as if it were already persisted. The
	// identifier is only known once CreateUserSession has run, so this is
	// resolved lazily at call time.
	m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return(
		func(_ context.Context, _ *sql.Tx, _ int64) ([]record.UserSession, error) {
			return []record.UserSession{{
				Id:                99,
				SessionIdentifier: newIdentifier,
				IpAddress:         "192.168.1.50",
				// The new key, so this row reaches the self-identifier guard rather than
				// being skipped by a mismatch and passing vacuously.
				DeviceId: thisDeviceId,
			}}, nil
		}).Once()

	_, _, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, device, "192.168.1.50", nil, SessionLimits{})

	assert.NoError(t, err)
}

// -----------------------------------------------------------------------------
// The session a sign-in replaces, the address it is given, and what it reports (#243)
//
// A sign-in that could not reuse the browser's own session for the same user -- expired, idle, or
// older than the max_age asked for -- replaces it. Every row removed comes back once, and only when
// its deletion committed, because each is owed a deleted_user_session event after the commit.
// -----------------------------------------------------------------------------

// The address stored is the argument, not the request's RemoteAddr: the caller reads the browser's
// address through the one reader the rest of the server uses.
func TestStartNewUserSession_StoresTheAddressItIsGiven(t *testing.T) {
	m := newStartSessionMocks(t)
	device := thisBrowser()

	captured := m.expectPersistThroughCommit(123, nil)

	result, _, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, device, "203.0.113.7", nil, SessionLimits{})

	require.NoError(t, err)
	assert.Equal(t, "203.0.113.7", (*captured).IpAddress)
	assert.Equal(t, "203.0.113.7", result.IpAddress)
}

// The browser's own session is removed with the new one's creation wherever it was last seen and
// whatever device it recorded: it is the one this sign-in replaces. Before #243 it survived
// whenever its address or header differed from the sign-in's, listed and bumped by its refresh
// tokens with no browser able to reach it. The other row is another device's and is not replaced,
// so it survives.
func TestStartNewUserSession_DeletesTheSessionItReplacesWhereverItWasSeen(t *testing.T) {
	m := newStartSessionMocks(t)
	replaced := record.UserSession{
		Id: 42, SessionIdentifier: "the-cookie-named-this", UserId: 123,
		IpAddress: "198.51.100.20", UserAgent: firefoxUserAgent, DeviceId: otherDeviceId,
	}
	m.expectPersistThroughCommit(123, []record.UserSession{
		replaced,
		{Id: 43, SessionIdentifier: "another-device", UserId: 123, IpAddress: "198.51.100.21", UserAgent: firefoxUserAgent, DeviceId: otherDeviceId},
	})
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()

	_, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, thisBrowser(), "192.168.1.50", &replaced, SessionLimits{})

	require.NoError(t, err)
	assert.Equal(t, []int64{42}, removedIds(removed))
	assert.Equal(t, map[int64]string{42: "replaced_by_sign_in"}, removedReasons(removed),
		"the row the browser's cookie named is reported as the one this sign-in replaced")
}

// A replaced session on the sign-in's own device is both reasons at once. It is deleted once and
// reported once, as the session this sign-in replaced, so the caller writes one event for it
// rather than two (#564 decision 7). DeleteUserSession answers nil for a row already gone, so a
// second delete would not fail: the Once is the assertion.
func TestStartNewUserSession_AReplacedSessionThatAlsoMatchesTheSweepIsRemovedOnce(t *testing.T) {
	m := newStartSessionMocks(t)
	replaced := record.UserSession{
		Id: 42, SessionIdentifier: "the-cookie-named-this", UserId: 123,
		IpAddress: "192.168.1.50", UserAgent: chromeUserAgent, DeviceId: thisDeviceId,
	}
	m.expectPersistThroughCommit(123, []record.UserSession{replaced})
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()

	_, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, thisBrowser(), "192.168.1.50", &replaced, SessionLimits{})

	require.NoError(t, err)
	assert.Equal(t, []int64{42}, removedIds(removed))
	assert.Equal(t, map[int64]string{42: "replaced_by_sign_in"}, removedReasons(removed))
}

// One sign-in can remove rows for both reasons, and each is reported with its own: the row the
// cookie named, seen elsewhere, as the one replaced, and another row from this device as the same
// device's. The third row is from another device and is not the one replaced, so it survives.
func TestStartNewUserSession_EachRemovalIsReportedWithItsOwnReason(t *testing.T) {
	m := newStartSessionMocks(t)
	replaced := record.UserSession{
		Id: 42, SessionIdentifier: "the-cookie-named-this", UserId: 123,
		IpAddress: "198.51.100.20", UserAgent: firefoxUserAgent, DeviceId: otherDeviceId,
	}
	m.expectPersistThroughCommit(123, []record.UserSession{
		replaced,
		{Id: 43, SessionIdentifier: "same-device", UserId: 123, IpAddress: "192.168.1.50", UserAgent: chromeUserAgent, DeviceId: thisDeviceId},
		{Id: 44, SessionIdentifier: "another-device", UserId: 123, IpAddress: "192.168.1.50", UserAgent: chromeUserAgent, DeviceId: otherDeviceId},
	})
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(43)).Return(nil).Once()

	_, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, thisBrowser(), "192.168.1.50", &replaced, SessionLimits{})

	require.NoError(t, err)
	assert.Equal(t, []int64{42, 43}, removedIds(removed))
	assert.Equal(t, map[int64]string{42: "replaced_by_sign_in", 43: "same_device"}, removedReasons(removed))
}

// A replaced session that is no longer there when the transaction reads -- a logout or the idle
// sweep got to it first -- is not deleted and not reported: this sign-in did not remove it, and an
// event saying so would record a deletion twice. The strict mock refuses a DeleteUserSession.
func TestStartNewUserSession_AReplacedSessionAlreadyGoneIsNotReported(t *testing.T) {
	m := newStartSessionMocks(t)
	replaced := record.UserSession{Id: 42, SessionIdentifier: "already-gone", UserId: 123, IpAddress: "198.51.100.20"}
	m.expectPersistThroughCommit(123, nil)

	_, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, thisBrowser(), "192.168.1.50", &replaced, SessionLimits{})

	require.NoError(t, err)
	assert.Empty(t, removed)
}

// Another user's session is not this function's to end: the cross-user handover terminates it with
// revocation before calling here, and replacing it here would delete it with nothing revoked. It is
// refused before anything is read or written.
func TestStartNewUserSession_RefusesToReplaceAnotherUsersSession(t *testing.T) {
	m := newStartSessionMocks(t)
	foreign := record.UserSession{Id: 42, SessionIdentifier: "someone-else", UserId: 999}

	result, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, thisBrowser(), "192.168.1.50", &foreign, SessionLimits{})

	require.ErrorContains(t, err, "belongs to user 999")
	assert.Nil(t, result)
	assert.Nil(t, removed)
	m.db.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
}

// No session is recorded without a device identifier: an empty one has a digest every such browser
// would share, so the next sign-in of any of them would sweep this one as the same device. Refused
// before anything is written, whether or not the identifier is called new.
func TestStartNewUserSession_RefusesAMissingDeviceIdentifier(t *testing.T) {
	for name, device := range map[string]Device{
		"presented": {Name: "Chrome 120.0.0.0", UserAgent: chromeUserAgent},
		"new":       {New: true, Name: "Chrome 120.0.0.0", UserAgent: chromeUserAgent},
	} {
		t.Run(name, func(t *testing.T) {
			m := newStartSessionMocks(t)

			result, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
				authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, device, "192.168.1.50", nil, SessionLimits{})

			require.ErrorContains(t, err, "no device identifier given")
			assert.Nil(t, result)
			assert.Nil(t, removed)
			m.db.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
		})
	}
}

// RunInTransaction reruns the whole body after a deadlock abort, so what the aborted attempt
// deleted was undone. The rows reported are the committed attempt's, once each: row 41 was deleted
// by the first attempt only -- something else removed it before the rerun read -- and row 42 by
// both. A slice kept across attempts would report 41, which the database has no deletion of by this
// sign-in, and 42 twice.
func TestStartNewUserSession_ARerunReportsTheCommittedAttemptsRemovalsOnce(t *testing.T) {
	m := newStartSessionMocks(t)
	sameDevice := func(id int64) record.UserSession {
		return record.UserSession{Id: id, SessionIdentifier: fmt.Sprintf("row-%d", id), IpAddress: "192.168.1.50", DeviceId: thisDeviceId}
	}

	datamocks.ExpectRunInTransactionRerun(m.db, txSentinel)
	m.db.On("CreateUserSession", mock.Anything, txSentinel, mock.Anything).Run(func(args mock.Arguments) {
		args.Get(2).(*record.UserSession).Id = 99
	}).Return(nil).Twice()
	m.db.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Twice()
	m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).
		Return([]record.UserSession{sameDevice(41), sameDevice(42)}, nil).Once()
	m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).
		Return([]record.UserSession{sameDevice(42)}, nil).Once()
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(41)).Return(nil).Once()
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Twice()

	_, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, thisBrowser(), "192.168.1.50", nil, SessionLimits{})

	require.NoError(t, err)
	assert.Equal(t, []int64{42}, removedIds(removed))
}

// A transaction that does not commit reports nothing, even when the body had already deleted rows
// before it failed: the rollback undid them, and an event for each would record deletions that did
// not happen. The refused commit is the same, because the helper cannot say it landed.
func TestStartNewUserSession_AnUncommittedTransactionReportsNoRemovals(t *testing.T) {
	dbErr := errors.New("database is down")
	sweep := []record.UserSession{
		{Id: 41, SessionIdentifier: "row-41", IpAddress: "192.168.1.50", DeviceId: thisDeviceId},
		{Id: 42, SessionIdentifier: "row-42", IpAddress: "192.168.1.50", DeviceId: thisDeviceId},
	}

	t.Run("a later delete fails and the body rolls back", func(t *testing.T) {
		m := newStartSessionMocks(t)
		stub := datamocks.ExpectRunInTransaction(m.db, txSentinel)
		m.db.On("CreateUserSession", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()
		m.db.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()
		m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return(sweep, nil).Once()
		m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(41)).Return(nil).Once()
		m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(dbErr).Once()

		result, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
			authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, thisBrowser(), "192.168.1.50", nil, SessionLimits{})

		require.ErrorIs(t, err, dbErr)
		require.ErrorIs(t, stub.BodyErr, dbErr, "the body rolled back")
		assert.Nil(t, result)
		assert.Empty(t, removed, "row 41's deletion was rolled back with the rest")
	})

	t.Run("the commit is refused", func(t *testing.T) {
		m := newStartSessionMocks(t)
		datamocks.ExpectRunInTransactionThenFail(m.db, txSentinel, dbErr)
		m.db.On("CreateUserSession", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()
		m.db.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()
		m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return(sweep, nil).Once()
		m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(41)).Return(nil).Once()
		m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()

		result, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
			authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, thisBrowser(), "192.168.1.50", nil, SessionLimits{})

		require.ErrorIs(t, err, dbErr)
		assert.Nil(t, result)
		assert.Empty(t, removed)
	})
}

// -----------------------------------------------------------------------------
// Failure paths
//
// Every step can fail, and none of them may return a session alongside an error.
// -----------------------------------------------------------------------------

func TestStartNewUserSession_ErrorsPropagate(t *testing.T) {
	dbErr := errors.New("database is down")

	testCases := []struct {
		name string
		// setup registers the case's expectations and returns whatever this case asserts
		// beyond "an error, and no session alongside it", or nil when the strict mocks are
		// the whole of it. A mock built with NewDatabase(t) fails the test on any call the
		// setup did not register, so what a case leaves out it is asserting did not happen.
		setup func(m *startSessionMocks) func(t *testing.T)
	}{
		{
			name: "the transaction cannot be opened",
			setup: func(m *startSessionMocks) func(*testing.T) {
				datamocks.ExpectRunInTransactionRefused(m.db, dbErr)
				return nil
			},
		},
		{
			name: "CreateUserSession fails",
			setup: func(m *startSessionMocks) func(*testing.T) {
				datamocks.ExpectRunInTransaction(m.db, txSentinel)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Return(dbErr).Once()
				return nil
			},
		},
		{
			name: "CreateUserSessionClient fails",
			setup: func(m *startSessionMocks) func(*testing.T) {
				datamocks.ExpectRunInTransaction(m.db, txSentinel)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(dbErr).Once()
				return nil
			},
		},
		{
			name: "the commit fails",
			setup: func(m *startSessionMocks) func(*testing.T) {
				datamocks.ExpectRunInTransactionThenFail(m.db, txSentinel, dbErr)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return(nil, nil).Once()
				return nil
			},
		},
		{
			// #198's first window. The read is inside the transaction now, so its failure is
			// handed to RunInTransaction, which rolls the row back; before the fix it ran
			// after the commit and the row stayed. BodyErr is how the rollback is observed,
			// the helper rolling back exactly when the body errs.
			name: "the sibling read fails inside the transaction",
			setup: func(m *startSessionMocks) func(*testing.T) {
				stub := datamocks.ExpectRunInTransaction(m.db, txSentinel)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return(nil, dbErr).Once()
				return func(t *testing.T) {
					assert.ErrorIs(t, stub.BodyErr, dbErr,
						"the body must hand its error to RunInTransaction, which is what rolls the row back")
				}
			},
		},
		{
			// #198's second window, and the same argument one call further in: the sweep is
			// in the transaction, so a delete that fails takes the new row down with it and
			// undoes the siblings it had already deleted.
			name: "a sibling delete fails inside the transaction",
			setup: func(m *startSessionMocks) func(*testing.T) {
				stub := datamocks.ExpectRunInTransaction(m.db, txSentinel)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return([]record.UserSession{{
					Id:                42,
					SessionIdentifier: "an-older-session",
					IpAddress:         "192.168.1.50",
					// The request's device, so the sweep still reaches the delete that fails here.
					DeviceId: thisDeviceId,
				}}, nil).Once()
				m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(dbErr).Once()
				return func(t *testing.T) {
					assert.ErrorIs(t, stub.BodyErr, dbErr,
						"the body must hand its error to RunInTransaction, which is what rolls the row back")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := newStartSessionMocks(t)
			alsoAssert := tc.setup(m)

			result, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
				authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, thisBrowser(), "192.168.1.50", nil, SessionLimits{})

			require.Error(t, err)
			assert.Nil(t, result, "no session may be returned alongside an error")
			assert.Empty(t, removed, "no case here swept a row that committed")
			if alsoAssert != nil {
				alsoAssert(t)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// #198: AbandonUserSession, the compensation for a binding that failed after the commit
//
// The binding of the new session to the browser session cannot join the start's transaction --
// RunInTransaction reruns its body on a deadlock and a rerun would write Set-Cookie twice -- so
// /auth/completed's create arm deletes the committed row through AbandonUserSession when it fails.
// -----------------------------------------------------------------------------

// The row the start committed is deleted rather than left for nobody, and the caller is told why the
// ceremony failed, not what the cleanup did. The delete carries a nil transaction, which is what
// says it is outside the committed one rather than part of it.
func TestAbandonUserSession_DeletesTheRowAndReturnsTheCause(t *testing.T) {
	m := newStartSessionMocks(t)
	cause := errors.New("unable to rotate the browser session identifier")
	m.db.On("DeleteUserSession", mock.Anything, (*sql.Tx)(nil), int64(99)).Return(nil).Once()

	err := m.manager.AbandonUserSession(context.Background(), &record.UserSession{Id: 99}, cause)

	require.ErrorIs(t, err, cause, "the caller must be told why the ceremony failed, not what the cleanup did")
	assert.Equal(t, cause.Error(), err.Error(), "a cleanup that succeeded adds nothing to the error")
	m.db.AssertExpectations(t)
}

// The compensation runs on a context of its own, because the cancellation that would stop it is
// the same event that causes the failure it is compensating for (#386, final review round 1
// finding 9).
//
// net/http cancels a request's context the moment the client disconnects, and a disconnected
// client is exactly why a browser-store write fails. So the two arrive together: the rotation
// reports a failure, and the DeleteUserSession that undoes the committed row is handed a context
// that is already done. Before this, that left #198's orphan behind in precisely the case the
// compensation was written for. The delete keeps the request's values, the request id among them.
func TestAbandonUserSession_DeletesTheRowEvenWhenTheRequestWasCancelled(t *testing.T) {
	m := newStartSessionMocks(t)
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), requestValueKey{}, "this request"))
	cancel()
	m.db.On("DeleteUserSession", aLiveSessionContext(), (*sql.Tx)(nil), int64(99)).
		Run(func(args mock.Arguments) {
			assert.Equal(t, "this request", args.Get(0).(context.Context).Value(requestValueKey{}),
				"the delete runs on the request's values")
		}).Return(nil).Once()

	err := m.manager.AbandonUserSession(ctx, &record.UserSession{Id: 99}, errCreateRefused)

	require.ErrorIs(t, err, errCreateRefused, "the caller is still told why the ceremony failed")
	require.Error(t, ctx.Err(), "the request really was cancelled before the compensation ran")
	m.db.AssertExpectations(t)
}

// requestValueKey carries a value the request's context has and a fresh one would not.
type requestValueKey struct{}

// errCreateRefused stands in for the browser session store refusing the rotation's write.
var errCreateRefused = errors.New("the backend refused the write")

// aLiveSessionContext matches only a context that is not done, so a compensation issued on the
// cancelled request's context matches nothing and the strict mock reports it.
func aLiveSessionContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool { return ctx.Err() == nil })
}

// The compensation is best effort and can itself fail, which is the one thing it cannot make
// impossible. When it does, the original error is still what errors.Is finds -- the caller answers
// for the reason the ceremony failed -- and the cleanup failure rides alongside it rather than being
// dropped, so the record says the row survived.
func TestAbandonUserSession_AFailedCompensationKeepsTheOriginalError(t *testing.T) {
	m := newStartSessionMocks(t)
	deleteErr := errors.New("database is down")
	m.db.On("DeleteUserSession", mock.Anything, (*sql.Tx)(nil), int64(99)).Return(deleteErr).Once()

	err := m.manager.AbandonUserSession(context.Background(), &record.UserSession{Id: 99}, errCreateRefused)

	require.ErrorIs(t, err, errCreateRefused, "the original failure must survive a failed cleanup")
	require.ErrorIs(t, err, deleteErr, "the cleanup failure must not be dropped")
	assert.Contains(t, err.Error(), "unable to delete the user session left behind by a failed browser session write")
}

// =============================================================================
// Tests for NewManager
// =============================================================================

func TestNewManager_StoresItsDependencies(t *testing.T) {
	m := newStartSessionMocks(t)

	manager := NewManager(m.db)

	assert.NotNil(t, manager)
	assert.Same(t, m.db, manager.database)

	// The constructor's clock is the wall clock in UTC.
	require.NotNil(t, manager.now)
	before := time.Now().UTC()
	got := manager.now()
	assert.Equal(t, time.UTC, got.Location())
	assert.False(t, got.Before(before))
}

// TestStartNewUserSession_StampsAuthStateGeneration is the session row of #106's
// persisted-state stamping table (finding 28). It asserts the generation written onto the
// model handed to CreateUserSession.
//
// The value comes from the AuthContext, which captured it when the ceremony authenticated,
// and NOT from the user's current value. A ceremony that began before a credential change
// must therefore produce a session on the superseded generation, which is then rejected,
// rather than one silently carried past the boundary that change established.
//
// 7 is deliberately nonzero: written with 0 this test would coincide with the column
// default and pass even if the assignment were missing entirely.
func TestStartNewUserSession_StampsAuthStateGeneration(t *testing.T) {
	m := newStartSessionMocks(t)
	captured := m.expectPersistThroughCommit(123, nil)

	_, _, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 7, nil, thisBrowser(), "192.168.1.50", nil, SessionLimits{})

	require.NoError(t, err)
	if assert.NotNil(t, *captured, "CreateUserSession was never called") {
		assert.EqualValues(t, 7, (*captured).AuthStateGeneration,
			"the session must carry the generation the ceremony authenticated under")
	}
}

// A brand new session carries the OTP configuration generation the ceremony observed when it
// answered the level 2 question, not the user's current value and not zero. Promoting it here
// rather than later is what stops the session owing a re-prompt on the very next request
// (#242 decision 3).
//
// 9 rather than a small number, and different from the auth state generation above, so the
// two parameters cannot be confused with each other or with a zero default.
func TestStartNewUserSession_StampsOtpConfigGeneration(t *testing.T) {
	m := newStartSessionMocks(t)
	captured := m.expectPersistThroughCommit(123, nil)

	observed := int64(9)
	_, _, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 7, &observed, thisBrowser(), "192.168.1.50", nil, SessionLimits{})

	require.NoError(t, err)
	if assert.NotNil(t, *captured, "CreateUserSession was never called") {
		assert.EqualValues(t, 9, (*captured).OtpConfigGeneration,
			"the session must carry the OTP configuration generation the ceremony answered against")
		assert.EqualValues(t, 7, (*captured).AuthStateGeneration,
			"the two generations must not be crossed")
	}
}

// A nil capture is what a ceremony written by an older binary produces, and it lands at 0.
// That is deliberately the fail-closed direction: a user whose counter has already moved above
// 0 owes a level 2 re-prompt on this brand new session, which costs one prompt, where the
// alternative of reading the counter live here would silently satisfy an obligation the
// ceremony never addressed.
func TestStartNewUserSession_NilOtpConfigGenerationLandsAtZero(t *testing.T) {
	m := newStartSessionMocks(t)
	captured := m.expectPersistThroughCommit(123, nil)

	_, _, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 7, nil, thisBrowser(), "192.168.1.50", nil, SessionLimits{})

	require.NoError(t, err)
	if assert.NotNil(t, *captured, "CreateUserSession was never called") {
		assert.EqualValues(t, 0, (*captured).OtpConfigGeneration)
	}
}

// -----------------------------------------------------------------------------
// AuthTime: the credential's instant, not this function's clock (#252 decision 8)
// -----------------------------------------------------------------------------

// AuthTime is the auth_time claim, and OIDC Core 3.1.2.1 makes it max_age's reference point:
// "the allowable elapsed time in seconds since the last time the End-User was actively
// authenticated by the OP". The credential is accepted at /auth/pwd or /auth/otp and the
// session is created two hops later at /auth/completed, with the browser driving the gap, so
// the two instants are the same only when nobody pauses.
//
// 90 minutes is well past any max_age a relying party would send and far outside the window a
// clock read inside the call could land in, so the assertion cannot pass by coincidence.
// Started and LastAccessed must stay on now: they measure the session's own life, and pulling
// them back would shorten it against the idle timeout and the max lifetime.
func TestStartNewUserSession_AuthTimeIsTheCapturedCredentialInstant(t *testing.T) {
	m := newStartSessionMocks(t)
	captured := m.expectPersistThroughCommit(123, nil)

	credentialAcceptedAt := time.Now().UTC().Add(-90 * time.Minute)

	before := time.Now().UTC()
	result, _, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, &credentialAcceptedAt), 7, nil, thisBrowser(), "192.168.1.50", nil, SessionLimits{})
	after := time.Now().UTC()

	require.NoError(t, err)
	if assert.NotNil(t, *captured, "CreateUserSession was never called") {
		assert.True(t, (*captured).AuthTime.Equal(credentialAcceptedAt),
			"the persisted AuthTime must be the captured credential instant, got %v want %v",
			(*captured).AuthTime, credentialAcceptedAt)
	}
	assert.True(t, result.AuthTime.Equal(credentialAcceptedAt),
		"the returned session must carry it too: /auth/completed reads AuthTime back off this "+
			"row and puts it on the AuthContext, which is what the code and then the token sign")

	assert.False(t, result.Started.Before(before), "Started must stay on now")
	assert.False(t, result.Started.After(after), "Started must stay on now")
	assert.Equal(t, result.Started, result.LastAccessed)
	assert.True(t, result.AuthTime.Before(result.Started),
		"a paused ceremony produces an AuthTime older than the session it creates")
}

// A non-UTC capture is normalised rather than stored as it arrives. Nothing in the ceremony
// produces one today (both credential handlers capture time.Now().UTC()), but the column is
// read back and compared against UTC values by every session view, and a location riding along
// on the model is the kind of thing that survives until a formatter prints the wrong hour.
func TestStartNewUserSession_AuthTimeIsNormalisedToUTC(t *testing.T) {
	m := newStartSessionMocks(t)
	captured := m.expectPersistThroughCommit(123, nil)

	zone := time.FixedZone("UTC+7", 7*60*60)
	credentialAcceptedAt := time.Now().In(zone).Add(-30 * time.Minute)

	_, _, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, &credentialAcceptedAt), 7, nil, thisBrowser(), "192.168.1.50", nil, SessionLimits{})

	require.NoError(t, err)
	if assert.NotNil(t, *captured, "CreateUserSession was never called") {
		assert.Equal(t, time.UTC, (*captured).AuthTime.Location(),
			"AuthTime must be stored in UTC, like Started and LastAccessed")
		assert.True(t, (*captured).AuthTime.Equal(credentialAcceptedAt),
			"normalising the location must not move the instant")
	}
}

// Nil and zero both mean "this call captured no credential instant", and there is nothing true
// to write into AuthTime, so the call is refused before anything is touched: no transaction and no
// row. Falling back to now here would recreate the exact defect #252 decision 8
// removed, one broken caller away -- a session claiming the user authenticated at the moment
// the redirect landed, whoever was holding the browser. The one production caller cannot reach
// this branch: /auth/completed refuses to mint a session without Level1AuthCompleted, and the
// password handler that sets it sets AuthenticatedAt beside it. The refusal is what turns that
// invariant from an argument in a comment into a check that fails closed.
func TestStartNewUserSession_RefusesAMissingCredentialInstant(t *testing.T) {
	var zeroTime time.Time
	for name, capture := range map[string]*time.Time{
		"nil":  nil,
		"zero": &zeroTime,
	} {
		t.Run(name, func(t *testing.T) {
			m := newStartSessionMocks(t)

			result, _, err := m.manager.StartNewUserSession(context.Background(), 7,
				authenticationOf(123, "pwd", record.AcrLevel1, capture), 7, nil, thisBrowser(), "192.168.1.50", nil, SessionLimits{})

			require.ErrorContains(t, err, "no credential instant captured")
			assert.Nil(t, result, "a refused call must hand back no session")

			// Nothing may have been written on either side of the refusal: the argument
			// counts below match each method's arity, because AssertNotCalled compares the
			// whole argument list and a wrong count would match nothing and assert nothing.
			m.db.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
			m.db.AssertNotCalled(t, "CreateUserSession", mock.Anything, mock.Anything, mock.Anything)
			m.db.AssertNotCalled(t, "CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything)
			m.db.AssertNotCalled(t, "GetUserSessionsByUserId", mock.Anything, mock.Anything, mock.Anything)
			m.db.AssertNotCalled(t, "DeleteUserSession", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// authenticationOf is a sign-in by userId with a password and nothing after it, so the credential
// instant is the password's too.
func authenticationOf(userId int64, methods string, acr record.AcrLevel, at *time.Time) Authentication {
	return Authentication{UserId: userId, AuthMethods: methods, AcrLevel: acr, AuthTime: at, PasswordAuthTime: at}
}
