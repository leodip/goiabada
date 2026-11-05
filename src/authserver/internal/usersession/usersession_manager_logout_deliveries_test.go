package usersession

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/backchannel"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// The logout tokens a sign-in's removals send (#784 decision 1): a removed session still within its
// idle timeout and maximum lifetime, whatever removed it, names each of its apps with a back-channel
// logout URI, read under its row before its deletion; an expired one names nobody and reads nothing.

// deliveryMocks is a strict database whose user is 123 with subject "subject-123", and the manager
// over it. Unlike newStartSessionMocks it stubs none of the reads the deliveries make, so each case
// says which it expects.
func deliveryMocks(t *testing.T) *startSessionMocks {
	t.Helper()
	db := datamocks.NewDatabase(t)
	db.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).
		Return(&record.User{Id: 123, Subject: "subject-123"}, nil).Once()
	return &startSessionMocks{db: db, manager: &Manager{database: db}}
}

// appsOn expects the session's row taken and its apps read: one with a back-channel logout URI and
// one without.
func (m *startSessionMocks) appsOn(session record.UserSession, held bool) {
	m.db.On("AcquireUserSessionRow", mock.Anything, txSentinel, session.SessionIdentifier).Return(held, nil).Once()
	if !held {
		return
	}
	clients := []record.UserSessionClient{
		{Id: 1, UserSessionId: session.Id, ClientId: 51},
		{Id: 2, UserSessionId: session.Id, ClientId: 52},
	}
	m.db.On("GetUserSessionClientsByUserSessionId", mock.Anything, txSentinel, session.Id).Return(clients, nil).Once()
	m.db.On("UserSessionClientsLoadClients", mock.Anything, txSentinel, clients).Run(func(args mock.Arguments) {
		loaded := args.Get(2).([]record.UserSessionClient)
		loaded[0].Client = record.Client{Id: 51, ClientIdentifier: "told-app", BackchannelLogoutURI: "https://told.example/bcl"}
		loaded[1].Client = record.Client{Id: 52, ClientIdentifier: "untold-app"}
	}).Return(nil).Once()
}

// toldApp is the one delivery a removed live session sends.
func toldApp(session record.UserSession) []backchannel.Delivery {
	return []backchannel.Delivery{{
		ClientId:          51,
		ClientIdentifier:  "told-app",
		URI:               "https://told.example/bcl",
		UserId:            123,
		Subject:           "subject-123",
		SessionIdentifier: session.SessionIdentifier,
	}}
}

func TestStartNewUserSession_ALiveRemovedSessionTellsItsApps(t *testing.T) {
	limits := capLimits(2)
	live := func(id int64, deviceId string) record.UserSession {
		session := otherBrowser(id, 2*time.Hour, 10*time.Minute)
		session.DeviceId = deviceId
		return session
	}

	cases := []struct {
		name      string
		existing  []record.UserSession
		replacing func(existing []record.UserSession) *record.UserSession
		reason    string
	}{
		{
			name:     "the same device's",
			existing: []record.UserSession{live(42, thisDeviceId)},
			reason:   "same_device",
		},
		{
			name:     "over the cap",
			existing: []record.UserSession{live(42, otherDeviceId), live(43, otherDeviceId)},
			reason:   "session_cap",
		},
		{
			name:      "replaced by the sign-in, still valid by the settings",
			existing:  []record.UserSession{live(42, otherDeviceId)},
			replacing: func(existing []record.UserSession) *record.UserSession { return &existing[0] },
			reason:    "replaced_by_sign_in",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := deliveryMocks(t)
			m.expectPersistThroughCommit(123, tc.existing)
			// The cap removes the least recently used of the two; both were used ten minutes ago,
			// so the lower id.
			removedSession := tc.existing[0]
			m.appsOn(removedSession, true)
			m.db.On("DeleteUserSession", mock.Anything, txSentinel, removedSession.Id).Return(nil).Once()
			var replacing *record.UserSession
			if tc.replacing != nil {
				replacing = tc.replacing(tc.existing)
			}

			_, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
				authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, thisBrowser(),
				"192.168.1.50", replacing, limits)

			require.NoError(t, err)
			require.Len(t, removed, 1)
			assert.Equal(t, tc.reason, removed[0].Reason)
			assert.Equal(t, toldApp(removedSession), removed[0].LogoutDeliveries)
		})
	}
}

// An expired session tells nobody, whatever removed it, and its row and apps are never read: the
// strict mock refuses the reads.
func TestStartNewUserSession_AnExpiredRemovedSessionTellsNobody(t *testing.T) {
	limits := capLimits(2)
	idle := otherBrowser(42, 3*time.Hour, 2*time.Hour)
	idle.DeviceId = thisDeviceId
	pastLifetime := otherBrowser(43, 25*time.Hour, time.Minute)
	keptValid := otherBrowser(44, time.Hour, 5*time.Minute)

	m := deliveryMocks(t)
	m.expectPersistThroughCommit(123, []record.UserSession{idle, pastLifetime, keptValid})
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(43)).Return(nil).Once()

	_, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, thisBrowser(),
		"192.168.1.50", nil, limits)

	require.NoError(t, err)
	assert.Equal(t, map[int64]string{42: "same_device", 43: "session_cap"}, removedReasons(removed))
	for _, removal := range removed {
		assert.Nil(t, removal.LogoutDeliveries, "session %d", removal.Session.Id)
	}
}

// A live session whose row is already gone, ended by someone else meanwhile, names no app: that end
// tells them.
func TestStartNewUserSession_ARemovedSessionAlreadyGoneTellsNobody(t *testing.T) {
	gone := otherBrowser(42, time.Hour, time.Minute)
	gone.DeviceId = thisDeviceId

	m := deliveryMocks(t)
	m.expectPersistThroughCommit(123, []record.UserSession{gone})
	m.appsOn(gone, false)
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()

	_, removed, err := m.manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, thisBrowser(),
		"192.168.1.50", nil, capLimits(0))

	require.NoError(t, err)
	require.Len(t, removed, 1)
	assert.Nil(t, removed[0].LogoutDeliveries)
}

// A failure to read the user's subject is the sign-in's failure, before any transaction opens.
func TestStartNewUserSession_AFailedSubjectReadCreatesNothing(t *testing.T) {
	db := datamocks.NewDatabase(t)
	dbErr := errors.New("users unreadable")
	db.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(nil, dbErr).Once()
	manager := &Manager{database: db}

	session, removed, err := manager.StartNewUserSession(context.Background(), 7,
		authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, thisBrowser(),
		"192.168.1.50", nil, capLimits(0))

	require.ErrorIs(t, err, dbErr)
	assert.Nil(t, session)
	assert.Nil(t, removed)
}
