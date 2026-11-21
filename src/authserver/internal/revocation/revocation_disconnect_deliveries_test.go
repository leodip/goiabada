package revocation

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/backchannel"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A disconnect tells the client (#135 decision 3): a client with a back-channel logout URI is sent
// one token naming the user alone, and one that requires sid a sub+sid token for each still-valid
// session of the user it is on. The tokens are collected on the disconnect's own transaction and
// handed to the caller, who sends them after the commit.

// The user's sub every token of these tests names.
const disconnectSubject = "subject-of-31"

// The user's sessions in these tests, by id: the client is on the two valid ones and the expired
// one; another client is on the third valid one.
const (
	disconnectLiveSid       = "sid-live"
	disconnectSecondLiveSid = "sid-second-live"
	disconnectExpiredSid    = "sid-expired"
	disconnectElsewhereSid  = "sid-elsewhere"
)

// disconnectLive judges every session valid but the expired one.
func disconnectLive(session *record.UserSession) bool {
	return session.SessionIdentifier != disconnectExpiredSid
}

// tellableClient is the disconnected client with a back-channel logout URI, requiring sid or not,
// public and self-registered so a delivery that drops either field is caught.
func tellableClient(sidRequired bool) record.Client {
	return record.Client{ID: disconnectClientID, ClientIdentifier: "dcr_disconnected", IsPublic: true, CreatedViaDCR: true,
		BackchannelLogoutURI: "https://app.example/bc?x=1", BackchannelLogoutSessionRequired: sidRequired}
}

// expectTellableClient registers the disconnect's reads of the client and the user, each on the
// disconnect's transaction.
func expectTellableClient(db *datamocks.Database, client record.Client) {
	db.On("GetClientsByIDs", mock.Anything, revokeTx, []int64{disconnectClientID}).
		Return([]record.Client{client}, nil).Once()
	db.On("GetUserByID", mock.Anything, revokeTx, disconnectUserID).
		Return(&record.User{ID: disconnectUserID, Subject: disconnectSubject}, nil).Once()
}

// expectOneTokenSwept registers a sweep that revokes one live token of one family: a change.
func expectOneTokenSwept(db *datamocks.Database) {
	token := &record.RefreshToken{ID: 7, RefreshTokenJTI: "rt-live", FirstRefreshTokenJTI: "fam-live"}
	db.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
		Return(int64(0), nil).Once()
	db.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
		Return([]*record.RefreshToken{token}, nil).Once()
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-live", ReasonClientDisconnected).
		Return(true, nil).Once()
	db.On("MarkRefreshTokenAsRevoked", mock.Anything, revokeTx, token.ID).Return(true, nil).Once()
}

// disconnectSessions is the user's four sessions, out of id order as the query may answer them.
func disconnectSessions() []record.UserSession {
	return []record.UserSession{
		{ID: 4, UserID: disconnectUserID, SessionIdentifier: disconnectSecondLiveSid},
		{ID: 3, UserID: disconnectUserID, SessionIdentifier: disconnectExpiredSid},
		{ID: 2, UserID: disconnectUserID, SessionIdentifier: disconnectLiveSid},
		{ID: 5, UserID: disconnectUserID, SessionIdentifier: disconnectElsewhereSid},
	}
}

// The token a disconnect sends a client that does not require sid: the user alone, the client as
// it was read, and no session.
func TestDisconnectClientTx_TellsTheClientAboutTheUserAlone(t *testing.T) {
	db := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(db, revokeTx)
	expectTellableClient(db, tellableClient(false))
	expectOneTokenSwept(db)

	result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID, disconnectLive,
		deletesTheConsent)

	require.NoError(t, err)
	assert.Equal(t, []backchannel.Delivery{{
		ClientID: disconnectClientID, ClientIdentifier: "dcr_disconnected", URI: "https://app.example/bc?x=1",
		IsPublic: true, CreatedViaDCR: true, UserID: disconnectUserID, Subject: disconnectSubject,
	}}, result.LogoutDeliveries)
	// One token about every session of the user: the sessions are not read.
	assertNotAttempted(t, db, "GetUserSessionsByUserID", "GetUserSessionClientsByUserSessionIDs")
	// Read before the disconnect's first write, so the reads hold no row against anyone.
	assert.Less(t, callIndex(t, db, "GetUserByID"), callIndex(t, db, "RevokeUnusedCodesByUserIDAndClientID"))
}

// A client that requires sid is sent one token for each of the user's sessions it is on that is
// still valid, in session id order: not the expired one it is on, not the valid one only another
// client is on.
func TestDisconnectClientTx_ASidRequiringClientIsToldOfEachValidSessionItIsOn(t *testing.T) {
	db := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(db, revokeTx)
	expectTellableClient(db, tellableClient(true))
	db.On("GetUserSessionsByUserID", mock.Anything, revokeTx, disconnectUserID).Return(disconnectSessions(), nil).Once()
	// Only the valid sessions' apps are read, the expired session's not.
	db.On("GetUserSessionClientsByUserSessionIDs", mock.Anything, revokeTx, []int64{2, 4, 5}).
		Return([]record.UserSessionClient{
			{UserSessionID: 4, ClientID: disconnectClientID},
			{UserSessionID: 5, ClientID: 999},
			{UserSessionID: 2, ClientID: 999},
			{UserSessionID: 2, ClientID: disconnectClientID},
		}, nil).Once()
	expectOneTokenSwept(db)

	result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID, disconnectLive,
		nil)

	require.NoError(t, err)
	withSession := func(sid string) backchannel.Delivery {
		return backchannel.Delivery{ClientID: disconnectClientID, ClientIdentifier: "dcr_disconnected",
			URI: "https://app.example/bc?x=1", IsPublic: true, CreatedViaDCR: true, UserID: disconnectUserID,
			Subject: disconnectSubject, SessionIdentifier: sid}
	}
	assert.Equal(t, []backchannel.Delivery{withSession(disconnectLiveSid), withSession(disconnectSecondLiveSid)},
		result.LogoutDeliveries)
	assert.Less(t, callIndex(t, db, "GetUserSessionClientsByUserSessionIDs"),
		callIndex(t, db, "RevokeUnusedCodesByUserIDAndClientID"))
}

// A client that requires sid and is on no valid session of the user is told nothing: on none at
// all, or only on one that expired.
func TestDisconnectClientTx_ASidRequiringClientOnNoValidSessionIsToldNothing(t *testing.T) {
	t.Run("on an expired session only", func(t *testing.T) {
		db := datamocks.NewDatabase(t)
		datamocks.ExpectRunInTransaction(db, revokeTx)
		expectTellableClient(db, tellableClient(true))
		db.On("GetUserSessionsByUserID", mock.Anything, revokeTx, disconnectUserID).Return(disconnectSessions(), nil).Once()
		db.On("GetUserSessionClientsByUserSessionIDs", mock.Anything, revokeTx, []int64{2, 4, 5}).
			Return([]record.UserSessionClient{{UserSessionID: 5, ClientID: 999}}, nil).Once()
		expectOneTokenSwept(db)

		result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID, disconnectLive,
			nil)

		require.NoError(t, err)
		assert.True(t, result.Changed())
		assert.Empty(t, result.LogoutDeliveries)
	})

	t.Run("with no session valid", func(t *testing.T) {
		db := datamocks.NewDatabase(t)
		datamocks.ExpectRunInTransaction(db, revokeTx)
		expectTellableClient(db, tellableClient(true))
		db.On("GetUserSessionsByUserID", mock.Anything, revokeTx, disconnectUserID).
			Return([]record.UserSession{{ID: 3, UserID: disconnectUserID, SessionIdentifier: disconnectExpiredSid}}, nil).Once()
		expectOneTokenSwept(db)

		result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID, disconnectLive,
			nil)

		require.NoError(t, err)
		assert.Empty(t, result.LogoutDeliveries)
		assertNotAttempted(t, db, "GetUserSessionClientsByUserSessionIDs")
	})

	t.Run("with no liveness to judge by", func(t *testing.T) {
		db := datamocks.NewDatabase(t)
		datamocks.ExpectRunInTransaction(db, revokeTx)
		expectTellableClient(db, tellableClient(true))
		expectOneTokenSwept(db)

		result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID, nil, nil)

		require.NoError(t, err)
		assert.Empty(t, result.LogoutDeliveries)
		assertNotAttempted(t, db, "GetUserSessionsByUserID", "GetUserSessionClientsByUserSessionIDs")
	})
}

// A client without a back-channel logout URI, or one already deleted, is told nothing, and the
// user is not read for it.
func TestDisconnectClientTx_AClientWithNoLogoutURIIsToldNothing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		clients []record.Client
	}{
		{"no URI", []record.Client{{ID: disconnectClientID, ClientIdentifier: "no-uri", BackchannelLogoutSessionRequired: true}}},
		{"the client gone", []record.Client{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := datamocks.NewDatabase(t)
			datamocks.ExpectRunInTransaction(db, revokeTx)
			db.On("GetClientsByIDs", mock.Anything, revokeTx, []int64{disconnectClientID}).Return(tc.clients, nil).Once()
			expectOneTokenSwept(db)

			result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID,
				disconnectLive, nil)

			require.NoError(t, err)
			assert.True(t, result.Changed())
			assert.Nil(t, result.LogoutDeliveries)
			assertNotAttempted(t, db, "GetUserByID", "GetUserSessionsByUserID")
		})
	}
}

// A user already gone, whose deletion told their apps, is no one to tell the client about.
func TestDisconnectClientTx_AUserAlreadyGoneTellsNobody(t *testing.T) {
	db := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(db, revokeTx)
	db.On("GetClientsByIDs", mock.Anything, revokeTx, []int64{disconnectClientID}).
		Return([]record.Client{tellableClient(false)}, nil).Once()
	db.On("GetUserByID", mock.Anything, revokeTx, disconnectUserID).Return(nil, nil).Once()
	expectOneTokenSwept(db)

	result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID, disconnectLive, nil)

	require.NoError(t, err)
	assert.Nil(t, result.LogoutDeliveries)
}

// A call that changed nothing had nothing to end, and tells nobody, though the client has a URI
// (#135 decision 2): a repeated disconnect sends no second token.
func TestDisconnectClientTx_NothingChangedTellsNobody(t *testing.T) {
	db := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(db, revokeTx)
	expectTellableClient(db, tellableClient(false))
	db.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
		Return(int64(0), nil).Once()
	db.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
		Return([]*record.RefreshToken{}, nil).Once()

	result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID, disconnectLive,
		func(*sql.Tx) (bool, error) { return false, nil })

	require.NoError(t, err)
	assert.False(t, result.Changed())
	assert.Nil(t, result.LogoutDeliveries)
}

// A failed read of what to tell fails the disconnect before any write, with the zero result: a
// disconnect that committed untold would leave the client showing the user as signed in.
func TestDisconnectClientTx_AFailedDeliveryReadFailsTheDisconnect(t *testing.T) {
	boom := errors.New("connection refused")
	for _, tc := range []struct {
		name  string
		setup func(db *datamocks.Database)
	}{
		{"the client read", func(db *datamocks.Database) {
			db.On("GetClientsByIDs", mock.Anything, revokeTx, []int64{disconnectClientID}).Return(nil, boom).Once()
		}},
		{"the user read", func(db *datamocks.Database) {
			db.On("GetClientsByIDs", mock.Anything, revokeTx, []int64{disconnectClientID}).
				Return([]record.Client{tellableClient(true)}, nil).Once()
			db.On("GetUserByID", mock.Anything, revokeTx, disconnectUserID).Return(nil, boom).Once()
		}},
		{"the sessions read", func(db *datamocks.Database) {
			expectTellableClient(db, tellableClient(true))
			db.On("GetUserSessionsByUserID", mock.Anything, revokeTx, disconnectUserID).Return(nil, boom).Once()
		}},
		{"the sessions' apps read", func(db *datamocks.Database) {
			expectTellableClient(db, tellableClient(true))
			db.On("GetUserSessionsByUserID", mock.Anything, revokeTx, disconnectUserID).Return(disconnectSessions(), nil).Once()
			db.On("GetUserSessionClientsByUserSessionIDs", mock.Anything, revokeTx, []int64{2, 4, 5}).Return(nil, boom).Once()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := datamocks.NewDatabase(t)
			datamocks.ExpectRunInTransaction(db, revokeTx)
			tc.setup(db)
			deleted := false

			result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID,
				disconnectLive, func(*sql.Tx) (bool, error) { deleted = true; return true, nil })

			require.ErrorIs(t, err, boom)
			assert.Equal(t, DisconnectResult{}, result)
			assert.False(t, deleted, "nothing is written after the failed read")
			assertNotAttempted(t, db, "RevokeUnusedCodesByUserIDAndClientID", "GetRefreshTokensByUserIDAndClientID")
		})
	}
}
