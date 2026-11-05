package revocation

import (
	"context"
	"slices"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/backchannel"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// expectTerminationWrites registers the three writes every termination makes, with nothing to
// revoke.
func expectTerminationWrites(db *datamocks.Database) {
	db.On("DeleteUserSession", mock.Anything, revokeTx, terminateSessionId).Return(nil).Once()
	db.On("RevokeCodesBySessionIdentifier", mock.Anything, revokeTx, terminateSid).Return(int64(0), nil).Once()
	db.On("GetRefreshTokensBySessionIdentifier", mock.Anything, revokeTx, terminateSid).
		Return([]*record.RefreshToken{}, nil).Once()
}

// TestTerminateUserSessionTx_ALiveSessionNamesTheAppsToTell: ending a session that was still valid
// collects, inside the termination's transaction and under the session's row, a logout token for
// each app on the session that registered a back-channel logout URI, naming the user's subject and
// the session (#784 decisions 1 and 3). An app without a URI is sent nothing.
func TestTerminateUserSessionTx_ALiveSessionNamesTheAppsToTell(t *testing.T) {
	db := datamocks.NewDatabase(t)

	db.On("GetUserById", mock.Anything, mock.Anything, revokeUserId).
		Return(&record.User{Id: revokeUserId, Subject: "subject-of-7"}, nil).Once()
	datamocks.ExpectRunInTransaction(db, revokeTx)
	db.On("AcquireUserSessionRow", mock.Anything, revokeTx, terminateSid).Return(true, nil).Once()
	sessionClients := []record.UserSessionClient{
		{Id: 1, UserSessionId: terminateSessionId, ClientId: 11,
			Client: record.Client{Id: 11, ClientIdentifier: "web", BackchannelLogoutURI: "https://web.example/bc"}},
		{Id: 2, UserSessionId: terminateSessionId, ClientId: 12,
			Client: record.Client{Id: 12, ClientIdentifier: "no-uri"}},
		{Id: 3, UserSessionId: terminateSessionId, ClientId: 13,
			Client: record.Client{Id: 13, ClientIdentifier: "dcr_spa", IsPublic: true, CreatedViaDCR: true,
				BackchannelLogoutURI: "https://spa.example/bc?x=1"}},
	}
	db.On("GetCommittedUserSessionClients", mock.Anything, revokeTx, terminateSessionId).
		Return(sessionClients, nil).Once()
	expectTerminationWrites(db)

	result, err := TerminateUserSessionTx(context.Background(), db, terminatedSession(), true)
	require.NoError(t, err)

	assert.Equal(t, []backchannel.Delivery{
		{ClientId: 11, ClientIdentifier: "web", URI: "https://web.example/bc",
			UserId: revokeUserId, Subject: "subject-of-7", SessionIdentifier: terminateSid},
		{ClientId: 13, ClientIdentifier: "dcr_spa", URI: "https://spa.example/bc?x=1", IsPublic: true, CreatedViaDCR: true,
			UserId: revokeUserId, Subject: "subject-of-7", SessionIdentifier: terminateSid},
	}, result.LogoutDeliveries)

	// Under the session's row, and before its deletion takes the session's apps with it: a ceremony
	// adding an app to the session takes that row first, so it is either counted here or refused.
	acquired := callIndex(t, db, "AcquireUserSessionRow")
	read := callIndex(t, db, "GetCommittedUserSessionClients")
	deleted := callIndex(t, db, "DeleteUserSession")
	assert.Less(t, acquired, read)
	assert.Less(t, read, deleted)
}

// TestTerminateUserSessionTx_ASessionAlreadyGoneTellsNobody: when the session's row is already gone
// once the termination holds its transaction, another end has taken it and told its apps, so this
// one names none.
func TestTerminateUserSessionTx_ASessionAlreadyGoneTellsNobody(t *testing.T) {
	db := datamocks.NewDatabase(t)

	db.On("GetUserById", mock.Anything, mock.Anything, revokeUserId).
		Return(&record.User{Id: revokeUserId, Subject: "subject-of-7"}, nil).Once()
	datamocks.ExpectRunInTransaction(db, revokeTx)
	db.On("AcquireUserSessionRow", mock.Anything, revokeTx, terminateSid).Return(false, nil).Once()
	expectTerminationWrites(db)

	result, err := TerminateUserSessionTx(context.Background(), db, terminatedSession(), true)
	require.NoError(t, err)

	assert.Empty(t, result.LogoutDeliveries)
	db.AssertNotCalled(t, "GetCommittedUserSessionClients", mock.Anything, mock.Anything, mock.Anything)
}

// TestTerminateUserSessionTx_AnExpiredSessionTellsNobody: a session past its idle timeout or
// maximum lifetime sends nothing when it is ended (#784 decision 1), so nothing is read for it.
func TestTerminateUserSessionTx_AnExpiredSessionTellsNobody(t *testing.T) {
	db := datamocks.NewDatabase(t)

	datamocks.ExpectRunInTransaction(db, revokeTx)
	expectTerminationWrites(db)

	result, err := TerminateUserSessionTx(context.Background(), db, terminatedSession(), false)
	require.NoError(t, err)

	assert.Empty(t, result.LogoutDeliveries)
	db.AssertNotCalled(t, "AcquireUserSessionRow", mock.Anything, mock.Anything, mock.Anything)
	db.AssertNotCalled(t, "GetCommittedUserSessionClients", mock.Anything, mock.Anything, mock.Anything)
}

// TestRevokeOnAuthCodeReuse_ALiveSessionNamesTheAppsToTell: a reused code that ends a session still
// valid reads, under the session row its first statement took and before the deletion, a logout
// token for each app on the session with a back-channel logout URI, naming the code's user (#784
// decision 1). An expired session, or no liveness to judge by, names nobody and reads no app.
func TestRevokeOnAuthCodeReuse_ALiveSessionNamesTheAppsToTell(t *testing.T) {
	session := &record.UserSession{Id: 9, UserId: revokeUserId, SessionIdentifier: reuseSid}
	code := &record.Code{Id: 42, SessionIdentifier: reuseSid, UserId: revokeUserId,
		User: record.User{Id: revokeUserId, Subject: "subject-of-7"}}

	expectReuse := func(db *datamocks.Database) {
		token := &record.RefreshToken{Id: 1, RefreshTokenJti: "rt-1"}
		datamocks.ExpectRunInTransaction(db, revokeTx)
		db.On("AcquireUserSessionRow", mock.Anything, revokeTx, reuseSid).Return(true, nil).Once()
		db.On("GetRefreshTokensBySessionIdentifier", mock.Anything, revokeTx, reuseSid).
			Return([]*record.RefreshToken{token}, nil).Once()
		db.On("UpdateRefreshToken", mock.Anything, revokeTx, token).Return(nil).Once()
		db.On("GetUserSessionBySessionIdentifier", mock.Anything, revokeTx, reuseSid).Return(session, nil).Once()
		db.On("DeleteUserSession", mock.Anything, revokeTx, int64(9)).Return(nil).Once()
	}

	t.Run("a live session tells its apps", func(t *testing.T) {
		db := datamocks.NewDatabase(t)
		expectReuse(db)
		sessionClients := []record.UserSessionClient{
			{Id: 1, UserSessionId: 9, ClientId: 11,
				Client: record.Client{Id: 11, ClientIdentifier: "web", BackchannelLogoutURI: "https://web.example/bc"}},
			{Id: 2, UserSessionId: 9, ClientId: 12, Client: record.Client{Id: 12, ClientIdentifier: "no-uri"}},
		}
		db.On("GetCommittedUserSessionClients", mock.Anything, revokeTx, int64(9)).Return(sessionClients, nil).Once()

		var judged *record.UserSession
		result, err := RevokeOnAuthCodeReuseTx(context.Background(), db, code, func(s *record.UserSession) bool {
			judged = s
			return true
		})

		require.NoError(t, err)
		assert.Same(t, session, judged, "the session judged is the one the response ends")
		assert.Equal(t, []backchannel.Delivery{{ClientId: 11, ClientIdentifier: "web", URI: "https://web.example/bc",
			UserId: revokeUserId, Subject: "subject-of-7", SessionIdentifier: reuseSid}}, result.LogoutDeliveries)
		// The apps are read before the deletion takes their rows.
		order := methodOrder(db)
		assert.Less(t, slices.Index(order, "GetCommittedUserSessionClients"), slices.Index(order, "DeleteUserSession"))
	})

	for name, live := range map[string]SessionLive{
		"an expired session tells nobody": func(*record.UserSession) bool { return false },
		"no liveness tells nobody":        nil,
	} {
		t.Run(name, func(t *testing.T) {
			db := datamocks.NewDatabase(t)
			expectReuse(db)

			result, err := RevokeOnAuthCodeReuseTx(context.Background(), db, code, live)

			require.NoError(t, err)
			assert.Nil(t, result.LogoutDeliveries)
		})
	}
}

// The two sessions and the apps of the user-wide and session-specific fixtures below: session 1
// still valid, session 2 not. Liveness is the notice's judgement, so the fixture names it directly.
const (
	liveSessionId    = int64(1)
	liveSessionSid   = "sid-live"
	expiredSessionId = int64(2)
	expiredSid       = "sid-expired"
)

func noticeSessions() []record.UserSession {
	// Out of id order, as the query may answer them: the rows are taken in id order.
	return []record.UserSession{
		{Id: expiredSessionId, UserId: revokeUserId, SessionIdentifier: expiredSid},
		{Id: liveSessionId, UserId: revokeUserId, SessionIdentifier: liveSessionSid},
	}
}

func liveOnly(session *record.UserSession) bool { return session.SessionIdentifier == liveSessionSid }

// The apps: onBoth (21) is on both sessions; onExpired (22) on the expired one; noURI (23) on the live
// one with no back-channel logout URI; sidRequired (24) requires sid and is on both; grantOnly (25)
// holds only a refresh token; grantNoURI (26) holds one and has no URI.
var (
	onBoth      = record.Client{Id: 21, ClientIdentifier: "on-both", BackchannelLogoutURI: "https://both.example/bc"}
	onExpired   = record.Client{Id: 22, ClientIdentifier: "on-expired", BackchannelLogoutURI: "https://expired.example/bc"}
	noURI       = record.Client{Id: 23, ClientIdentifier: "no-uri"}
	sidRequired = record.Client{Id: 24, ClientIdentifier: "sid-required", BackchannelLogoutURI: "https://sid.example/bc",
		BackchannelLogoutSessionRequired: true}
	grantOnly = record.Client{Id: 25, ClientIdentifier: "grant-only", BackchannelLogoutURI: "https://grant.example/bc",
		IsPublic: true, CreatedViaDCR: true}
	grantNoURI = record.Client{Id: 26, ClientIdentifier: "grant-no-uri"}
)

// expectSessionApps registers the row and the apps of one session.
func expectSessionApps(db *datamocks.Database, sid string, sessionId int64, held bool, clients ...record.Client) {
	db.On("AcquireUserSessionRow", mock.Anything, revokeTx, sid).Return(held, nil).Once()
	if !held {
		return
	}
	sessionClients := make([]record.UserSessionClient, len(clients))
	for i, client := range clients {
		sessionClients[i] = record.UserSessionClient{UserSessionId: sessionId, ClientId: client.Id, Client: client}
	}
	db.On("GetCommittedUserSessionClients", mock.Anything, revokeTx, sessionId).Return(sessionClients, nil).Once()
}

// expectSweep registers the generation increment and the sweep of the two sessions with no tokens,
// keeping keptSid's session when it is set.
func expectSweep(db *datamocks.Database, keptSid string) {
	db.On("IncrementUserAuthStateGeneration", mock.Anything, revokeTx, revokeUserId).Return(revokeNewGeneration, nil).Once()
	db.On("GetUserSessionsByUserId", mock.Anything, revokeTx, revokeUserId).Return(noticeSessions(), nil).Once()
	for _, session := range noticeSessions() {
		if session.SessionIdentifier == keptSid {
			db.On("PromoteUserSessionGeneration", mock.Anything, revokeTx, session.Id, revokeNewGeneration).Return(nil).Once()
			continue
		}
		db.On("DeleteUserSession", mock.Anything, revokeTx, session.Id).Return(nil).Once()
	}
	db.On("GetRefreshTokensByUserId", mock.Anything, revokeTx, revokeUserId).Return([]*record.RefreshToken{}, nil).Once()
	if keptSid != "" {
		db.On("GetRefreshTokensBySessionIdentifier", mock.Anything, revokeTx, keptSid).Return([]*record.RefreshToken{}, nil).Once()
	}
	db.On("PromoteRefreshTokenGenerations", mock.Anything, revokeTx, []int64{}, revokeNewGeneration).Return(nil).Once()
}

// subOnly is the sub-only token to client a user-wide end sends.
func subOnly(client record.Client) backchannel.Delivery {
	return backchannel.Delivery{ClientId: client.Id, ClientIdentifier: client.ClientIdentifier,
		URI: client.BackchannelLogoutURI, IsPublic: client.IsPublic, CreatedViaDCR: client.CreatedViaDCR,
		UserId: revokeUserId, Subject: "subject-of-7"}
}

// withSid is the sub+sid token about session sid to client.
func withSid(client record.Client, sid string) backchannel.Delivery {
	delivery := subOnly(client)
	delivery.SessionIdentifier = sid
	return delivery
}

// TestRevokeUserAuthState_AUserWideEndTellsEveryAppThatKnewTheUser: a user-wide end sends one sub-only
// token to each app with a URI that was on any of the user's sessions, valid or not, or holds one of
// the user's usable refresh tokens, and a sub+sid token for each valid session to an app requiring
// sid, which a grant alone tells nothing (#784 decision 3). The apps are read under each session's
// row, in id order, before the session's deletion, and the grants before the token sweep.
func TestRevokeUserAuthState_AUserWideEndTellsEveryAppThatKnewTheUser(t *testing.T) {
	db := datamocks.NewDatabase(t)
	expectSweep(db, "")
	expectSessionApps(db, liveSessionSid, liveSessionId, true, onBoth, noURI, sidRequired)
	expectSessionApps(db, expiredSid, expiredSessionId, true, onBoth, onExpired, sidRequired)
	db.On("GetUsableRefreshTokenClientIdsByUserId", mock.Anything, revokeTx, revokeUserId, mock.Anything).
		Return([]int64{grantOnly.Id, onBoth.Id, sidRequired.Id, grantNoURI.Id}, nil).Once()
	// onBoth was read on a session already; the others are read now.
	db.On("GetClientsByIds", mock.Anything, revokeTx, []int64{grantOnly.Id, sidRequired.Id, grantNoURI.Id}).
		Return([]record.Client{grantOnly, sidRequired, grantNoURI}, nil).Once()

	result, err := RevokeUserAuthState(context.Background(), db, revokeTx, revokeUserId, "",
		LogoutNotice{Subject: "subject-of-7", UserWide: true, Live: liveOnly})
	require.NoError(t, err)

	assert.Equal(t, []backchannel.Delivery{
		withSid(sidRequired, liveSessionSid),
		subOnly(onBoth),
		subOnly(onExpired),
		subOnly(grantOnly),
	}, result.LogoutDeliveries)

	// Each session's row is taken, and its apps read, before any session is deleted; the grants are
	// read before the sweep revokes them.
	firstDelete := callIndex(t, db, "DeleteUserSession")
	for _, call := range db.Calls[firstDelete:] {
		assert.NotEqual(t, "GetCommittedUserSessionClients", call.Method, "a session's apps are read before any deletion")
	}
	assert.Less(t, callIndex(t, db, "GetUsableRefreshTokenClientIdsByUserId"), callIndex(t, db, "GetRefreshTokensByUserId"))
	var acquired []string
	for _, call := range db.Calls {
		if call.Method == "AcquireUserSessionRow" {
			acquired = append(acquired, call.Arguments[2].(string))
		}
	}
	assert.Equal(t, []string{liveSessionSid, expiredSid}, acquired, "the rows are taken in id order")
}

// TestRevokeUserAuthState_AUserWideEndSkipsASessionAlreadyGone: a session whose row is gone when the
// end holds its transaction was ended by someone else, so its apps are not read; an app on it that
// holds a grant is still told through the grant.
func TestRevokeUserAuthState_AUserWideEndSkipsASessionAlreadyGone(t *testing.T) {
	db := datamocks.NewDatabase(t)
	expectSweep(db, "")
	expectSessionApps(db, liveSessionSid, liveSessionId, false)
	expectSessionApps(db, expiredSid, expiredSessionId, true, onExpired)
	db.On("GetUsableRefreshTokenClientIdsByUserId", mock.Anything, revokeTx, revokeUserId, mock.Anything).
		Return([]int64{onExpired.Id}, nil).Once()

	result, err := RevokeUserAuthState(context.Background(), db, revokeTx, revokeUserId, "",
		LogoutNotice{Subject: "subject-of-7", UserWide: true, Live: liveOnly})
	require.NoError(t, err)

	assert.Equal(t, []backchannel.Delivery{subOnly(onExpired)}, result.LogoutDeliveries)
	db.AssertNotCalled(t, "GetCommittedUserSessionClients", mock.Anything, revokeTx, liveSessionId)
	db.AssertNotCalled(t, "GetClientsByIds", mock.Anything, mock.Anything, mock.Anything)
}

// TestRevokeUserAuthState_ASessionSpecificEndTellsTheEndedValidSessionsApps: the user's own password
// change keeps one session and ends the others. Each app on an ended session that was still valid
// gets a sub+sid token for it, whether or not it requires sid; the expired session, the kept session
// and the grants tell nobody, so none of them is read (#784 decisions 1 and 3).
func TestRevokeUserAuthState_ASessionSpecificEndTellsTheEndedValidSessionsApps(t *testing.T) {
	db := datamocks.NewDatabase(t)
	sessions := []record.UserSession{
		{Id: 3, UserId: revokeUserId, SessionIdentifier: revokeKeepSid},
		{Id: liveSessionId, UserId: revokeUserId, SessionIdentifier: liveSessionSid},
		{Id: expiredSessionId, UserId: revokeUserId, SessionIdentifier: expiredSid},
	}
	db.On("IncrementUserAuthStateGeneration", mock.Anything, revokeTx, revokeUserId).Return(revokeNewGeneration, nil).Once()
	db.On("GetUserSessionsByUserId", mock.Anything, revokeTx, revokeUserId).Return(sessions, nil).Once()
	db.On("PromoteUserSessionGeneration", mock.Anything, revokeTx, int64(3), revokeNewGeneration).Return(nil).Once()
	db.On("DeleteUserSession", mock.Anything, revokeTx, liveSessionId).Return(nil).Once()
	db.On("DeleteUserSession", mock.Anything, revokeTx, expiredSessionId).Return(nil).Once()
	db.On("GetRefreshTokensByUserId", mock.Anything, revokeTx, revokeUserId).Return([]*record.RefreshToken{}, nil).Once()
	db.On("GetRefreshTokensBySessionIdentifier", mock.Anything, revokeTx, revokeKeepSid).Return([]*record.RefreshToken{}, nil).Once()
	db.On("PromoteRefreshTokenGenerations", mock.Anything, revokeTx, []int64{}, revokeNewGeneration).Return(nil).Once()
	expectSessionApps(db, liveSessionSid, liveSessionId, true, onBoth, noURI, sidRequired)

	live := func(session *record.UserSession) bool { return session.SessionIdentifier != expiredSid }
	result, err := RevokeUserAuthState(context.Background(), db, revokeTx, revokeUserId, revokeKeepSid,
		LogoutNotice{Subject: "subject-of-7", Live: live})
	require.NoError(t, err)

	assert.Equal(t, []backchannel.Delivery{
		withSid(onBoth, liveSessionSid),
		withSid(sidRequired, liveSessionSid),
	}, result.LogoutDeliveries)
	assert.Less(t, callIndex(t, db, "GetCommittedUserSessionClients"), callIndex(t, db, "DeleteUserSession"))
	db.AssertNotCalled(t, "AcquireUserSessionRow", mock.Anything, revokeTx, revokeKeepSid)
	db.AssertNotCalled(t, "AcquireUserSessionRow", mock.Anything, revokeTx, expiredSid)
	db.AssertNotCalled(t, "GetUsableRefreshTokenClientIdsByUserId", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestRevokeUserAuthState_NoNoticeTellsNobody: without a subject the revocation reads no app at all.
func TestRevokeUserAuthState_NoNoticeTellsNobody(t *testing.T) {
	db := datamocks.NewDatabase(t)
	expectSweep(db, "")

	result, err := RevokeUserAuthState(context.Background(), db, revokeTx, revokeUserId, "",
		LogoutNotice{UserWide: true, Live: liveOnly})
	require.NoError(t, err)

	assert.Empty(t, result.LogoutDeliveries)
	db.AssertNotCalled(t, "AcquireUserSessionRow", mock.Anything, mock.Anything, mock.Anything)
	db.AssertNotCalled(t, "GetUsableRefreshTokenClientIdsByUserId", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestUserWideDeliveries_ReadsTheUsersSessionsAndGrants: the deletion's collection is the user-wide
// shape over the user's sessions as it reads them.
func TestUserWideDeliveries_ReadsTheUsersSessionsAndGrants(t *testing.T) {
	db := datamocks.NewDatabase(t)
	db.On("GetUserSessionsByUserId", mock.Anything, revokeTx, revokeUserId).Return(noticeSessions(), nil).Once()
	expectSessionApps(db, liveSessionSid, liveSessionId, true, sidRequired)
	expectSessionApps(db, expiredSid, expiredSessionId, true, onExpired, sidRequired)
	db.On("GetUsableRefreshTokenClientIdsByUserId", mock.Anything, revokeTx, revokeUserId, mock.Anything).
		Return([]int64{grantOnly.Id}, nil).Once()
	db.On("GetClientsByIds", mock.Anything, revokeTx, []int64{grantOnly.Id}).Return([]record.Client{grantOnly}, nil).Once()

	deliveries, err := UserWideDeliveries(context.Background(), db, revokeTx, revokeUserId, "subject-of-7", liveOnly)
	require.NoError(t, err)

	assert.Equal(t, []backchannel.Delivery{
		withSid(sidRequired, liveSessionSid),
		subOnly(onExpired),
		subOnly(grantOnly),
	}, deliveries)
}
