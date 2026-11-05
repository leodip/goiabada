package revocation

import (
	"context"
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
		{Id: 1, UserSessionId: terminateSessionId, ClientId: 11},
		{Id: 2, UserSessionId: terminateSessionId, ClientId: 12},
		{Id: 3, UserSessionId: terminateSessionId, ClientId: 13},
	}
	db.On("GetUserSessionClientsByUserSessionId", mock.Anything, revokeTx, terminateSessionId).
		Return(sessionClients, nil).Once()
	db.On("UserSessionClientsLoadClients", mock.Anything, revokeTx, sessionClients).
		Run(func(args mock.Arguments) {
			loaded := args.Get(2).([]record.UserSessionClient)
			loaded[0].Client = record.Client{Id: 11, ClientIdentifier: "web", BackchannelLogoutURI: "https://web.example/bc"}
			loaded[1].Client = record.Client{Id: 12, ClientIdentifier: "no-uri"}
			loaded[2].Client = record.Client{Id: 13, ClientIdentifier: "dcr_spa", IsPublic: true, CreatedViaDCR: true,
				BackchannelLogoutURI: "https://spa.example/bc?x=1"}
		}).Return(nil).Once()
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
	read := callIndex(t, db, "GetUserSessionClientsByUserSessionId")
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
	db.AssertNotCalled(t, "GetUserSessionClientsByUserSessionId", mock.Anything, mock.Anything, mock.Anything)
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
	db.AssertNotCalled(t, "GetUserSessionClientsByUserSessionId", mock.Anything, mock.Anything, mock.Anything)
}
