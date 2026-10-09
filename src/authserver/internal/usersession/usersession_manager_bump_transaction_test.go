package usersession

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A bump decides, for the client the ceremony is for, between inserting an association and
// updating the one the session already holds, and the table has one row per session and client
// (migration 000055). Two bumps of one session that overlap can both find the client absent and both
// insert; the engine refuses the second on the key, and the second attempt must then read the row
// the first committed and update it. That holds only if the session and its associations are read
// on the transaction that decides, every attempt, which is what these cases pin at the manager. That
// the engine really refuses, and that the rerun succeeds against it, is the data tier's (#249, #437).

const bumpSessionIdentifier = "bump-session-id"

// bumpedSession is the session as a read returns it, holding the given associations. A fresh value
// per read is what a database returns, and what lets a rerun's read differ from the first's.
func bumpedSession(clients ...record.UserSessionClient) *record.UserSession {
	return &record.UserSession{
		Id:                1,
		SessionIdentifier: bumpSessionIdentifier,
		UserId:            123,
		AcrLevel:          record.AcrLevel1,
		AuthMethods:       "pwd",
		IpAddress:         "192.168.1.1",
		LastAccessed:      time.Now().UTC().Add(-1 * time.Hour),
		Clients:           clients,
	}
}

func lostTheAssociationKey() error {
	return errs.Errorf("%w: another bump inserted the association first", data.ErrUniqueViolation)
}

// The session, its associations and every write are on the one transaction the stub hands the body.
// A read left outside it would decide from a copy no other statement of the attempt sees, which is
// the shape that makes a rerun decide "absent" twice.
func TestBumpUserSession_ReadsAndWritesOnTheTransaction(t *testing.T) {
	database := datamocks.NewDatabase(t)
	manager := &Manager{database: database}

	session := bumpedSession()
	stub := datamocks.ExpectRunInTransaction(database, txSentinel)
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(session, nil).Once()
	database.On("UserSessionLoadClients", mock.Anything, txSentinel, session).Return(nil).Once()
	database.On("UpdateUserSession", mock.Anything, txSentinel, session).Return(nil).Once()
	database.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.MatchedBy(func(c *record.UserSessionClient) bool {
		return c.ClientId == 456 && c.UserSessionId == 1
	})).Return(nil).Once()

	result, err := manager.BumpUserSession(context.Background(), bumpSessionIdentifier, 456, "", "", "")

	require.NoError(t, err)
	require.NoError(t, stub.BodyErr)
	assert.Same(t, session, result)
	database.AssertExpectations(t)
}

// An insert that loses the (session, client) key reruns the whole body once. The rerun reads the
// session again, finds the association the winner committed, and updates it: the insert happened
// once, the update once, and what the caller gets back is the attempt that committed, one
// association and not two.
func TestBumpUserSession_ALostAssociationKeyRunsOnceMoreAndFindsThePair(t *testing.T) {
	database := datamocks.NewDatabase(t)
	manager := &Manager{database: database}

	first := bumpedSession()
	second := bumpedSession(record.UserSessionClient{Id: 9, UserSessionId: 1, ClientId: 456, LastAccessed: time.Now().UTC().Add(-time.Minute)})

	attempt1 := datamocks.ExpectRunInTransaction(database, txSentinel)
	attempt2 := datamocks.ExpectRunInTransaction(database, txSentinel)
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(first, nil).Once()
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(second, nil).Once()
	database.On("UserSessionLoadClients", mock.Anything, txSentinel, first).Return(nil).Once()
	database.On("UserSessionLoadClients", mock.Anything, txSentinel, second).Return(nil).Once()
	database.On("UpdateUserSession", mock.Anything, txSentinel, first).Return(nil).Once()
	database.On("UpdateUserSession", mock.Anything, txSentinel, second).Return(nil).Once()
	database.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(lostTheAssociationKey()).Once()
	database.On("UpdateUserSessionClient", mock.Anything, txSentinel, mock.MatchedBy(func(c *record.UserSessionClient) bool {
		return c.Id == 9 && c.ClientId == 456
	})).Return(nil).Once()

	result, err := manager.BumpUserSession(context.Background(), bumpSessionIdentifier, 456, "", "", "")

	require.NoError(t, err, "a loser on the key is rerun, and the rerun finds the row")
	require.ErrorIs(t, attempt1.BodyErr, data.ErrUniqueViolation, "the first attempt lost the key and rolled back")
	require.NoError(t, attempt2.BodyErr, "the second committed")
	assert.Same(t, second, result, "the session returned is the committed attempt's, not the first attempt's")
	require.Len(t, result.Clients, 1, "one association for the client, never two")
	assert.Equal(t, int64(9), result.Clients[0].Id)
	database.AssertExpectations(t)
	database.AssertNumberOfCalls(t, "CreateUserSessionClient", 1)
}

// The retry is bounded at two attempts: a third collision would mean a writer that keeps creating
// the association this one keeps failing to read, which is a fault and not a race.
func TestBumpUserSession_ASecondLossIsAFaultAndIsNotRetriedAgain(t *testing.T) {
	database := datamocks.NewDatabase(t)
	manager := &Manager{database: database}

	datamocks.ExpectRunInTransaction(database, txSentinel)
	datamocks.ExpectRunInTransaction(database, txSentinel)
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).
		Return(bumpedSession(), nil).Twice()
	database.On("UserSessionLoadClients", mock.Anything, txSentinel, mock.Anything).Return(nil).Twice()
	database.On("UpdateUserSession", mock.Anything, txSentinel, mock.Anything).Return(nil).Twice()
	database.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(lostTheAssociationKey()).Twice()

	result, err := manager.BumpUserSession(context.Background(), bumpSessionIdentifier, 456, "", "", "")

	require.ErrorIs(t, err, data.ErrUniqueViolation)
	assert.Nil(t, result)
	database.AssertExpectations(t)
}

// A failure that is not a lost key is not rerun, and returns no session. Each statement of the body
// failing is one.
func TestBumpUserSession_AFailureOtherThanTheKeyIsNotRetried(t *testing.T) {
	boom := errs.New("connection reset")

	for _, tc := range []struct {
		name string
		arm  func(database *datamocks.Database, session *record.UserSession)
	}{
		{"the session read fails", func(database *datamocks.Database, _ *record.UserSession) {
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(nil, boom).Once()
		}},
		{"the association read fails", func(database *datamocks.Database, session *record.UserSession) {
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(session, nil).Once()
			database.On("UserSessionLoadClients", mock.Anything, txSentinel, session).Return(boom).Once()
		}},
		{"the session write fails", func(database *datamocks.Database, session *record.UserSession) {
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(session, nil).Once()
			database.On("UserSessionLoadClients", mock.Anything, txSentinel, session).Return(nil).Once()
			database.On("UpdateUserSession", mock.Anything, txSentinel, session).Return(boom).Once()
		}},
		{"the association insert fails", func(database *datamocks.Database, session *record.UserSession) {
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(session, nil).Once()
			database.On("UserSessionLoadClients", mock.Anything, txSentinel, session).Return(nil).Once()
			database.On("UpdateUserSession", mock.Anything, txSentinel, session).Return(nil).Once()
			database.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(boom).Once()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			manager := &Manager{database: database}

			stub := datamocks.ExpectRunInTransaction(database, txSentinel)
			tc.arm(database, bumpedSession())

			result, err := manager.BumpUserSession(context.Background(), bumpSessionIdentifier, 456, "", "", "")

			require.ErrorIs(t, err, boom)
			assert.Nil(t, result)
			require.ErrorIs(t, stub.BodyErr, boom, "the transaction rolled back")
			database.AssertExpectations(t)
		})
	}
}

// A commit the engine refuses returns no session either, though the body ran to the end and set
// what it would have returned.
func TestBumpUserSession_ARefusedCommitReturnsNoSession(t *testing.T) {
	database := datamocks.NewDatabase(t)
	manager := &Manager{database: database}

	refused := errs.New("commit refused")
	session := bumpedSession()
	datamocks.ExpectRunInTransactionThenFail(database, txSentinel, refused)
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(session, nil).Once()
	database.On("UserSessionLoadClients", mock.Anything, txSentinel, session).Return(nil).Once()
	database.On("UpdateUserSession", mock.Anything, txSentinel, session).Return(nil).Once()
	database.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()

	result, err := manager.BumpUserSession(context.Background(), bumpSessionIdentifier, 456, "", "", "")

	require.ErrorIs(t, err, refused)
	assert.Nil(t, result)
}

// A deadlock reruns the body too, and the rerun decides from a fresh read: the first attempt found
// the client absent and inserted it, the engine aborted that attempt, and the second finds the
// association another bump committed meanwhile and updates it. A body that reused the first read
// would insert the same pair a second time, which the key would now refuse.
func TestBumpUserSession_ADeadlockRerunDecidesFromAFreshRead(t *testing.T) {
	database := datamocks.NewDatabase(t)
	manager := &Manager{database: database}

	first := bumpedSession()
	second := bumpedSession(record.UserSessionClient{Id: 9, UserSessionId: 1, ClientId: 456})
	stub := datamocks.ExpectRunInTransactionRerun(database, txSentinel)
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(first, nil).Once()
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(second, nil).Once()
	database.On("UserSessionLoadClients", mock.Anything, txSentinel, mock.Anything).Return(nil).Twice()
	database.On("UpdateUserSession", mock.Anything, txSentinel, mock.Anything).Return(nil).Twice()
	database.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()
	database.On("UpdateUserSessionClient", mock.Anything, txSentinel, mock.MatchedBy(func(c *record.UserSessionClient) bool {
		return c.Id == 9
	})).Return(nil).Once()

	result, err := manager.BumpUserSession(context.Background(), bumpSessionIdentifier, 456, "", "", "")

	require.NoError(t, err)
	require.NoError(t, stub.BodyErr)
	assert.Same(t, second, result, "the committed attempt's session")
	database.AssertExpectations(t)
	database.AssertNumberOfCalls(t, "CreateUserSessionClient", 1)
}
