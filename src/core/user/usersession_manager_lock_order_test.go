package user

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

// #139: THE SESSION MANAGER'S TWO WRITERS TAKE THEIR ROWS IN THE BRANCH'S ORDER.
//
// The order is users, then clients, then user_sessions, then the grants. Both functions here
// write a user_session_clients row, which is what puts them under the clients half of it:
// commondb.DeleteClient takes the clients row exclusively and then reads the associations naming
// that client so it can take their session rows, and that read is complete only because every
// inserter takes the same row shared first. A fixed-point loop over re-reads cannot close that
// window, since InnoDB fixes the consistent-read snapshot at a transaction's first plain SELECT.
//
// StartNewUserSession also takes the USERS row, ahead of the client, and that one is easy to
// mistake for surplus because no statement below it names users. CreateUserSession's insert takes
// a shared lock on the parent through user_sessions.user_id without naming it, and a transaction
// holding the shared client lock that then reaches for a row ABOVE clients can be part of a cycle
// even though nothing is upgraded and no two shared holders ever conflict: lock queues are fair,
// so once a deletion's exclusive request is queued behind a shared holder, a later shared request
// queues behind the DELETION. Review reproduced exactly that on MySQL, three parties:
//
//	issuance                holds users, waits for the client behind the queued deletion
//	fresh session creation  holds the client shared, waits for users behind issuance
//	client deletion         queued exclusively on the client, waits for the fresh session
//
// BumpUserSession needs no users acquisition and the ABSENCE is asserted here rather than left to
// be noticed: UserSession.UserId is dont-update, so its full-row UPDATE puts no foreign key in
// the SET list and SQL Server has nothing to re-check (f8ffd56e). A tag removed elsewhere would
// silently give this transaction a users lock below its client lock, which is the inversion above.
//
// The order is only visible on the connection, so a mock recording the sequence is the only place
// it can be pinned. What two real transactions of these shapes do to each other on a real catalog
// is the data tier's, on all four engines.

// sequenceRecorder collects the database calls a transaction makes, in order.
type sequenceRecorder struct{ calls []string }

func (s *sequenceRecorder) note(what string) func(mock.Arguments) {
	return func(mock.Arguments) { s.calls = append(s.calls, what) }
}

func TestStartNewUserSession_TakesItsLocksInOrder(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	store := mocks_sessionstore.NewStore(t)
	manager := &UserSessionManager{database: db, sessionStore: store, sessionName: testSessionName}
	session := sessions.NewSession(store, testSessionName)

	const userId, clientId = int64(123), int64(7)

	var seq sequenceRecorder
	db.On("BeginTransaction").Return(nil, nil).Run(seq.note("begin")).Once()
	db.On("AcquireUserRow", mock.Anything, userId).Return(nil).Run(seq.note("users row")).Once()
	db.On("AcquireClientRowShared", mock.Anything, clientId).Return(nil).
		Run(seq.note("client row, shared")).Once()
	db.On("CreateUserSession", mock.Anything, mock.Anything).Return(nil).
		Run(func(args mock.Arguments) {
			args.Get(1).(*models.UserSession).Id = 99
			seq.calls = append(seq.calls, "session row")
		}).Once()
	db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).
		Run(seq.note("association row")).Once()
	db.On("CommitTransaction", mock.Anything).Return(nil).Run(seq.note("commit")).Once()
	db.On("RollbackTransaction", mock.Anything).Return(nil).Once()
	db.On("GetUserSessionsByUserId", mock.Anything, userId).Return(nil, nil).Once()
	store.On("Get", mock.Anything, testSessionName).Return(session, nil).Once()
	store.On("Save", mock.Anything, mock.Anything, session).Return(nil).Once()

	req := httptest.NewRequest("GET", "/auth/completed", nil)
	req.RemoteAddr = "192.168.1.50:54321"
	_, err := manager.StartNewUserSession(httptest.NewRecorder(), req, userId, clientId,
		"pwd", enums.AcrLevel1.String(), 0, nil)
	require.NoError(t, err)

	assert.Equal(t, []string{
		"begin", "users row", "client row, shared", "session row", "association row", "commit",
	}, seq.calls,
		"users, then clients, then user_sessions, then the association: the users row leads because "+
			"the session insert reaches it through its foreign key without naming it, and a "+
			"transaction that took the shared client lock first and then reached upward is the "+
			"MySQL three-party deadlock this order exists to prevent")

	db.AssertExpectations(t)
}

// TestBumpUserSession_TakesTheClientRowAndNoUserRow. Both halves matter. The acquisition is what
// closes DeleteClient's discovery window against a session joining a client it has already read;
// the absence of a users acquisition is what keeps this transaction out of the order entirely
// rather than in it upside down.
func TestBumpUserSession_TakesTheClientRowAndNoUserRow(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	manager := &UserSessionManager{database: db}

	const clientId = int64(456)
	userSession := &models.UserSession{
		Id:                1,
		SessionIdentifier: "test-session-id",
		UserId:            123,
		AcrLevel:          enums.AcrLevel1.String(),
		AuthMethods:       "pwd",
		IpAddress:         "192.168.1.1",
		LastAccessed:      time.Now().UTC().Add(-time.Hour),
		Clients:           []models.UserSessionClient{},
	}

	var seq sequenceRecorder
	db.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").Return(userSession, nil)
	db.On("UserSessionLoadClients", mock.Anything, userSession).Return(nil)
	db.On("BeginTransaction").Return(nil, nil).Run(seq.note("begin")).Once()
	db.On("AcquireClientRowShared", mock.Anything, clientId).Return(nil).
		Run(seq.note("client row, shared")).Once()
	db.On("UpdateUserSession", mock.Anything, mock.Anything).Return(nil).Run(seq.note("session row")).Once()
	db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).
		Run(seq.note("association row")).Once()
	db.On("CommitTransaction", mock.Anything).Return(nil).Run(seq.note("commit")).Once()
	db.On("RollbackTransaction", mock.Anything).Return(nil).Once()

	req := httptest.NewRequest("GET", "/auth/completed", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	_, err := manager.BumpUserSession(req, "test-session-id", clientId, "pwd", enums.AcrLevel1.String())
	require.NoError(t, err)

	assert.Equal(t, []string{
		"begin", "client row, shared", "session row", "association row", "commit",
	}, seq.calls, "the client row is taken before the session row this transaction writes")

	db.AssertNotCalled(t, "AcquireUserRow", mock.Anything, mock.Anything)

	db.AssertExpectations(t)
}

// TestBumpUserSession_TakesTheClientRowEvenWhenItOnlyUpDATESTheAssociation is the case the
// unconditional acquisition exists for. The insert-versus-update decision is made from
// userSession.Clients, read BEFORE the transaction opened, so a bump that believes it is only
// updating an existing association can still be the one that inserts. Taking the lock only on the
// insert path would therefore leave exactly the schedule the lock is there to exclude.
func TestBumpUserSession_TakesTheClientRowEvenWhenItOnlyUpdatesTheAssociation(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	manager := &UserSessionManager{database: db}

	const clientId = int64(456)
	userSession := &models.UserSession{
		Id:                1,
		SessionIdentifier: "test-session-id",
		UserId:            123,
		AcrLevel:          enums.AcrLevel1.String(),
		AuthMethods:       "pwd",
		IpAddress:         "192.168.1.1",
		LastAccessed:      time.Now().UTC().Add(-time.Hour),
		Clients: []models.UserSessionClient{
			{Id: 11, UserSessionId: 1, ClientId: clientId},
		},
	}

	db.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").Return(userSession, nil)
	db.On("UserSessionLoadClients", mock.Anything, userSession).Return(nil)
	db.On("BeginTransaction").Return(nil, nil).Once()
	db.On("AcquireClientRowShared", mock.Anything, clientId).Return(nil).Once()
	db.On("UpdateUserSession", mock.Anything, mock.Anything).Return(nil).Once()
	db.On("UpdateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
	db.On("CommitTransaction", mock.Anything).Return(nil).Once()
	db.On("RollbackTransaction", mock.Anything).Return(nil).Once()

	req := httptest.NewRequest("GET", "/auth/completed", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	_, err := manager.BumpUserSession(req, "test-session-id", clientId, "pwd", enums.AcrLevel1.String())
	require.NoError(t, err)

	db.AssertExpectations(t)
}

// TestBumpUserSession_AFailedClientAcquisitionStops. A transaction refused the lock it was about
// to depend on has to stop rather than write anyway, which is the same rule the issuance handler
// and DeleteClient follow.
func TestBumpUserSession_AFailedClientAcquisitionStops(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	manager := &UserSessionManager{database: db}

	userSession := &models.UserSession{
		Id:                1,
		SessionIdentifier: "test-session-id",
		UserId:            123,
		AcrLevel:          enums.AcrLevel1.String(),
		AuthMethods:       "pwd",
		IpAddress:         "192.168.1.1",
		LastAccessed:      time.Now().UTC().Add(-time.Hour),
		Clients:           []models.UserSessionClient{},
	}

	boom := errors.New("the engine refused the shared client acquisition")
	db.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").Return(userSession, nil)
	db.On("UserSessionLoadClients", mock.Anything, userSession).Return(nil)
	db.On("BeginTransaction").Return(nil, nil).Once()
	db.On("AcquireClientRowShared", mock.Anything, int64(456)).Return(boom).Once()
	db.On("RollbackTransaction", mock.Anything).Return(nil).Once()

	req := httptest.NewRequest("GET", "/auth/completed", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	result, err := manager.BumpUserSession(req, "test-session-id", 456, "pwd", enums.AcrLevel1.String())

	require.ErrorIs(t, err, boom)
	assert.Nil(t, result, "a bump that could not take its lock returns no session alongside its error")
	db.AssertNotCalled(t, "UpdateUserSession", mock.Anything, mock.Anything)
	db.AssertNotCalled(t, "CreateUserSessionClient", mock.Anything, mock.Anything)
	db.AssertNotCalled(t, "CommitTransaction", mock.Anything)
	db.AssertExpectations(t)
}
