package handlers

import (
	"database/sql"
	"errors"
	"testing"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// methodOrder is the sequence of database methods a call issued, which is the whole subject of
// this file. Every other assertion about these two functions is about WHAT they wrote; a lock
// order is only ever about WHEN, so the order is what has to be pinned, and testify records it
// whether or not the expectations were registered in that order.
func methodOrder(db *mocks_data.Database) []string {
	order := make([]string, 0, len(db.Calls))
	for _, call := range db.Calls {
		order = append(order, call.Method)
	}
	return order
}

// TestRevokeOnAuthCodeReuse_TakesTheSessionRowFirst pins the lock order at the replay path
// (#139 decision 10, site 2).
//
// The rule is that every application transaction writing a user_sessions row and that session's
// grants takes the user_sessions row FIRST. Written the other way round, this transaction takes
// refresh_tokens and then user_sessions while an authorization ceremony takes user_sessions and
// then codes, and the two deadlock on PostgreSQL, MySQL and SQL Server with this transaction
// chosen as the victim, so the reused code's session survives the response meant to contain it.
//
// Order is the only thing a mock can answer here, and it is the thing that matters: what two
// real transactions of these shapes do to each other is the data tier's, in
// TestLockOrder_ReplayResponseAgainstTermination.
func TestRevokeOnAuthCodeReuse_TakesTheSessionRowFirst(t *testing.T) {
	const sid = "sid-reused"

	t.Run("the session row is taken before any grant is read", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		tx := &sql.Tx{}
		token := &models.RefreshToken{Id: 1, RefreshTokenJti: "rt-1"}

		db.On("BeginTransaction").Return(tx, nil).Once()
		db.On("AcquireUserSessionRow", tx, sid).Return(true, nil).Once()
		db.On("GetRefreshTokensBySessionIdentifier", tx, sid).
			Return([]*models.RefreshToken{token}, nil).Once()
		db.On("UpdateRefreshToken", tx, token).Return(nil).Once()
		db.On("GetUserSessionBySessionIdentifier", tx, sid).
			Return(&models.UserSession{Id: 9, SessionIdentifier: sid}, nil).Once()
		db.On("DeleteUserSession", tx, int64(9)).Return(nil).Once()
		db.On("CommitTransaction", tx).Return(nil).Once()
		db.On("RollbackTransaction", tx).Return(nil).Once()

		jtis, err := revokeOnAuthCodeReuse(db, &models.Code{Id: 42, SessionIdentifier: sid})

		require.NoError(t, err)
		assert.Equal(t, []string{"rt-1"}, jtis)
		assert.Equal(t, []string{
			"BeginTransaction",
			"AcquireUserSessionRow",
			"GetRefreshTokensBySessionIdentifier",
			"UpdateRefreshToken",
			"GetUserSessionBySessionIdentifier",
			"DeleteUserSession",
			"CommitTransaction",
			"RollbackTransaction",
		}, methodOrder(db), "the acquisition must be the transaction's first statement")
	})

	t.Run("the acquisition's answer is not a branch", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		tx := &sql.Tx{}
		token := &models.RefreshToken{Id: 1, RefreshTokenJti: "rt-1"}

		db.On("BeginTransaction").Return(tx, nil).Once()
		// The row is already gone, which is ordinary: an offline grant's tokens are designed
		// to outlive their session, and the background reapers remove idle sessions routinely.
		db.On("AcquireUserSessionRow", tx, sid).Return(false, nil).Once()
		db.On("GetRefreshTokensBySessionIdentifier", tx, sid).
			Return([]*models.RefreshToken{token}, nil).Once()
		db.On("UpdateRefreshToken", tx, token).Return(nil).Once()
		db.On("GetUserSessionBySessionIdentifier", tx, sid).Return(nil, nil).Once()
		db.On("CommitTransaction", tx).Return(nil).Once()
		db.On("RollbackTransaction", tx).Return(nil).Once()

		jtis, err := revokeOnAuthCodeReuse(db, &models.Code{Id: 42, SessionIdentifier: sid})

		require.NoError(t, err)
		assert.Equal(t, []string{"rt-1"}, jtis,
			"the replay must still revoke the grant's tokens when the session row has gone")
		assert.True(t, token.Revoked)
	})

	t.Run("an acquisition that errors stops before any grant is read", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		tx := &sql.Tx{}
		boom := errors.New("connection refused")

		db.On("BeginTransaction").Return(tx, nil).Once()
		db.On("AcquireUserSessionRow", tx, sid).Return(false, boom).Once()
		db.On("RollbackTransaction", tx).Return(nil).Once()

		jtis, err := revokeOnAuthCodeReuse(db, &models.Code{Id: 42, SessionIdentifier: sid})

		require.ErrorIs(t, err, boom,
			"a statement that did not run has not established anything, so the caller gets a 500")
		assert.Nil(t, jtis)
		db.AssertNotCalled(t, "GetRefreshTokensBySessionIdentifier", mock.Anything, mock.Anything)
		db.AssertNotCalled(t, "CommitTransaction", mock.Anything)
	})

	t.Run("a code with no session identifier acquires nothing", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		tx := &sql.Tx{}
		token := &models.RefreshToken{Id: 1, RefreshTokenJti: "rt-1"}

		db.On("BeginTransaction").Return(tx, nil).Once()
		db.On("GetRefreshTokensByCodeId", tx, int64(42)).
			Return([]*models.RefreshToken{token}, nil).Once()
		db.On("UpdateRefreshToken", tx, token).Return(nil).Once()
		db.On("CommitTransaction", tx).Return(nil).Once()
		db.On("RollbackTransaction", tx).Return(nil).Once()

		jtis, err := revokeOnAuthCodeReuse(db, &models.Code{Id: 42})

		require.NoError(t, err)
		assert.Equal(t, []string{"rt-1"}, jtis)
		// No row carries an empty session identifier, so the statement would refuse the
		// argument, and the code-id-scoped fallback writes no session row to order against.
		db.AssertNotCalled(t, "AcquireUserSessionRow", mock.Anything, mock.Anything)
	})

	t.Run("#77's guard survives the hoist", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		tx := &sql.Tx{}

		db.On("BeginTransaction").Return(tx, nil).Once()
		db.On("AcquireUserSessionRow", tx, sid).Return(true, nil).Once()
		db.On("GetRefreshTokensBySessionIdentifier", tx, sid).
			Return([]*models.RefreshToken{{Id: 1, RefreshTokenJti: "rt-1", Revoked: true}}, nil).Once()
		db.On("CommitTransaction", tx).Return(nil).Once()
		db.On("RollbackTransaction", tx).Return(nil).Once()

		jtis, err := revokeOnAuthCodeReuse(db, &models.Code{Id: 42, SessionIdentifier: sid})

		require.NoError(t, err)
		assert.Empty(t, jtis)
		// The losing racer of a concurrent redemption finds nothing to revoke and must leave
		// the winner's session row in place. It now HOLDS that row for the rest of the
		// transaction, which is what the acquisition's comment is about, but it still must
		// not delete it.
		db.AssertNotCalled(t, "DeleteUserSession", mock.Anything, mock.Anything)
		db.AssertNotCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything)
	})
}

// TestRevokeUserAuthState_TakesTheSessionRowsBeforeTheTokenSweep pins the lock order at the
// credential sweep (#139 decision 10, site 3).
//
// Same rule and same hazard as the replay path above, and the same division of labour: the order
// is pinned here, and what the reordered transaction does to a real catalog is the data tier's.
//
// IncrementUserAuthStateGeneration stays above the session block and that is asserted too. It
// takes the users row, which sits above user_sessions on every path here, and it is the durable
// half of the operation: the codes carry auth_state_generation, so advancing it is what
// invalidates them.
func TestRevokeUserAuthState_TakesTheSessionRowsBeforeTheTokenSweep(t *testing.T) {
	t.Run("the session block precedes both refresh-token reads", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		token := &models.RefreshToken{Id: 1, RefreshTokenJti: "rt-1"}

		db.On("IncrementUserAuthStateGeneration", revokeTx, revokeUserId).
			Return(revokeNewGeneration, nil).Once()
		db.On("GetUserSessionsByUserId", revokeTx, revokeUserId).Return([]models.UserSession{
			{Id: 10, SessionIdentifier: revokeKeepSid},
			{Id: 20, SessionIdentifier: revokeOtherSid},
		}, nil).Once()
		db.On("PromoteUserSessionGeneration", revokeTx, int64(10), revokeNewGeneration).
			Return(nil).Once()
		db.On("DeleteUserSession", revokeTx, int64(20)).Return(nil).Once()
		db.On("GetRefreshTokensByUserId", revokeTx, revokeUserId).
			Return([]*models.RefreshToken{token}, nil).Once()
		db.On("GetRefreshTokensBySessionIdentifier", revokeTx, revokeKeepSid).
			Return([]*models.RefreshToken{}, nil).Once()
		db.On("UpdateRefreshToken", revokeTx, token).Return(nil).Once()
		db.On("PromoteRefreshTokenGenerations", revokeTx, []int64{}, revokeNewGeneration).
			Return(nil).Once()

		result, err := RevokeUserAuthState(db, revokeTx, revokeUserId, revokeKeepSid)

		require.NoError(t, err)
		assert.Equal(t, []string{revokeOtherSid}, result.TerminatedSessionIdentifiers)
		assert.Equal(t, []string{"rt-1"}, result.RevokedRefreshTokenJtis)
		assert.Equal(t, []string{
			"IncrementUserAuthStateGeneration",
			"GetUserSessionsByUserId",
			"PromoteUserSessionGeneration",
			"DeleteUserSession",
			"GetRefreshTokensByUserId",
			"GetRefreshTokensBySessionIdentifier",
			"UpdateRefreshToken",
			"PromoteRefreshTokenGenerations",
		}, methodOrder(db),
			"the session writes must precede both refresh-token reads, under the increment")
	})

	t.Run("several sessions are taken in ascending id order", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)

		db.On("IncrementUserAuthStateGeneration", revokeTx, revokeUserId).
			Return(revokeNewGeneration, nil).Once()
		// The order the engine chose to return them in. GetUserSessionsByUserId carries no
		// ORDER BY, so this is a shape it really can produce.
		db.On("GetUserSessionsByUserId", revokeTx, revokeUserId).Return([]models.UserSession{
			{Id: 30, SessionIdentifier: "sid-c"},
			{Id: 10, SessionIdentifier: "sid-a"},
			{Id: 20, SessionIdentifier: "sid-b"},
		}, nil).Once()
		db.On("DeleteUserSession", revokeTx, mock.AnythingOfType("int64")).Return(nil).Times(3)
		db.On("GetRefreshTokensByUserId", revokeTx, revokeUserId).
			Return([]*models.RefreshToken{}, nil).Once()
		db.On("PromoteRefreshTokenGenerations", revokeTx, []int64{}, revokeNewGeneration).
			Return(nil).Once()

		result, err := RevokeUserAuthState(db, revokeTx, revokeUserId, "")

		require.NoError(t, err)

		// Two transactions of this shape taking the same two rows in opposite orders is a
		// cycle among sessions that no rule about the order of TABLES can reach, which is why
		// the loop sorts rather than trusting the query (#139).
		var deleted []int64
		for _, call := range db.Calls {
			if call.Method == "DeleteUserSession" {
				deleted = append(deleted, call.Arguments.Get(1).(int64))
			}
		}
		assert.Equal(t, []int64{10, 20, 30}, deleted,
			"the session rows must be taken in a fixed order, whatever order the query returned them in")

		// And the reported list follows the same order, which is what an auditor reads.
		assert.Equal(t, []string{"sid-a", "sid-b", "sid-c"}, result.TerminatedSessionIdentifiers)
	})
}
