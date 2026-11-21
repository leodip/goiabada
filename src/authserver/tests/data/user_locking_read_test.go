package datatests

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GetUserByIDForUpdate is the locking read of a user that the recovery decides on: it answers the
// user as last committed, even after an earlier read in the same transaction fixed MySQL's
// snapshot, and it takes the row until the transaction ends. Each engine has its own locking
// clause, so each is shown here on the engine it runs on (#498 round 5 F1).

// The read's contract: the user GetUserByID answers, nothing for a user that is not there, and a
// refusal without a transaction, where the row would be released before the caller decides.
func TestGetUserByIDForUpdate(t *testing.T) {
	ctx := context.Background()
	user := createTestUser(t)
	plain, err := database.GetUserByID(ctx, nil, user.ID)
	require.NoError(t, err)

	tx := beginTx(t)
	locked, err := database.GetUserByIDForUpdate(ctx, tx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, plain, locked, "the same user GetUserByID reads")
	// Ended before the cases below open their own: SQLite's pool has one connection.
	require.NoError(t, database.RollbackTransaction(ctx, tx))

	t.Run("a user that is not there is nil", func(t *testing.T) {
		tx := beginTx(t)
		missing, err := database.GetUserByIDForUpdate(ctx, tx, user.ID+1_000_000)
		require.NoError(t, err)
		assert.Nil(t, missing)
	})

	t.Run("without a transaction the statement would autocommit and release the row", func(t *testing.T) {
		_, err := database.GetUserByIDForUpdate(ctx, nil, user.ID)
		require.Error(t, err)
	})
}

// A change committed on another connection after the transaction's first read is what the locking
// read answers. On MySQL the plain read beside it still answers the snapshot that first read fixed,
// which is the reason the locking read exists; the other engines read each statement afresh.
func TestGetUserByIDForUpdate_ReadsWhatCommittedAfterAnEarlierRead(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)
	ctx := context.Background()
	other := secondDatabase(t)
	user := createTestUserOn(t, database)

	tx := beginTx(t)
	_, err := database.GetUserByID(ctx, tx, user.ID)
	require.NoError(t, err)

	changed, err := other.TrySetUserEnabled(ctx, nil, user.ID, user.Enabled, !user.Enabled)
	require.NoError(t, err)
	require.True(t, changed)

	locked, err := database.GetUserByIDForUpdate(ctx, tx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, locked)
	assert.Equal(t, !user.Enabled, locked.Enabled, "the locking read answers the change committed after the first read")

	plain, err := database.GetUserByID(ctx, tx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, plain)
	if dbType() == data.MySQL {
		assert.Equal(t, user.Enabled, plain.Enabled, "on MySQL a plain read answers the snapshot the first read fixed")
	} else {
		assert.Equal(t, !user.Enabled, plain.Enabled, "elsewhere a plain read answers what committed too")
	}
}

// The read holds the row until its transaction ends: a writer of the user's row on another
// connection waits for it, as it waits for AcquireUserRow.
func TestGetUserByIDForUpdate_HoldsTheRowUntilTheTransactionEnds(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)
	ctx := context.Background()
	other := secondDatabase(t)
	user := createTestUserOn(t, database)

	holder := beginTx(t)
	_, err := database.GetUserByIDForUpdate(ctx, holder, user.ID)
	require.NoError(t, err)

	writer := goBlocked(t, "a credential write", holder, func(reached func()) error {
		tx, err := other.BeginTransaction(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = other.RollbackTransaction(ctx, tx) }()
		reached()
		if err := other.SetUserPasswordHash(ctx, tx, user.ID, "hash-written-behind-the-locking-read"); err != nil {
			return err
		}
		return other.CommitTransaction(ctx, tx)
	})
	writer.requireBlocked(t)
	writer.requireStillWaiting(t)

	require.NoError(t, database.CommitTransaction(ctx, holder))
	require.NoError(t, writer.await(t), "the write goes through once the holder commits")
}
