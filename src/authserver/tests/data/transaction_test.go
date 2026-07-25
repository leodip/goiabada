package datatests

import (
	"database/sql"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Transactions.
//
// Every method on the Database interface takes a leading tx *sql.Tx, but until
// these tests every data test passed nil, so only the autocommit path was ever
// exercised and BeginTransaction, CommitTransaction and RollbackTransaction had
// no coverage at all. Nothing pinned the behaviour the parameter exists for: that
// a rollback discards the writes made through it. A method that accepted its tx
// and then quietly wrote through the pool instead would have passed the whole
// suite, while silently escaping its caller's transaction.
//
// TestTransaction_RollbackDiscards is the test that catches exactly that.

// newTestGroup returns an unsaved group with a unique identifier.
func newTestGroup() *models.Group {
	return &models.Group{
		GroupIdentifier: "TxGroup_" + gofakeit.LetterN(8),
		Description:     "Transaction test group",
	}
}

// beginTx starts a transaction and registers a rollback that tolerates the
// transaction already being finished, so a test can commit or roll back
// explicitly without leaking one on an early t.Fatal.
func beginTx(t *testing.T) *sql.Tx {
	t.Helper()
	tx, err := database.BeginTransaction()
	require.NoError(t, err, "BeginTransaction")
	require.NotNil(t, tx, "BeginTransaction returned a nil transaction")
	t.Cleanup(func() { _ = tx.Rollback() })
	return tx
}

func TestTransaction_CommitPersists(t *testing.T) {
	tx := beginTx(t)
	group := newTestGroup()

	require.NoError(t, database.CreateGroup(tx, group), "CreateGroup in a transaction")
	require.NotZero(t, group.Id, "expected an id to be assigned inside the transaction")
	require.NoError(t, database.CommitTransaction(tx), "CommitTransaction")

	committed, err := database.GetGroupById(nil, group.Id)
	require.NoError(t, err, "GetGroupById after commit")
	require.NotNil(t, committed, "a committed row must be visible outside the transaction")
	assert.Equal(t, group.GroupIdentifier, committed.GroupIdentifier)
}

// The core of the contract: writes made through a transaction are undone when it
// is rolled back. This is what fails if a method ignores its tx argument and
// writes through the connection pool instead, because the pool write would
// survive the rollback.
func TestTransaction_RollbackDiscards(t *testing.T) {
	tx := beginTx(t)
	group := newTestGroup()

	require.NoError(t, database.CreateGroup(tx, group), "CreateGroup in a transaction")
	require.NotZero(t, group.Id, "expected an id to be assigned inside the transaction")
	require.NoError(t, database.RollbackTransaction(tx), "RollbackTransaction")

	rolledBack, err := database.GetGroupById(nil, group.Id)
	require.NoError(t, err, "GetGroupById after rollback")
	assert.Nil(t, rolledBack, "a rolled-back row must not exist")
}

// A read through the transaction sees that transaction's own uncommitted writes.
// Safe on every engine because the read uses the same connection as the write.
func TestTransaction_ReadYourWritesInsideTransaction(t *testing.T) {
	tx := beginTx(t)
	group := newTestGroup()

	require.NoError(t, database.CreateGroup(tx, group), "CreateGroup in a transaction")

	found, err := database.GetGroupById(tx, group.Id)
	require.NoError(t, err, "GetGroupById through the same transaction")
	require.NotNil(t, found, "the transaction must see its own uncommitted write")
	assert.Equal(t, group.GroupIdentifier, found.GroupIdentifier)

	// Also through a query that filters on a column rather than the primary key.
	byIdentifier, err := database.GetGroupByGroupIdentifier(tx, group.GroupIdentifier)
	require.NoError(t, err, "GetGroupByGroupIdentifier through the same transaction")
	assert.NotNil(t, byIdentifier, "the transaction must see its own uncommitted write")

	require.NoError(t, database.RollbackTransaction(tx), "RollbackTransaction")
}

// Isolation: an uncommitted write is not visible to a reader outside the
// transaction. This needs a second connection, which rules out two engines for
// unrelated reasons, so it runs on mysql and postgres only.
func TestTransaction_UncommittedWriteIsNotVisibleOutside(t *testing.T) {
	switch dbType() {
	case "", "sqlite":
		t.Skip("sqlite is limited to one connection (SetMaxOpenConns(1)), so a read outside " +
			"an open transaction would queue behind it and the test would hang rather than fail")
	case "mssql":
		t.Skip("SQL Server's default READ COMMITTED takes shared row locks rather than reading a " +
			"snapshot, so reading the uncommitted row would block until the transaction ended " +
			"instead of returning nothing")
	}

	tx := beginTx(t)
	group := newTestGroup()

	require.NoError(t, database.CreateGroup(tx, group), "CreateGroup in a transaction")
	require.NotZero(t, group.Id, "expected an id to be assigned inside the transaction")

	outside, err := database.GetGroupById(nil, group.Id)
	require.NoError(t, err, "GetGroupById outside the transaction")
	assert.Nil(t, outside, "an uncommitted row must not be visible outside its transaction")

	require.NoError(t, database.RollbackTransaction(tx), "RollbackTransaction")
}

// DeleteUser issues two statements (it clears refresh tokens before deleting the
// user, see deleteRefreshTokensByColumn). When the caller supplies a transaction,
// both must join it, and neither may be committed by the callee: rolling back has
// to restore the user and its tokens together. This is what stops a partial
// delete from surviving a rollback.
func TestTransaction_RollbackUndoesMultiStatementDelete(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)
	refreshToken := createROPCRefreshToken(t, user.Id, client.Id)

	tx := beginTx(t)
	require.NoError(t, database.DeleteUser(tx, user.Id), "DeleteUser in a transaction")

	// Gone as far as this transaction is concerned.
	deletedInTx, err := database.GetUserById(tx, user.Id)
	require.NoError(t, err, "GetUserById through the transaction")
	require.Nil(t, deletedInTx, "the transaction must see its own delete")

	require.NoError(t, database.RollbackTransaction(tx), "RollbackTransaction")

	restoredUser, err := database.GetUserById(nil, user.Id)
	require.NoError(t, err, "GetUserById after rollback")
	assert.NotNil(t, restoredUser, "the user must survive a rolled-back delete")

	restoredToken, err := database.GetRefreshTokenById(nil, refreshToken.Id)
	require.NoError(t, err, "GetRefreshTokenById after rollback")
	assert.NotNil(t, restoredToken,
		"the refresh token deleted by the same call must survive the rollback too")
}

// The mirror of the above: committing the caller's transaction applies both
// statements, so the multi-statement delete is not left half-done.
func TestTransaction_CommitAppliesMultiStatementDelete(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)
	refreshToken := createROPCRefreshToken(t, user.Id, client.Id)

	tx := beginTx(t)
	require.NoError(t, database.DeleteUser(tx, user.Id), "DeleteUser in a transaction")
	require.NoError(t, database.CommitTransaction(tx), "CommitTransaction")

	deletedUser, err := database.GetUserById(nil, user.Id)
	require.NoError(t, err, "GetUserById after commit")
	assert.Nil(t, deletedUser, "the user must be gone after the commit")

	deletedToken, err := database.GetRefreshTokenById(nil, refreshToken.Id)
	require.NoError(t, err, "GetRefreshTokenById after commit")
	assert.Nil(t, deletedToken, "the refresh token must be gone after the commit")
}
