package datatests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #242: the two narrow writes behind the OTP configuration generation, exercised
// against the real implementation on all four engines rather than through a mock.
//
// The reason this tier owns them: a mock-backed case shows a method was HANDED a transaction,
// never that it used it. The rollback cases below are the only place that distinction is
// observable, and it is the property decision 2 rests on. If IncrementUserOtpConfigGeneration
// quietly ran outside the caller's transaction, every unit test in the tree would stay green
// while a failed enrollment left the counter advanced and every session of that user carrying
// a re-prompt it does not owe.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>

// TestIncrementUserOtpConfigGeneration covers the counter's whole contract: it moves exactly
// one row by exactly one, it refuses the arguments that could silently do nothing, and it
// enlists in the caller's transaction.
func TestIncrementUserOtpConfigGeneration(t *testing.T) {
	moved := createTestUser(t)
	bystander := createTestUser(t)

	reload := func(id int64) int64 {
		u, err := database.GetUserById(nil, id)
		require.NoError(t, err, "reload user %d", id)
		require.NotNil(t, u, "user %d vanished", id)
		return u.OtpConfigGeneration
	}

	require.EqualValues(t, 0, reload(moved.Id), "a fresh user starts at generation 0")

	// By one, and the returned value is the one that landed. The read-back rather than
	// computing the successor in Go is what makes this true under a concurrent increment, and
	// the browser enrollment promotes exactly this number onto the session it creates.
	tx, err := database.BeginTransaction()
	require.NoError(t, err, "BeginTransaction")
	got, err := database.IncrementUserOtpConfigGeneration(tx, moved.Id)
	require.NoError(t, err, "IncrementUserOtpConfigGeneration")
	require.NoError(t, database.CommitTransaction(tx), "CommitTransaction")

	assert.EqualValues(t, 1, got, "the returned value must be the one that landed")
	assert.EqualValues(t, 1, reload(moved.Id))
	assert.EqualValues(t, 0, reload(bystander.Id),
		"the increment is keyed on one user id and must not reach any other row")

	// Twice more, so "by one" is a property rather than a coincidence of starting at 0.
	for want := int64(2); want <= 3; want++ {
		tx, err := database.BeginTransaction()
		require.NoError(t, err, "BeginTransaction")
		got, err := database.IncrementUserOtpConfigGeneration(tx, moved.Id)
		require.NoError(t, err, "IncrementUserOtpConfigGeneration")
		require.NoError(t, database.CommitTransaction(tx), "CommitTransaction")
		assert.EqualValues(t, want, got)
	}
	assert.EqualValues(t, 3, reload(moved.Id))

	// A nil transaction is refused rather than tolerated. Outside a transaction the increment
	// and its read-back are separable, so a concurrent increment landing between them would
	// have this caller return the other caller's generation and promote it onto a session that
	// never answered for it. IncrementUserAuthStateGeneration refuses nil for the same reason.
	_, err = database.IncrementUserOtpConfigGeneration(nil, moved.Id)
	assert.Error(t, err, "a nil transaction must be refused")
	assert.EqualValues(t, 3, reload(moved.Id), "the refused call must not have moved anything")

	// Id 0 is refused. Nothing has that id, so an unguarded call would match no row, and the
	// rowsAffected check below would report it as "user not found" anyway; refusing it up front
	// names the mistake rather than the symptom.
	tx, err = database.BeginTransaction()
	require.NoError(t, err, "BeginTransaction")
	_, err = database.IncrementUserOtpConfigGeneration(tx, 0)
	assert.Error(t, err, "user id 0 must be refused")
	require.NoError(t, database.RollbackTransaction(tx), "RollbackTransaction")

	// An id that matches no row is an error, not a no-op. The caller is establishing or
	// removing an authenticator and the counter is what tells every session about it; a silent
	// success would commit the authenticator change with nobody informed.
	tx, err = database.BeginTransaction()
	require.NoError(t, err, "BeginTransaction")
	_, err = database.IncrementUserOtpConfigGeneration(tx, bystander.Id+1_000_000)
	assert.Error(t, err, "an unknown user id must be refused")
	require.NoError(t, database.RollbackTransaction(tx), "RollbackTransaction")
}

// TestIncrementUserOtpConfigGeneration_EnlistsInTheCallersTransaction is the case that cannot
// be written at any other tier. Decision 2 of #242 requires the counter to commit with the
// write that changed the authenticator, and "was handed a *sql.Tx" is not the same claim as
// "used it": a method that ignored its argument and ran on the pool would satisfy every mock
// in the tree and break exactly this.
func TestIncrementUserOtpConfigGeneration_EnlistsInTheCallersTransaction(t *testing.T) {
	user := createTestUser(t)

	tx, err := database.BeginTransaction()
	require.NoError(t, err, "BeginTransaction")

	got, err := database.IncrementUserOtpConfigGeneration(tx, user.Id)
	require.NoError(t, err, "IncrementUserOtpConfigGeneration")
	assert.EqualValues(t, 1, got, "inside the transaction the increment is visible to its own read-back")

	require.NoError(t, database.RollbackTransaction(tx), "RollbackTransaction")

	after, err := database.GetUserById(nil, user.Id)
	require.NoError(t, err, "reload user")
	require.NotNil(t, after)
	assert.EqualValues(t, 0, after.OtpConfigGeneration,
		"a rolled back transaction must leave the counter where it was; if this reads 1 the "+
			"increment ran outside the caller's transaction and a failed enrollment would strand it")
}

// TestPromoteUserSessionOtpConfigGeneration covers the snapshot write: it lands on the named
// session only, and refuses the two ids that would otherwise write nothing quietly.
func TestPromoteUserSessionOtpConfigGeneration(t *testing.T) {
	user := createTestUser(t)
	named := createTestUserSession(t, user.Id)
	unnamed := createTestUserSession(t, user.Id)

	reload := func(id int64) int64 {
		us, err := database.GetUserSessionById(nil, id)
		require.NoError(t, err, "reload user session %d", id)
		require.NotNil(t, us, "user session %d vanished", id)
		return us.OtpConfigGeneration
	}

	require.NoError(t, database.PromoteUserSessionOtpConfigGeneration(nil, named.Id, 7),
		"PromoteUserSessionOtpConfigGeneration")

	assert.EqualValues(t, 7, reload(named.Id))
	assert.EqualValues(t, 0, reload(unnamed.Id),
		"the promotion is keyed on one session id: another device of the same user has not "+
			"answered this ceremony's level 2 question and must keep owing its re-prompt")

	assert.Error(t, database.PromoteUserSessionOtpConfigGeneration(nil, 0, 7),
		"user session id 0 must be refused")

	// A promotion that matched nothing is an error rather than a no-op, as for
	// PromoteUserSessionGeneration: the ceremony has just answered the level 2 question, and
	// failing to record that silently leaves the session re-prompted on every later request.
	assert.Error(t, database.PromoteUserSessionOtpConfigGeneration(nil, unnamed.Id+1_000_000, 7),
		"an unknown user session id must be refused")
	assert.EqualValues(t, 0, reload(unnamed.Id), "the refused calls must not have moved anything")
}

// The promote's half of the enlistment property. It is called with a nil transaction in
// production today, from /auth/completed, so this is about the contract rather than a current
// caller: the method takes a *sql.Tx and must honour it, or a future caller batching the
// promotion with another write would find half of it committed.
func TestPromoteUserSessionOtpConfigGeneration_EnlistsInTheCallersTransaction(t *testing.T) {
	user := createTestUser(t)
	session := createTestUserSession(t, user.Id)

	tx, err := database.BeginTransaction()
	require.NoError(t, err, "BeginTransaction")

	require.NoError(t, database.PromoteUserSessionOtpConfigGeneration(tx, session.Id, 7),
		"PromoteUserSessionOtpConfigGeneration")

	require.NoError(t, database.RollbackTransaction(tx), "RollbackTransaction")

	after, err := database.GetUserSessionById(nil, session.Id)
	require.NoError(t, err, "reload user session")
	require.NotNil(t, after)
	assert.EqualValues(t, 0, after.OtpConfigGeneration,
		"a rolled back transaction must leave the snapshot where it was")
}

// TestUpdateUser_DoesNotClobberOtpConfigGeneration is the users-table half of the dont-update
// tag, the sibling of TestUpdateUserSession_DoesNotClobberAuthStateGeneration.
//
// The hazard is direct rather than theoretical: both OTP enable sites load the whole user, set
// OTPEnabled and write it back through UpdateUser inside the same transaction as the increment.
// With the column in the ordinary update set, that write would carry the pre-increment value
// and undo the advance the very statement beside it just made, so every session of the user
// would keep its snapshot matching and no re-prompt would ever be owed (#242).
func TestUpdateUser_DoesNotClobberOtpConfigGeneration(t *testing.T) {
	user := createTestUser(t)

	tx, err := database.BeginTransaction()
	require.NoError(t, err, "BeginTransaction")
	_, err = database.IncrementUserOtpConfigGeneration(tx, user.Id)
	require.NoError(t, err, "IncrementUserOtpConfigGeneration")
	require.NoError(t, database.CommitTransaction(tx), "CommitTransaction")

	stale, err := database.GetUserById(nil, user.Id)
	require.NoError(t, err, "reload user")
	require.NotNil(t, stale)
	require.EqualValues(t, 1, stale.OtpConfigGeneration)

	stale.OtpConfigGeneration = 0
	stale.OTPEnabled = true
	require.NoError(t, database.UpdateUser(nil, stale), "UpdateUser")

	after, err := database.GetUserById(nil, user.Id)
	require.NoError(t, err, "reload user")
	require.NotNil(t, after)
	assert.EqualValues(t, 1, after.OtpConfigGeneration,
		"UpdateUser must not carry otp_config_generation; is the dont-update tag missing?")
	assert.True(t, after.OTPEnabled, "the rest of the update must still apply")
}
