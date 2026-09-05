package datatests

import (
	"database/sql"
	"sort"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #139 DECISION 11: THE USERS ROW IS THE TOP OF THE LOCK ORDER.
//
// Decision 10 ordered user_sessions against the grants hanging off it and said nothing about the
// users row those sessions belong to. That row is reached by two different kinds of statement and
// only one of them names it. A credential operation, a password change, a reset, an administrator
// setting a password, disabling or deleting an account, writes users and then reaches the
// sessions. An authorization ceremony holds the session row and then inserts a code, and
// codes.user_id is a foreign key, so that insert takes a lock on the parent users row WITHOUT
// naming it. Two orders, one cycle.
//
// Reproduced on the branch before this: an authorization ceremony racing a password change
// deadlocks on MySQL and SQL Server with the CREDENTIAL OPERATION chosen as the victim, so the
// password does not change, the session it was ending survives, and the refresh token it was
// revoking stays valid. Whoever holds the session, including whoever stole it, needs no permission
// to keep trying; the owner locking them out is the one who gets the error. Deleting a user was
// the second instance, in the other direction: decision 10's session hoist inverted the
// users-before-user_sessions order that DELETE FROM users and its cascade used to give it for
// free.
//
// The remedy is one row of extra discipline: users, then user_sessions, then the grants. These
// tests are the three pairs that cycle, both orderings each, on all four engines.
//
// WHY THE INTERLEAVING IS WRITTEN OUT STATEMENT BY STATEMENT in the pairs below. A cycle needs
// each party to hold half of what the other wants, so a test that runs one transaction to
// completion and only then starts the other can never build one: the first party holds everything
// before the second asks for anything. Every subtest here therefore stops the foreground party
// part way, lets the other arrive and requires it to block, and only then lets the first continue.
// requireBlocked is what makes "has arrived" a fact; see blocked_party_test.go.

// deadlockSignatures are what each engine says when it aborts one of two transactions to break a
// cycle, plus the two refusals an engine issues instead of detecting one. Matched
// case-insensitively.
//
// Used only where a subtest legitimately expects an error for a different reason, so
// require.NoError would be wrong and asserting nothing would let a deadlock through unnoticed.
// Everywhere else the assertion is simply that neither party errored at all.
var deadlockSignatures = []string{
	"deadlock",          // MySQL 1213, PostgreSQL 40P01 and SQL Server 1205 all spell it out
	"40001",             // MySQL's SQLSTATE for it
	"40p01",             // PostgreSQL's
	"1205",              // SQL Server's error number
	"lock wait timeout", // InnoDB giving up rather than detecting
	"database is locked",
}

// requireNotDeadlock fails when err is an engine refusing one of two transactions over a lock. A
// nil error passes: this asks what KIND of failure happened, not whether one did.
func requireNotDeadlock(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		return
	}
	lowered := strings.ToLower(err.Error())
	for _, signature := range deadlockSignatures {
		if strings.Contains(lowered, signature) {
			t.Fatalf("%s was aborted over a lock, which is the cycle this test exists to rule out: %v",
				what, err)
		}
	}
}

// changePassword is the write a credential operation hands RevokeUserAuthStateTx: the durable
// half, which is what makes the users row the first thing that transaction touches.
func changePassword(user *models.User) func(tx *sql.Tx) error {
	return func(tx *sql.Tx) error {
		user.PasswordHash = "changed_" + gofakeit.LetterN(10)
		return database.UpdateUser(tx, user)
	}
}

// sweepSessionBlock issues RevokeUserAuthState's session block on the caller's transaction: read
// the user's sessions, take them in a stable order, delete them.
//
// Split out from the increment above it so a subtest can let the other party arrive BETWEEN the
// two, which is the only interleaving that can build the cycle. The real function runs both
// halves back to back and is driven whole wherever a subtest does not need to stop in the middle.
func sweepSessionBlock(db data.Database, tx *sql.Tx, userId int64) error {
	sessions, err := db.GetUserSessionsByUserId(tx, userId)
	if err != nil {
		return err
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Id < sessions[j].Id })
	for i := range sessions {
		if err := db.DeleteUserSession(tx, sessions[i].Id); err != nil {
			return err
		}
	}
	return nil
}

// sweepOutcome is one credential operation's outcome.
type sweepOutcome struct {
	result handlers.RevocationResult
	err    error
}

// TestLockOrder_IssuanceAgainstCredentialSweep is the first pair, and the one the final review
// reproduced: an authorization ceremony completing while the account's password is changed.
//
// The ceremony takes the users row, then the session row, then inserts. The sweep writes the users
// row through the caller's password write and IncrementUserAuthStateGeneration, then deletes the
// sessions, then revokes the grants. Same order, so one of them waits.
//
// Without the ceremony's users-row acquisition the two interleave into a cycle: the sweep's
// increment finds the users row free and takes it, then blocks on the session row the ceremony
// holds, and the ceremony's insert then asks for the parent users row the sweep is holding.
// MySQL and SQL Server abort the sweep. PostgreSQL survives this particular pair by accident,
// because IncrementUserAuthStateGeneration updates a non-key column and so takes FOR NO KEY
// UPDATE, which does not conflict with the FOR KEY SHARE an insert takes on its parent; that is a
// property of which columns the statement happens to touch rather than a rule anyone stated, so
// the fix is not conditioned on the engine and neither is this test.
func TestLockOrder_IssuanceAgainstCredentialSweep(t *testing.T) {
	t.Run("the ceremony goes first and the password change waits", func(t *testing.T) {
		other := secondDatabase(t)

		client := createTestClient(t)
		user := createTestUser(t)
		session := createTestUserSession(t, user.Id)

		tx, err := database.BeginTransaction()
		require.NoError(t, err, "opening the ceremony's transaction")
		defer func() { _ = database.RollbackTransaction(tx) }()

		// The ceremony, stopped between taking its rows and inserting, which is the state the
		// cycle needs it to be in when the sweep arrives.
		require.NoError(t, database.AcquireUserRow(tx, user.Id), "the ceremony takes the user row")
		live, err := database.AcquireUserSessionRow(tx, session.SessionIdentifier)
		require.NoError(t, err, "the ceremony takes the session row")
		require.True(t, live, "the session row is still there when the ceremony takes it")

		// The real credential path, whole, on the other handle.
		sweep := goBlocked(t, "the password change", tx, func(reached func()) sweepOutcome {
			reached()
			result, err := handlers.RevokeUserAuthStateTx(other, user.Id, "", changePassword(user))
			return sweepOutcome{result: result, err: err}
		})

		sweep.requireBlocked(t)

		// THE INSERT COMES AFTER THE SWEEP HAS ARRIVED. It is the statement that reaches users
		// without naming it, so it is the statement that closes the cycle when the ceremony does
		// not already hold that row.
		code, err := mintCode(database, tx, client, user, session.SessionIdentifier)
		require.NoError(t, err,
			"the ceremony's insert must not be chosen as a deadlock victim: it reaches the users row "+
				"through codes.user_id, and holding that row already is what makes it safe")

		sweep.requireStillWaiting(t)
		require.NoError(t, database.CommitTransaction(tx), "committing the ceremony")

		outcome := sweep.await(t)
		require.NoError(t, outcome.err,
			"the password change must wait for the ceremony and then commit, not be aborted over a lock. "+
				"Losing this one is the bad outcome: the owner locking an intruder out is the party that fails")

		// The credential operation did all of its work, which is the point of it not being the
		// victim: the password moved, the generation advanced, the session is gone. A deadlocked
		// sweep leaves every one of these three untouched, which is what the reproduction
		// recorded as "generation=0 (before=0), passwordChanged=false, sessionPresent=true".
		assert.Equal(t, outcome.result.OldGeneration+1, outcome.result.NewGeneration,
			"the generation advanced by exactly one")
		assert.Contains(t, outcome.result.TerminatedSessionIdentifiers, session.SessionIdentifier,
			"the sweep ended the session it was there to end")
		assertSessionGone(t, session.Id, "the session the password change ended")

		reloaded, err := database.GetUserById(nil, user.Id)
		require.NoError(t, err, "reloading the user")
		require.NotNil(t, reloaded)
		assert.Equal(t, user.PasswordHash, reloaded.PasswordHash,
			"the password change committed rather than being rolled back by a deadlock")

		// And the ceremony's own code exists, because it won the race legitimately: it completed
		// before the sweep began. The generation advance is what invalidates it, which is #106's
		// subject rather than this one's.
		stored, err := database.GetCodeById(nil, code.Id)
		require.NoError(t, err, "reloading the minted code")
		assert.NotNil(t, stored, "the ceremony that won the race keeps its code")
	})

	t.Run("the password change goes first and the ceremony waits", func(t *testing.T) {
		other := secondDatabase(t)

		client := createTestClient(t)
		user := createTestUser(t)
		session := createTestUserSession(t, user.Id)

		tx, err := database.BeginTransaction()
		require.NoError(t, err, "opening the password change's transaction")
		defer func() { _ = database.RollbackTransaction(tx) }()

		// RevokeUserAuthStateTx owns and commits its own transaction, so the ordering that needs
		// the sweep HELD OPEN across the ceremony's arrival drives the inner function instead.
		require.NoError(t, changePassword(user)(tx), "the password write")
		_, err = handlers.RevokeUserAuthState(database, tx, user.Id, "")
		require.NoError(t, err, "the sweep on a user nothing else has touched yet")

		ceremony := goBlocked(t, "the ceremony", tx, func(reached func()) issuanceOutcome {
			otherTx, err := other.BeginTransaction()
			if err != nil {
				reached()
				return issuanceOutcome{err: err}
			}
			defer func() { _ = other.RollbackTransaction(otherTx) }()

			reached()
			outcome := issuanceStatements(other, otherTx, client, user, session.SessionIdentifier)
			if outcome.err == nil && outcome.code != nil {
				outcome.err = other.CommitTransaction(otherTx)
			}
			return outcome
		})

		ceremony.requireBlocked(t)
		ceremony.requireStillWaiting(t)
		require.NoError(t, database.CommitTransaction(tx), "committing the password change")

		outcome := ceremony.await(t)
		require.NoError(t, outcome.err,
			"the ceremony must wait for the password change and then read its answer, not deadlock with it")

		// The whole value of waiting: the ceremony reads its answer AFTER the wait, so it sees the
		// session the password change removed and refuses.
		assert.False(t, outcome.live,
			"the session acquisition must report the session gone, which is what waiting buys")
		assert.Nil(t, outcome.code, "a ceremony whose session is gone writes no code at all")
		assertSessionGone(t, session.Id, "the session the password change ended")
	})
}

// TestLockOrder_DeleteUserAgainstCredentialSweep is the second instance, and the one decision 10
// created rather than left alone. Before this branch commondb.DeleteUser reached the users row
// through DELETE FROM users, whose cascade then removed the sessions, so it agreed with the
// credential paths for free. Decision 10's hoist made it delete the session rows explicitly first,
// which inverted it, and deleting a user then deadlocked with a password change for that user on
// PostgreSQL, MySQL and SQL Server. AcquireUserRow puts the users row back on top without giving
// the session rows their old position back.
func TestLockOrder_DeleteUserAgainstCredentialSweep(t *testing.T) {
	t.Run("the password change holds the user row and the delete waits", func(t *testing.T) {
		other := secondDatabase(t)

		user := createTestUser(t)
		session := createTestUserSession(t, user.Id)

		tx, err := database.BeginTransaction()
		require.NoError(t, err, "opening the password change's transaction")
		defer func() { _ = database.RollbackTransaction(tx) }()

		// The sweep stopped after its users writes and BEFORE its session block. That is the
		// interleaving the cycle needs, and it is why the two halves are driven separately here:
		// run whole, the sweep would hold the session rows too and the delete would simply queue.
		require.NoError(t, changePassword(user)(tx), "the password write")
		_, err = database.IncrementUserAuthStateGeneration(tx, user.Id)
		require.NoError(t, err, "the generation advance, which is the sweep's own users write")

		deletion := goBlocked(t, "DeleteUser", tx, func(reached func()) error {
			reached()
			return other.DeleteUser(nil, user.Id)
		})

		// With AcquireUserRow the delete stops here, at the top of the order, having taken
		// nothing. Without it, its first write is the session delete, which succeeds because the
		// sweep has not reached the sessions yet, and it then blocks on DELETE FROM users while
		// holding the session rows the sweep is about to want. That is the cycle, and it is the
		// statement below that closes it.
		deletion.requireBlocked(t)

		require.NoError(t, sweepSessionBlock(database, tx, user.Id),
			"the sweep's session block must not be chosen as a deadlock victim: the delete waiting "+
				"at the users row is holding no session row for it to collide with")

		deletion.requireStillWaiting(t)
		require.NoError(t, database.CommitTransaction(tx), "committing the password change")

		require.NoError(t, deletion.await(t),
			"the delete must wait for the password change and then commit, not deadlock with it")

		gone, err := database.GetUserById(nil, user.Id)
		require.NoError(t, err, "reloading the deleted user")
		assert.Nil(t, gone, "the user must be gone once the delete that waited committed")
		assertSessionGone(t, session.Id, "the session both parties removed")
	})

	t.Run("the delete goes first and the password change waits", func(t *testing.T) {
		other := secondDatabase(t)

		user := createTestUser(t)
		createTestUserSession(t, user.Id)

		tx, err := database.BeginTransaction()
		require.NoError(t, err, "opening the delete's transaction")
		defer func() { _ = database.RollbackTransaction(tx) }()

		require.NoError(t, database.DeleteUser(tx, user.Id), "DeleteUser on the held transaction")

		sweep := goBlocked(t, "the password change", tx, func(reached func()) sweepOutcome {
			reached()
			result, err := handlers.RevokeUserAuthStateTx(other, user.Id, "", changePassword(user))
			return sweepOutcome{result: result, err: err}
		})

		sweep.requireBlocked(t)
		sweep.requireStillWaiting(t)
		require.NoError(t, database.CommitTransaction(tx), "committing the delete")

		outcome := sweep.await(t)

		// This one legitimately fails, and WHICH failure it is, is the assertion. The user it was
		// going to sweep no longer exists, so the generation advance affects no row and says so.
		// A deadlock would arrive here too and would look like an ordinary failure to anything
		// that only checked that an error came back.
		requireNotDeadlock(t, outcome.err, "the password change")
		require.Error(t, outcome.err,
			"a sweep of a user that has just been deleted has nothing to sweep and must say so")
		assert.Contains(t, outcome.err.Error(), "user not found when incrementing auth state generation",
			"the failure must be the absent user rather than anything about locks")

		gone, err := database.GetUserById(nil, user.Id)
		require.NoError(t, err, "reloading the deleted user")
		assert.Nil(t, gone, "the delete committed")
	})
}
