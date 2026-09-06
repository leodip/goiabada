package datatests

import (
	"database/sql"
	"sync"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// THE RESIDUAL DEADLOCKS, FORCED AND SHOWN TO RESOLVE (#301 decision 6).
//
// Dropping the global lock order (#297, removed in stage 4) leaves pairs of transactions on the
// same account that can take the same rows in opposite orders and deadlock. Decision 7 answers
// that not by re-imposing an order but by rerunning the engine's victim, inside RunInTransaction.
// A paragraph in CLAUDE.md claiming this holds on four engines is not evidence; these tests are.
//
// Each test drives two REAL production transactions, both opened through RunInTransaction, into a
// genuine engine cycle, and asserts that both finish. The proof that the retry is what carried
// them is the mutation recorded in the stage log: neutralise the dialect classifier so isDeadlock
// returns false, and every one of these fails with the engine's own deadlock error, because
// nothing reruns the victim.
//
// HOW A CYCLE IS FORCED BETWEEN TWO RunInTransaction BODIES. issuance_ordering_test.go and
// replay_ordering_test.go hold one transaction open by hand and drive the other through the real
// function; that works there because those pairs SERIALIZE, one waits for the other and neither is
// aborted. A deadlock needs both parties inside RunInTransaction at once, so a transaction cannot
// be held open from the outside. The barrier below parks one party from INSIDE its own body: a
// decorator over data.Database overrides one method to hand its transaction to the test and wait,
// so the party is stopped holding exactly the rows it has taken so far while the other party takes
// the row it will later want. The blocked_party_test.go harness then confirms the second party is
// genuinely queued behind the first before the first is released.
//
// SQLite is skipped everywhere: its pool has one connection (SetMaxOpenConns(1)), so two
// transactions of this process never overlap and there is no cycle, which is also why its
// classifier is always false.

// barrier parks the first caller of a decorated method and hands its transaction to the test.
//
// arriveBefore trips exactly once, on the first call: it publishes the transaction and blocks
// until releaseParked closes the release channel. Every later call, including the rerun after the
// engine aborts this transaction as a deadlock victim, passes straight through, because a rerun
// that parked again would wait for a release that has already happened and hang the tier.
type barrier struct {
	once    sync.Once
	reached chan *sql.Tx
	release chan struct{}
}

func newBarrier() *barrier {
	return &barrier{reached: make(chan *sql.Tx, 1), release: make(chan struct{})}
}

func (b *barrier) arriveBefore(tx *sql.Tx) {
	b.once.Do(func() {
		b.reached <- tx
		<-b.release
	})
}

func (b *barrier) releaseParked() { close(b.release) }

// pausedBeforeSessionDelete parks the credential sweep after it has taken the users row (the
// password write and the generation increment both precede DeleteUserSession) and before it takes
// the first session row. RevokeUserAuthState calls DeleteUserSession on the db it was handed, so
// this decorator, passed as that db, catches it.
type pausedBeforeSessionDelete struct {
	data.Database
	b *barrier
}

func (d pausedBeforeSessionDelete) DeleteUserSession(tx *sql.Tx, userSessionId int64) error {
	d.b.arriveBefore(tx)
	return d.Database.DeleteUserSession(tx, userSessionId)
}

// pausedBeforeTokenUpdate parks the termination after it has taken the session row and the codes
// rows (DeleteUserSession and RevokeCodesBySessionIdentifier both precede the token sweep) and
// before it takes the first token row. TerminateUserSessionTx reaches its token updates through
// revokeRefreshTokens, which calls UpdateRefreshToken on the db it was handed.
type pausedBeforeTokenUpdate struct {
	data.Database
	b *barrier
}

func (d pausedBeforeTokenUpdate) UpdateRefreshToken(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	d.b.arriveBefore(tx)
	return d.Database.UpdateRefreshToken(tx, refreshToken)
}

func skipIfSQLite(t *testing.T) {
	t.Helper()
	if dbType() == "sqlite" || dbType() == "" {
		t.Skip("SQLite runs on one connection, so two transactions never overlap and nothing can deadlock")
	}
}

// TestDeadlockRetry_CredentialSweepAgainstIssuance is the residual table's first pair: a credential
// change and an authorization ceremony for the same account, taking the users row and the session
// row in opposite orders.
//
// The sweep is parked holding the users row. Issuance acquires the session row and then inserts a
// code, whose foreign key to users wants a lock on the row the sweep holds. On MySQL and SQL Server
// that FK lock conflicts and issuance blocks; releasing the sweep then sends it at the session row
// issuance holds and the cycle closes. On PostgreSQL the FK check takes FOR KEY SHARE, which does
// not conflict with the sweep's FOR NO KEY UPDATE, so issuance never blocks and there is no cycle:
// PostgreSQL is clean on this pair by design, so the test records whether the block happened rather
// than requiring it. Either way both transactions finish, the password is the new one and the
// session is gone.
func TestDeadlockRetry_CredentialSweepAgainstIssuance(t *testing.T) {
	skipIfSQLite(t)

	other := secondDatabase(t)

	client := createTestClient(t)
	user := createTestUser(t)
	session := createTestUserSession(t, user.Id)

	const newHash = "deadlock-pair-1-new-hash"

	b := newBarrier()
	pDB := pausedBeforeSessionDelete{Database: database, b: b}

	sweepDone := make(chan error, 1)
	go func() {
		_, err := handlers.RevokeUserAuthStateTx(pDB, user.Id, "", func(tx *sql.Tx) error {
			return pDB.SetUserPasswordHash(tx, user.Id, newHash)
		})
		sweepDone <- err
	}()

	sweepTx := <-b.reached // the sweep holds the users row and is parked before its session deletes

	type issuanceOut struct {
		live bool
		code *models.Code
		err  error
	}
	issuance := goBlocked(t, "issuance", sweepTx, func(reached func()) issuanceOut {
		var out issuanceOut
		out.err = other.RunInTransaction(func(tx *sql.Tx) error {
			live, err := other.AcquireUserSessionRow(tx, session.SessionIdentifier)
			if err != nil {
				return err
			}
			if !live {
				out.live = false
				return nil // the ceremony's legitimate session-gone refusal
			}
			reached() // the next statement, the code insert, is the one that may block on the FK
			code, err := mintCode(other, tx, client, user, session.SessionIdentifier)
			if err != nil {
				return err
			}
			out.live, out.code = true, code
			return nil
		})
		return out
	})

	// PostgreSQL does not block here (see the doc comment), so record the outcome rather than
	// requiring it. On MySQL and SQL Server issuance is queued behind the parked sweep.
	blocked := issuance.awaitBlocked() == nil
	t.Logf("engine %s: issuance blocked behind the credential sweep = %v", dbType(), blocked)

	b.releaseParked()

	out := issuance.await(t)
	sweepErr := <-sweepDone

	require.NoError(t, sweepErr, "the credential sweep must finish, whether it was the victim or the survivor")
	require.NoError(t, out.err, "issuance must finish; a gone session is a refusal, not an error")

	// End state, deterministic on every engine: the password is the sweep's, and the session the
	// sweep swept is gone. Whether issuance minted a code depends on which party won, so it is not
	// asserted; the retained ordering test owns the session-gone refusal shape.
	reloaded, err := database.GetUserById(nil, user.Id)
	require.NoError(t, err)
	require.NotNil(t, reloaded, "the credential sweep does not delete the user")
	assert.Equal(t, newHash, reloaded.PasswordHash, "the password hash is the one the sweep wrote")
	assertSessionGoneOn(t, database, session.Id, "the session the credential sweep terminated")
}

// TestDeadlockRetry_DeleteUserAgainstCredentialSweep is the pair whose victim legitimately refuses.
//
// The sweep is parked holding the users row. DeleteUser deletes the user's session rows first, then
// wants the users row for its final DELETE, which conflicts on all three engines, so it blocks.
// Releasing the sweep sends it at the session rows DeleteUser holds and the cycle closes. Whichever
// party the engine aborts, both finish and the user ends gone. If DeleteUser won, the sweep's rerun
// finds no user and IncrementUserAuthStateGeneration refuses with "user not found", which is the
// correct answer and is deliberate: the retry's promise is that an operation still applicable
// succeeds, not that a removed precondition is conjured back (decision 7, #301).
func TestDeadlockRetry_DeleteUserAgainstCredentialSweep(t *testing.T) {
	skipIfSQLite(t)

	other := secondDatabase(t)

	user := createTestUser(t)
	// A session must exist for both parties to contend on: the sweep's barrier trips on its
	// first DeleteUserSession, and DeleteUser takes that same session row before the users row.
	_ = createTestUserSession(t, user.Id)

	const newHash = "deadlock-pair-2-new-hash"

	b := newBarrier()
	pDB := pausedBeforeSessionDelete{Database: database, b: b}

	type sweepResult struct {
		result handlers.RevocationResult
		err    error
	}
	sweepDone := make(chan sweepResult, 1)
	go func() {
		result, err := handlers.RevokeUserAuthStateTx(pDB, user.Id, "", func(tx *sql.Tx) error {
			return pDB.SetUserPasswordHash(tx, user.Id, newHash)
		})
		sweepDone <- sweepResult{result: result, err: err}
	}()

	sweepTx := <-b.reached // the sweep holds the users row and is parked before its session deletes

	deleteUser := goBlocked(t, "DeleteUser", sweepTx, func(reached func()) error {
		reached()
		return other.DeleteUser(nil, user.Id)
	})

	deleteUser.requireBlocked(t) // DeleteUser holds the session rows and waits for the users row
	deleteUser.requireStillWaiting(t)

	b.releaseParked()

	deleteErr := deleteUser.await(t)
	sweep := <-sweepDone

	require.NoError(t, deleteErr, "DeleteUser must finish, whether it was the victim or the survivor")

	// The user is gone on every engine and either winner: DeleteUser removes it, and if the sweep
	// won first, DeleteUser's rerun removes it after.
	gone, err := database.GetUserById(nil, user.Id)
	require.NoError(t, err)
	assert.Nil(t, gone, "the user is gone: DeleteUser removed it whichever party the engine aborted")

	if sweep.err == nil {
		// The sweep won: its generation advance is read from its own result, never from the row,
		// which is now gone.
		assert.Equal(t, sweep.result.OldGeneration+1, sweep.result.NewGeneration,
			"a sweep that committed advanced the generation by one")
	} else {
		// DeleteUser won and removed the user before the sweep's rerun. The refusal is the
		// deliberate one, not a deadlock error leaking through.
		assert.Contains(t, sweep.err.Error(), "user not found when incrementing auth state generation",
			"the sweep's only permitted failure is the vanished-precondition refusal")
	}
}

// TestDeadlockRetry_DeleteClientAgainstTermination is the client-side pair.
//
// The termination is parked holding the session's codes rows (it has deleted the session row and
// revoked its codes, and is about to sweep the tokens). DeleteClient deletes the client's refresh
// tokens (statement one completes, because the termination holds no token yet), then deletes the
// clients row, whose ON DELETE CASCADE to codes wants the codes rows the termination holds, so it
// blocks. Releasing the termination sends its token update at the token row DeleteClient deleted,
// and the cycle closes without depending on any statement-internal lock order. Both finish and the
// client, its tokens and the session are gone.
func TestDeadlockRetry_DeleteClientAgainstTermination(t *testing.T) {
	skipIfSQLite(t)

	other := secondDatabase(t)

	client := createTestClient(t)
	user := createTestUser(t)
	session := createTestUserSession(t, user.Id)
	code := createTestCodeInSession(t, client.Id, user.Id, session.SessionIdentifier)
	token := createTokenOfCode(t, client.Id, user.Id, code.Id, session.SessionIdentifier)

	b := newBarrier()
	pDB := pausedBeforeTokenUpdate{Database: database, b: b}

	terminationDone := make(chan error, 1)
	go func() {
		_, err := handlers.TerminateUserSessionTx(pDB, session)
		terminationDone <- err
	}()

	terminationTx := <-b.reached // the termination holds the codes rows and is parked before the token sweep

	deleteClient := goBlocked(t, "DeleteClient", terminationTx, func(reached func()) error {
		reached()
		return other.DeleteClient(nil, client.Id)
	})

	deleteClient.requireBlocked(t) // DeleteClient holds the tokens and waits for the codes cascade
	deleteClient.requireStillWaiting(t)

	b.releaseParked()

	deleteErr := deleteClient.await(t)
	terminationErr := <-terminationDone

	require.NoError(t, deleteErr, "DeleteClient must finish, whether it was the victim or the survivor")
	require.NoError(t, terminationErr, "the termination must finish; it refuses on no vanished precondition here")

	// End state, deterministic: the client is gone, its cascade took the code and the token, and
	// the termination deleted the session.
	goneClient, err := database.GetClientById(nil, client.Id)
	require.NoError(t, err)
	assert.Nil(t, goneClient, "the client is gone")

	goneToken, err := database.GetRefreshTokenById(nil, token.Id)
	require.NoError(t, err)
	assert.Nil(t, goneToken, "the client's refresh token is gone")

	assertSessionGoneOn(t, database, session.Id, "the terminated session")
}
