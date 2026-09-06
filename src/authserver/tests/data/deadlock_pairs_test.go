package datatests

import (
	"database/sql"
	"sync"
	"testing"
	"time"

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
	arrived  sync.Once
	released sync.Once
	reached  chan *sql.Tx
	release  chan struct{}
	what     string
}

// newBarrier registers the release as a cleanup, which is what keeps a failure between the park
// and the release from taking the rest of the tier down with it. Every check in these tests
// between those two points fails through t.Fatal, and a Fatal unwinds the test goroutine without
// running the rest of the function: the parked worker would then wait forever for a release
// nobody sends, holding its transaction and every row it has taken, and each later test on this
// engine that wanted one of those rows would block until the package timeout. What a reader
// would see is a hang in an unrelated test rather than the assertion that actually failed.
func newBarrier(t *testing.T, what string) *barrier {
	t.Helper()
	b := &barrier{reached: make(chan *sql.Tx, 1), release: make(chan struct{}), what: what}
	t.Cleanup(b.releaseParked)
	return b
}

func (b *barrier) arriveBefore(tx *sql.Tx) {
	b.arrived.Do(func() {
		b.reached <- tx
		<-b.release
	})
}

// awaitParked waits for the worker to reach its barrier, bounded. Unbounded, a worker that fails
// before it gets there parks the test itself on a channel nothing will ever send to, and the
// tier dies on its own timeout naming no test and no reason.
func (b *barrier) awaitParked(t *testing.T) *sql.Tx {
	t.Helper()
	select {
	case tx := <-b.reached:
		return tx
	case <-time.After(lockWaitCeiling):
		t.Fatalf("%s never reached its barrier within %s, so it never took the rows the other "+
			"party has to contend with and nothing here was measured", b.what, lockWaitCeiling)
		return nil
	}
}

// releaseParked is idempotent because the cleanup above also runs on the success path, after the
// test has already released; closing a closed channel panics.
func (b *barrier) releaseParked() { b.released.Do(func() { close(b.release) }) }

// awaitWorker collects a barrier-driven worker's result, bounded for the reason awaitParked is.
// blockedParty.await already does this for the other party; these workers are not blockedParty,
// because they are the ones that park rather than the ones that block.
func awaitWorker[T any](t *testing.T, what string, ch <-chan T) T {
	t.Helper()
	select {
	case out := <-ch:
		return out
	case <-time.After(lockWaitCeiling):
		var zero T
		t.Fatalf("%s never returned within %s", what, lockWaitCeiling)
		return zero
	}
}

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

	b := newBarrier(t, "the credential sweep")
	pDB := pausedBeforeSessionDelete{Database: database, b: b}

	sweepDone := make(chan error, 1)
	go func() {
		_, err := handlers.RevokeUserAuthStateTx(pDB, user.Id, "", func(tx *sql.Tx) error {
			return pDB.SetUserPasswordHash(tx, user.Id, newHash)
		})
		sweepDone <- err
	}()

	sweepTx := b.awaitParked(t) // the sweep holds the users row and is parked before its session deletes

	type issuanceOut struct {
		live bool
		code *models.Code
		err  error
	}
	issuance := goBlocked(t, "issuance", sweepTx, func(reached func()) issuanceOut {
		var out issuanceOut
		out.err = other.RunInTransaction(func(tx *sql.Tx) error {
			// Each attempt starts clean. out lives outside the closure, so a rerun would
			// otherwise inherit the aborted attempt's code and could report a gone session
			// holding a code that was never committed, which is the impossible shape the
			// assertions below refuse. RunInTransaction's doc comment names this hazard.
			out = issuanceOut{}

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
	sweepErr := awaitWorker(t, "the credential sweep", sweepDone)

	require.NoError(t, sweepErr, "the credential sweep must finish, whether it was the victim or the survivor")
	require.NoError(t, out.err, "issuance must finish; a gone session is a refusal, not an error")

	// End state, deterministic on every engine: the password is the sweep's, and the session the
	// sweep swept is gone.
	reloaded, err := database.GetUserById(nil, user.Id)
	require.NoError(t, err)
	require.NotNil(t, reloaded, "the credential sweep does not delete the user")
	assert.Equal(t, newHash, reloaded.PasswordHash, "the password hash is the one the sweep wrote")
	assertSessionGoneOn(t, database, session.Id, "the session the credential sweep terminated")

	// ISSUANCE HAS TWO VALID SHAPES AND THE THIRD IS IMPOSSIBLE. It either found the session
	// live and minted a code, or found it gone and minted nothing. Which of the two depends on
	// the party the engine aborted, so neither is required; that they are the only two is. Left
	// unasserted, a mintCode that quietly returns no code at all satisfies this test, and then
	// the pair proves the two transactions finished without proving the ceremony did anything.
	if out.live {
		require.NotNil(t, out.code, "a ceremony that found the session live minted a code")

		minted, err := database.GetCodeById(nil, out.code.Id)
		require.NoError(t, err)
		require.NotNil(t, minted, "the code issuance committed is in the catalog")
		assert.Equal(t, session.SessionIdentifier, minted.SessionIdentifier,
			"the code carries the session it was issued through")
		assert.Equal(t, user.Id, minted.UserId)
		assert.Equal(t, client.Id, minted.ClientId)
		assert.False(t, minted.Used, "the code was minted, not redeemed")

		// The code outlives the session it was issued through, and what stops it being spent is
		// the generation the sweep advanced rather than any write to this row: RevokeUserAuthState
		// increments the user's auth_state_generation, deletes the session rows and sweeps the
		// refresh tokens, and touches no code (#106). Pinning that here is what says the winner's
		// code is refused at redemption for the reason the design claims, not by luck.
		assert.False(t, minted.Revoked,
			"this sweep invalidates codes by advancing the generation, it does not mark them revoked")
	} else {
		assert.Nil(t, out.code, "a session-gone refusal mints nothing")
	}
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

	b := newBarrier(t, "the credential sweep")
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

	sweepTx := b.awaitParked(t) // the sweep holds the users row and is parked before its session deletes

	deleteUser := goBlocked(t, "DeleteUser", sweepTx, func(reached func()) error {
		reached()
		return other.DeleteUser(nil, user.Id)
	})

	deleteUser.requireBlocked(t) // DeleteUser holds the session rows and waits for the users row
	deleteUser.requireStillWaiting(t)

	b.releaseParked()

	deleteErr := deleteUser.await(t)
	sweep := awaitWorker(t, "the credential sweep", sweepDone)

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

	b := newBarrier(t, "the termination")
	pDB := pausedBeforeTokenUpdate{Database: database, b: b}

	terminationDone := make(chan error, 1)
	go func() {
		_, err := handlers.TerminateUserSessionTx(pDB, session)
		terminationDone <- err
	}()

	terminationTx := b.awaitParked(t) // the termination holds the codes rows and is parked before the token sweep

	deleteClient := goBlocked(t, "DeleteClient", terminationTx, func(reached func()) error {
		reached()
		return other.DeleteClient(nil, client.Id)
	})

	deleteClient.requireBlocked(t) // DeleteClient holds the tokens and waits for the codes cascade
	deleteClient.requireStillWaiting(t)

	b.releaseParked()

	deleteErr := deleteClient.await(t)
	terminationErr := awaitWorker(t, "the termination", terminationDone)

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
