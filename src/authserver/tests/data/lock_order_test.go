package datatests

import (
	"database/sql"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockedFor is how long the second party is given to reach the lock the first one is holding
// before the first commits. It only has to exceed the time one BeginTransaction and one
// statement take to reach the engine, and the failure it guards against is a false PASS: if the
// second party has not blocked yet, the two never overlap and the test proves nothing about a
// cycle. Overshooting costs wall clock and nothing else.
const blockedFor = 300 * time.Millisecond

// lockWaitCeiling is longer than any engine's own lock timeout here (SQLite's busy_timeout is
// 5s, InnoDB's lock wait 50s), so a party that reaches this has not been refused by the engine,
// it is genuinely stuck. Failing beats hanging the tier on a lock nobody will release.
const lockWaitCeiling = 90 * time.Second

// awaitParty collects a backgrounded transaction's outcome. A deadlock arrives as an error and
// fails the caller; a live hang arrives as the ceiling above.
func awaitParty[T any](t *testing.T, done <-chan T, what string) T {
	t.Helper()
	select {
	case out := <-done:
		return out
	case <-time.After(lockWaitCeiling):
		t.Fatalf("%s never returned: it is still waiting on a lock that nothing is going to release", what)
		var zero T
		return zero
	}
}

// replayResponse issues, on the caller's transaction, the statements revokeOnAuthCodeReuse
// issues for a replayed code that carries a session identifier: the session row first, then the
// grants that hang off it. It reports whether the acquisition found the row.
//
// It is written out here rather than called, because revokeOnAuthCodeReuse is unexported in the
// handlers package and takes no transaction from its caller. The pairing is the one #139 uses
// throughout: a unit test in that package pins that production issues exactly this sequence in
// exactly this order, and this tier answers what a mock cannot, whether two real transactions
// of these shapes can form a cycle on a real catalog.
func replayResponse(db data.Database, tx *sql.Tx, sessionIdentifier string) (bool, error) {
	live, err := db.AcquireUserSessionRow(tx, sessionIdentifier)
	if err != nil {
		return false, err
	}

	tokens, err := db.GetRefreshTokensBySessionIdentifier(tx, sessionIdentifier)
	if err != nil {
		return live, err
	}

	revoked := 0
	for _, rt := range tokens {
		if rt.Revoked {
			continue
		}
		rt.Revoked = true
		if err := db.UpdateRefreshToken(tx, rt); err != nil {
			return live, err
		}
		revoked++
	}

	// #77's guard: the session comes down only when this call actually revoked something.
	if revoked == 0 {
		return live, nil
	}
	session, err := db.GetUserSessionBySessionIdentifier(tx, sessionIdentifier)
	if err != nil {
		return live, err
	}
	if session == nil {
		return live, nil
	}
	return live, db.DeleteUserSession(tx, session.Id)
}

// terminationStatements issues, on the caller's transaction, what TerminateUserSessionTx issues
// in the order it issues them. The real function owns and commits its own transaction, so an
// ordering that needs the termination HELD OPEN across the other party's arrival cannot call it;
// the ordering that does not is driven through the real function, in the test below.
func terminationStatements(db data.Database, tx *sql.Tx, session *models.UserSession) error {
	if err := db.DeleteUserSession(tx, session.Id); err != nil {
		return err
	}
	if _, err := db.RevokeCodesBySessionIdentifier(tx, session.SessionIdentifier); err != nil {
		return err
	}
	tokens, err := db.GetRefreshTokensBySessionIdentifier(tx, session.SessionIdentifier)
	if err != nil {
		return err
	}
	for _, rt := range tokens {
		if rt.Revoked {
			continue
		}
		rt.Revoked = true
		if err := db.UpdateRefreshToken(tx, rt); err != nil {
			return err
		}
	}
	return nil
}

// TestLockOrder_ReplayResponseAgainstTermination is #139 decision 10 measured where it has to
// hold: on a real catalog, on every engine, with two transactions genuinely overlapping.
//
// The replay response to a reused authorization code (RFC 6749 section 10.5) and an explicit
// session termination both write a session row and that session's grants. Written the obvious
// way they take them in opposite orders, the replay reaching refresh_tokens before
// user_sessions, and two transactions that each hold half of what the other wants deadlock:
// measured on PostgreSQL, MySQL and SQL Server, with the REPLAY chosen as the victim, which is
// the bad outcome rather than merely an unlucky one, because the reused code's session then
// survives the very response meant to contain it.
//
// Both parties now take the session row first, so one of them simply waits. This test asserts
// the absence of the cycle in both orderings: neither party may return an error, because a
// deadlock is reported as one on all three engines that detect it and as a lock timeout on the
// two that serialize instead.
func TestLockOrder_ReplayResponseAgainstTermination(t *testing.T) {
	t.Run("the replay goes first and the termination waits", func(t *testing.T) {
		other := secondDatabase(t)

		client := createTestClient(t)
		user := createTestUser(t)
		session := createTestUserSession(t, user.Id)
		code := createTestCodeInSession(t, client.Id, user.Id, session.SessionIdentifier)
		token := createTokenOfCode(t, client.Id, user.Id, code.Id, session.SessionIdentifier)

		tx, err := database.BeginTransaction()
		require.NoError(t, err, "opening the replay's transaction")
		defer func() { _ = database.RollbackTransaction(tx) }()

		live, err := replayResponse(database, tx, session.SessionIdentifier)
		require.NoError(t, err, "the replay response on a session nothing else has touched yet")
		assert.True(t, live, "the session row is still there when the replay takes it")

		// The real termination, on the other handle, arriving while the replay holds the row.
		// Its first statement is the delete, which is what makes it wait.
		terminated := make(chan error, 1)
		go func() {
			_, err := handlers.TerminateUserSessionTx(other, session)
			terminated <- err
		}()

		time.Sleep(blockedFor)
		require.NoError(t, database.CommitTransaction(tx), "committing the replay")

		require.NoError(t, awaitParty(t, terminated, "the termination"),
			"the termination must wait for the replay and then commit, not deadlock with it")

		assertCodeRevoked(t, code.Id, true, "the code of the terminated session")
		assertTokenRevoked(t, token.Id, true, "the token the replay revoked")
		assertSessionGone(t, session.Id, "the session both parties removed")
	})

	t.Run("the termination goes first and the replay waits", func(t *testing.T) {
		other := secondDatabase(t)

		client := createTestClient(t)
		user := createTestUser(t)
		session := createTestUserSession(t, user.Id)
		code := createTestCodeInSession(t, client.Id, user.Id, session.SessionIdentifier)
		token := createTokenOfCode(t, client.Id, user.Id, code.Id, session.SessionIdentifier)

		tx, err := database.BeginTransaction()
		require.NoError(t, err, "opening the termination's transaction")
		defer func() { _ = database.RollbackTransaction(tx) }()

		require.NoError(t, terminationStatements(database, tx, session),
			"the termination's statements on a session nothing else has touched yet")

		type replayOutcome struct {
			live bool
			err  error
		}
		replayed := make(chan replayOutcome, 1)
		go func() {
			otherTx, err := other.BeginTransaction()
			if err != nil {
				replayed <- replayOutcome{err: err}
				return
			}
			defer func() { _ = other.RollbackTransaction(otherTx) }()

			live, err := replayResponse(other, otherTx, session.SessionIdentifier)
			if err != nil {
				replayed <- replayOutcome{live: live, err: err}
				return
			}
			replayed <- replayOutcome{live: live, err: other.CommitTransaction(otherTx)}
		}()

		time.Sleep(blockedFor)
		require.NoError(t, database.CommitTransaction(tx), "committing the termination")

		outcome := awaitParty(t, replayed, "the replay response")
		require.NoError(t, outcome.err,
			"the replay must wait for the termination and then commit, not deadlock with it")

		// The whole value of waiting: the replay reads its answer AFTER the wait rather than
		// from a snapshot taken before it, so it sees the row the termination removed.
		assert.False(t, outcome.live,
			"the acquisition must report the session gone, which is what waiting for the termination buys")

		assertCodeRevoked(t, code.Id, true, "the code the termination revoked")
		assertTokenRevoked(t, token.Id, true, "the token the termination revoked")
		assertSessionGone(t, session.Id, "the terminated session")
	})
}

// TestLockOrder_DeleteUserAgainstIssuance is the fifth site, the one decision 10's answer did not
// enumerate, measured rather than argued.
//
// DeleteUser is not a pure cascade: Go chooses to delete refresh_tokens explicitly and only then
// DELETE FROM users, whose cascade removes codes and user_sessions. So it took refresh_tokens
// before user_sessions while an authorization ceremony takes user_sessions before codes, and the
// two deadlocked on PostgreSQL, MySQL and SQL Server with the CEREMONY as the victim. It now
// deletes the user's session rows explicitly first, which is the same rows and the same outcome
// one statement earlier, and puts it on the one lock order.
//
// What removing the rows achieves is TestDeleteUser_RemovesAllDependentRows' subject and is not
// restated here. This test is about the absence of a cycle, in both orderings.
func TestLockOrder_DeleteUserAgainstIssuance(t *testing.T) {
	t.Run("issuance goes first and the user delete waits", func(t *testing.T) {
		// SQLite refuses this overlap rather than waiting through it, and the refusal is the
		// engine's rather than a cycle. DeleteUser's first statement is a read, so its
		// transaction begins as a reader, and SQLite answers a reader that then asks to
		// become a writer while another connection holds the write lock with SQLITE_BUSY at
		// once, without consulting the busy handler that would otherwise wait. The probe
		// behind decision 10 measured exactly this and recorded S7 on SQLite as safe, because
		// fail-closed is what it is: no cycle, no partial write, and the pre-existing
		// lock-refusal mode the agreement puts out of scope.
		//
		// There is also nothing here for a SQLite deployment to be protected from. Each
		// process builds one data.Database and sqlitedb calls SetMaxOpenConns(1), so a
		// process cannot hold these two transactions at the same time at all; the second
		// handle this test opens is concurrency SQLite does not have in production. The other
		// three subtests in this file do run on SQLite, because in those the waiting party
		// opens with a write and the busy handler applies.
		if dbType() == "sqlite" || dbType() == "" {
			t.Skip("sqlite refuses a reader's upgrade with SQLITE_BUSY instead of waiting, and a " +
				"SQLite process has one connection, so these two transactions never overlap in production")
		}

		other := secondDatabase(t)

		client := createTestClient(t)
		user := createTestUser(t)
		session := createTestUserSession(t, user.Id)

		tx, err := database.BeginTransaction()
		require.NoError(t, err, "opening the ceremony's transaction")
		defer func() { _ = database.RollbackTransaction(tx) }()

		live, err := database.AcquireUserSessionRow(tx, session.SessionIdentifier)
		require.NoError(t, err, "the ceremony takes the session row")
		require.True(t, live, "the session row is still there when the ceremony takes it")

		deleted := make(chan error, 1)
		go func() { deleted <- other.DeleteUser(nil, user.Id) }()

		// THE INSERT COMES AFTER THE DELETE HAS ARRIVED, and the order of these three
		// statements is the whole test. Inserting before the goroutine starts proves nothing:
		// the ceremony would then hold every lock it will ever want, so nothing it does can
		// close a cycle and the test passes against the unordered DeleteUser too. Measured
		// that way, as a surviving mutation, before it was written this way.
		//
		// Interleaved like this the insert needs a foreign-key lock on the users row, which is
		// exactly the row an unordered DeleteUser is holding while its cascade waits on the
		// session row the ceremony holds. That is the cycle, and it is why both this insert
		// and the delete are required to succeed: PostgreSQL, MySQL and SQL Server all abort
		// one of the two, and either error fails this test.
		time.Sleep(blockedFor)

		code := &models.Code{
			ClientId:          client.Id,
			UserId:            user.Id,
			Code:              "lockorder_" + gofakeit.LetterN(6),
			CodeHash:          "lockorderhash_" + gofakeit.LetterN(6),
			RedirectURI:       "https://example.com/callback",
			Scope:             "openid profile",
			ResponseMode:      "query",
			AuthenticatedAt:   time.Now().UTC().Truncate(time.Microsecond),
			SessionIdentifier: session.SessionIdentifier,
			AcrLevel:          "1",
			AuthMethods:       "pwd",
		}
		require.NoError(t, database.CreateCode(tx, code),
			"the ceremony's insert must not be chosen as a deadlock victim")

		require.NoError(t, database.CommitTransaction(tx), "committing the ceremony")

		require.NoError(t, awaitParty(t, deleted, "DeleteUser"),
			"DeleteUser must wait for the ceremony and then commit, not deadlock with it")

		gone, err := database.GetUserById(nil, user.Id)
		require.NoError(t, err, "reloading the deleted user")
		assert.Nil(t, gone, "the user must be gone once the delete that waited committed")
	})

	t.Run("the user delete goes first and issuance waits", func(t *testing.T) {
		other := secondDatabase(t)

		user := createTestUser(t)
		session := createTestUserSession(t, user.Id)

		// DeleteUser takes a transaction, so the real function is what runs here, held open
		// across the ceremony's arrival rather than replayed by hand.
		tx, err := database.BeginTransaction()
		require.NoError(t, err, "opening the delete's transaction")
		defer func() { _ = database.RollbackTransaction(tx) }()

		require.NoError(t, database.DeleteUser(tx, user.Id), "DeleteUser on the held transaction")

		type acquireOutcome struct {
			live bool
			err  error
		}
		acquired := make(chan acquireOutcome, 1)
		go func() {
			otherTx, err := other.BeginTransaction()
			if err != nil {
				acquired <- acquireOutcome{err: err}
				return
			}
			defer func() { _ = other.RollbackTransaction(otherTx) }()

			live, err := other.AcquireUserSessionRow(otherTx, session.SessionIdentifier)
			acquired <- acquireOutcome{live: live, err: err}
		}()

		time.Sleep(blockedFor)
		require.NoError(t, database.CommitTransaction(tx), "committing the delete")

		outcome := awaitParty(t, acquired, "the ceremony's acquisition")
		require.NoError(t, outcome.err,
			"the ceremony must wait for the delete and then read its answer, not deadlock with it")
		assert.False(t, outcome.live,
			"the acquisition must report the session gone, so the ceremony refuses and writes no code")
	})
}

// assertSessionGone reloads a session row and requires it to be absent.
func assertSessionGone(t *testing.T, sessionId int64, what string) {
	t.Helper()
	session, err := database.GetUserSessionById(nil, sessionId)
	require.NoErrorf(t, err, "reloading %s", what)
	assert.Nilf(t, session, "%s must be gone", what)
}
