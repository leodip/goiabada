package datatests

import (
	"database/sql"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// replayResponse issues, on the caller's transaction, the statements revokeOnAuthCodeReuse
// issues for a replayed code that carries a session identifier: the session row first, then the
// grants that hang off it. It reports whether the acquisition found the row.
//
// It is written out here rather than called, because revokeOnAuthCodeReuse is unexported in the
// handlers package and takes no transaction from its caller. The pairing is the one
// issuance_ordering_test.go uses: a unit test in that package pins that production issues exactly
// this sequence in exactly this order, and this tier answers what a mock cannot, whether two real
// transactions of these shapes wait for each other on a real catalog.
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

// TestLockOrder_ReplayResponseAgainstTermination measures the one order the replay response keeps
// on purpose where it has to hold: on a real catalog, on every engine, with two transactions
// genuinely overlapping.
//
// The replay response to a reused authorization code (RFC 6749 section 10.5) and an explicit
// session termination both write a session row and that session's grants. Both take the session
// row first, so one of them simply waits for the other and reads its answer after the wait. This
// test asserts that in both orderings: neither party may return an error, because a deadlock is
// reported as one on the three engines that detect it, and the retry that would otherwise answer
// it is not what this pair relies on. The order is kept so the pair never reaches the retry, and
// so the replay reads the session's fate after the termination rather than from a snapshot taken
// before it (#139, #301).
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
		termination := goBlocked(t, "the termination", tx, func(reached func()) error {
			reached()
			_, err := handlers.TerminateUserSessionTx(other, session)
			return err
		})

		termination.requireBlocked(t)
		termination.requireStillWaiting(t)
		require.NoError(t, database.CommitTransaction(tx), "committing the replay")

		require.NoError(t, termination.await(t),
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
		replay := goBlocked(t, "the replay response", tx, func(reached func()) replayOutcome {
			otherTx, err := other.BeginTransaction()
			if err != nil {
				reached()
				return replayOutcome{err: err}
			}
			defer func() { _ = other.RollbackTransaction(otherTx) }()

			reached()
			live, err := replayResponse(other, otherTx, session.SessionIdentifier)
			if err != nil {
				return replayOutcome{live: live, err: err}
			}
			return replayOutcome{live: live, err: other.CommitTransaction(otherTx)}
		})

		replay.requireBlocked(t)
		replay.requireStillWaiting(t)
		require.NoError(t, database.CommitTransaction(tx), "committing the termination")

		outcome := replay.await(t)
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

// assertSessionGone reloads a session row and requires it to be absent.
func assertSessionGone(t *testing.T, sessionId int64, what string) {
	t.Helper()
	assertSessionGoneOn(t, database, sessionId, what)
}
