package datatests

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
//
// The replay is revocation.RevokeOnAuthCodeReuse itself, on a transaction this test holds open, so
// the statements measured here are the ones that ship; its unit test pins their order by mock, and
// this tier answers what a mock cannot, whether two real transactions of these shapes wait for each
// other on a real catalog.
func TestLockOrder_ReplayResponseAgainstTermination(t *testing.T) {
	t.Run("the replay goes first and the termination waits", func(t *testing.T) {
		other := secondDatabase(t)

		client := createTestClient(t)
		user := createTestUser(t)
		session := createTestUserSession(t, user.Id)
		code := createTestCodeInSession(t, client.Id, user.Id, session.SessionIdentifier)
		token := createTokenOfCode(t, client.Id, user.Id, code.Id, session.SessionIdentifier)

		tx, err := database.BeginTransaction(context.Background())
		require.NoError(t, err, "opening the replay's transaction")
		defer func() { _ = database.RollbackTransaction(context.Background(), tx) }()

		result, err := revocation.RevokeOnAuthCodeReuse(context.Background(), database, tx, code)
		require.NoError(t, err, "the replay response on a session nothing else has touched yet")
		assert.Equal(t, []string{token.RefreshTokenJti}, result.RevokedRefreshTokenJtis,
			"the replay revokes the grant's token")

		// The real termination, on the other handle, arriving while the replay holds the row.
		// Its first statement is the delete, which is what makes it wait.
		termination := goBlocked(t, "the termination", tx, func(reached func()) error {
			reached()
			_, err := revocation.TerminateUserSessionTx(context.Background(), other, session)
			return err
		})

		termination.requireBlocked(t)
		termination.requireStillWaiting(t)
		require.NoError(t, database.CommitTransaction(context.Background(), tx), "committing the replay")

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

		tx, err := database.BeginTransaction(context.Background())
		require.NoError(t, err, "opening the termination's transaction")
		defer func() { _ = database.RollbackTransaction(context.Background(), tx) }()

		require.NoError(t, terminationStatements(database, tx, session),
			"the termination's statements on a session nothing else has touched yet")

		type replayOutcome struct {
			result revocation.AuthCodeReuseResult
			err    error
		}
		replay := goBlocked(t, "the replay response", tx, func(reached func()) replayOutcome {
			otherTx, err := other.BeginTransaction(context.Background())
			if err != nil {
				reached()
				return replayOutcome{err: err}
			}
			defer func() { _ = other.RollbackTransaction(context.Background(), otherTx) }()

			reached()
			result, err := revocation.RevokeOnAuthCodeReuse(context.Background(), other, otherTx, code)
			if err != nil {
				return replayOutcome{result: result, err: err}
			}
			return replayOutcome{result: result, err: other.CommitTransaction(context.Background(), otherTx)}
		})

		replay.requireBlocked(t)
		replay.requireStillWaiting(t)
		require.NoError(t, database.CommitTransaction(context.Background(), tx), "committing the termination")

		outcome := replay.await(t)
		require.NoError(t, outcome.err,
			"the replay must wait for the termination and then commit, not deadlock with it")

		// The whole value of waiting: the replay reads its answer AFTER the wait rather than from
		// a snapshot taken before it, so it finds the token the termination already revoked and
		// transitions nothing, which also keeps #77's guard from deleting anything. A replay that
		// read the token before the termination committed would revoke it again and report it.
		require.NotNil(t, outcome.result.RevokedRefreshTokenJtis)
		assert.Empty(t, outcome.result.RevokedRefreshTokenJtis,
			"the replay must see the termination's revocation, which is what waiting for it buys")

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
