package datatests

import (
	"net/http"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #139: A SESSION BUMP NEVER REACHES THE USERS ROW.
//
// BumpUserSession is the ordinary SSO write: every completed ceremony on an existing session
// rewrites the whole user_sessions row and touches its client association. It writes no grant,
// so it sits outside the users, user_sessions, grants order the rest of this package pins. It was
// nevertheless inside it on one engine. user_sessions.user_id is a foreign key, and SQL Server
// re-checks a foreign key whenever the column is in an UPDATE's SET list, unchanged value or
// not, by taking a shared lock on the parent. So the bump's full-row UPDATE took the session
// row and then the users row, while an authorization ceremony for the same user takes the users
// row and then the session row. Measured on SQL Server: the ceremony is the deadlock victim and
// the person completing the ceremony sees a 500. PostgreSQL and MySQL skip the re-check on an
// unchanged value and were never affected.
//
// The remedy is that user_id is never in the update set (the model tags it dont-update), so
// the bump takes exactly one row above its association, the session's, and queues on it like
// everything else. These two subtests are that pair in both orderings on all four engines. The
// first is the one that deadlocked, and its whole assertion is that the bump RETURNS while the
// ceremony still holds the users row: a bump that needed that row could not.

func bumpRequest() *http.Request {
	r, _ := http.NewRequest("GET", "/auth/completed", nil)
	r.RemoteAddr = "127.0.0.1:4321"
	return r
}

func TestLockOrder_IssuanceAgainstSessionBump(t *testing.T) {
	t.Run("the ceremony holds the users row and the bump does not need it", func(t *testing.T) {
		if dbType() == "sqlite" || dbType() == "" {
			t.Skip("SQLite has one writer, so the bump's UPDATE cannot run at all while another connection holds a write; the pair cannot overlap there in production either")
		}
		other := secondDatabase(t)

		client := createTestClient(t)
		usr := createTestUser(t)
		session := createTestUserSessionWithClient(t, usr.Id, client.Id)

		tx, err := database.BeginTransaction()
		require.NoError(t, err, "opening the ceremony's transaction")
		defer func() { _ = database.RollbackTransaction(tx) }()

		// The ceremony stopped between its two acquisitions: holding users, about to take the
		// session row. That is the state the cycle needs it to be in when the bump arrives.
		require.NoError(t, database.AcquireUserRow(tx, usr.Id), "the ceremony takes the users row")

		// The real bump, whole, on the other handle. Before the fix, on SQL Server, its UPDATE
		// takes the session row and then queues on the users row the ceremony holds, and it
		// stays there until the ceremony's next statement closes the cycle.
		done := make(chan error, 1)
		go func() {
			_, err := user.NewUserSessionManager(nil, nil, "", other).BumpUserSession(bumpRequest(),
				session.SessionIdentifier, client.Id, "pwd", enums.AcrLevel1.String())
			done <- err
		}()

		// THE WHOLE TEST. A bump that needs the users row cannot return while the ceremony
		// holds it exclusively, so returning here proves it never asked. The ceiling is the
		// same one requireBlocked uses to decide a party is stuck.
		select {
		case err := <-done:
			require.NoError(t, err, "the bump must complete while the ceremony holds the users row")
		case <-time.After(blockedCeiling):
			t.Fatalf("the bump did not return within %s while the ceremony held the users row: it is "+
				"waiting on that row, which a session bump has no business taking", blockedCeiling)
		}

		// The ceremony then takes the session row the bump just released and finishes. This is
		// the statement that was chosen as the deadlock victim.
		live, err := database.AcquireUserSessionRow(tx, session.SessionIdentifier)
		require.NoError(t, err, "the ceremony's session acquisition must not be a deadlock victim")
		require.True(t, live, "the bumped session is still there")
		code, err := mintCode(database, tx, client, usr, session.SessionIdentifier)
		require.NoError(t, err, "the ceremony's insert")
		require.NoError(t, database.CommitTransaction(tx), "committing the ceremony")

		// Both did their work: the bump moved last_accessed, the ceremony's code exists, and the
		// session still belongs to the user it was created for.
		bumped, err := database.GetUserSessionById(nil, session.Id)
		require.NoError(t, err)
		require.NotNil(t, bumped)
		assert.True(t, bumped.LastAccessed.After(session.LastAccessed), "the bump landed")
		assert.Equal(t, usr.Id, bumped.UserId, "the session's owner is untouched by the bump")
		stored, err := database.GetCodeById(nil, code.Id)
		require.NoError(t, err)
		assert.NotNil(t, stored, "the ceremony's code exists")
	})

	t.Run("the bump holds the session row and the ceremony waits", func(t *testing.T) {
		other := secondDatabase(t)

		client := createTestClient(t)
		usr := createTestUser(t)
		session := createTestUserSessionWithClient(t, usr.Id, client.Id)

		// BumpUserSession owns and commits its own transaction, so the ordering that needs it
		// HELD OPEN across the ceremony's arrival replays its statements by hand: the reads on
		// no transaction, as the real one does them, then the full-row session update first and
		// the association second. The reads come BEFORE the transaction opens: on SQLite the
		// package handle has one connection, and a read on the pool while a transaction holds
		// it waits for that transaction forever.
		held, err := database.GetUserSessionBySessionIdentifier(nil, session.SessionIdentifier)
		require.NoError(t, err)
		require.NoError(t, database.UserSessionLoadClients(nil, held))

		tx, err := database.BeginTransaction()
		require.NoError(t, err, "opening the bump's transaction")
		defer func() { _ = database.RollbackTransaction(tx) }()

		held.LastAccessed = time.Now().UTC().Truncate(time.Microsecond)
		require.NoError(t, database.UpdateUserSession(tx, held), "the bump's session update on the held transaction")

		ceremony := goBlocked(t, "the ceremony", tx, func(reached func()) issuanceOutcome {
			otherTx, err := other.BeginTransaction()
			if err != nil {
				reached()
				return issuanceOutcome{err: err}
			}
			defer func() { _ = other.RollbackTransaction(otherTx) }()

			reached()
			outcome := issuanceStatements(other, otherTx, client, usr, session.SessionIdentifier)
			if outcome.err == nil && outcome.code != nil {
				outcome.err = other.CommitTransaction(otherTx)
			}
			return outcome
		})

		ceremony.requireBlocked(t)

		require.Len(t, held.Clients, 1)
		held.Clients[0].LastAccessed = time.Now().UTC().Truncate(time.Microsecond)
		require.NoError(t, database.UpdateUserSessionClient(tx, &held.Clients[0]), "the bump's association update")
		ceremony.requireStillWaiting(t)
		require.NoError(t, database.CommitTransaction(tx), "committing the bump")

		outcome := ceremony.await(t)
		require.NoError(t, outcome.err, "the ceremony must wait for the bump and then commit, not deadlock with it")
		assert.True(t, outcome.live, "the session is still there once the bump has committed")
		require.NotNil(t, outcome.code, "the ceremony minted its code after the wait")
		assertCodeRevoked(t, outcome.code.Id, false, "the code of a live session")
	})
}
