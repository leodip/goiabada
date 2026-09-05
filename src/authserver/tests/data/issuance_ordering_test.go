package datatests

import (
	"database/sql"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issuanceOutcome is what one authorization ceremony's transaction came to: whether its
// acquisition found the session row, the code it minted when it did, and the error if any.
type issuanceOutcome struct {
	live bool
	code *models.Code
	err  error
}

// mintCode inserts one authorization code through the real CodeIssuer, so the client lookup and
// the insert run on the transaction production runs them on, rather than through a bare
// CreateCode.
func mintCode(db data.Database, tx *sql.Tx, client *models.Client, user *models.User, sessionIdentifier string) (*models.Code, error) {
	return oauth.NewCodeIssuer(db).CreateAuthCode(tx, &oauth.CreateCodeInput{
		AuthContext: oauth.AuthContext{
			ClientId:    client.ClientIdentifier,
			UserId:      user.Id,
			RedirectURI: "https://example.com/callback",
			Scope:       "openid profile",
			AcrLevel:    "urn:goiabada:level1",
			AuthMethods: "pwd",
		},
		SessionIdentifier: sessionIdentifier,
	})
}

// issuanceStatements issues, on the caller's transaction, what /auth/issue issues on the
// authorization code branch: the users row, then the session row, then the code. When the
// acquisition reports the session row gone it inserts nothing, which is the refusal (#139
// decision 3), and the caller decides whether to commit.
//
// The users row leads because the insert below reaches it anyway through codes.user_id, and
// taking it explicitly is what puts this ceremony on the same order the credential operations
// already use (#139 decision 11). The shared client acquisition follows it and precedes the
// session row: it is what closes DeleteClient's discovery window, and it has to come AFTER
// everything above clients, because a shared holder that then reaches upward closes a cycle with
// a deletion queued exclusively on that row.
//
// The handler itself cannot be driven from this tier: it owns its transaction and answers over
// HTTP. The pairing is the one #139 uses throughout: the unit tests in the handlers package pin
// that production issues exactly this sequence in exactly this order, and this tier answers what
// a mock cannot, what two real transactions of these shapes do to each other on a real catalog.
func issuanceStatements(db data.Database, tx *sql.Tx, client *models.Client, user *models.User, sessionIdentifier string) issuanceOutcome {
	if err := db.AcquireUserRow(tx, user.Id); err != nil {
		return issuanceOutcome{err: err}
	}
	if err := db.AcquireClientRowShared(tx, client.Id); err != nil {
		return issuanceOutcome{err: err}
	}
	live, err := db.AcquireUserSessionRow(tx, sessionIdentifier)
	if err != nil || !live {
		return issuanceOutcome{live: live, err: err}
	}
	code, err := mintCode(db, tx, client, user, sessionIdentifier)
	return issuanceOutcome{live: true, code: code, err: err}
}

// TestIssuanceOrdering_AgainstTermination is #139 itself, measured where it has to hold: on a real
// catalog, on every engine, with the code insert and the session termination genuinely
// overlapping. It is section 4's "there is no third case" as a test rather than a probe.
//
// Both parties write the one user_sessions row before touching anything else, the termination by
// deleting it and the ceremony by AcquireUserSessionRow, so on every engine one of them waits for
// the other and reads its answer AFTER the wait rather than from a snapshot taken before it. That
// leaves exactly two outcomes, one per subtest:
//
//   - the termination waits, and its code sweep then runs after the insert committed, so the code
//     it hands the client is already marked revoked;
//   - the ceremony waits, and its acquisition then matches no rows, so it refuses and no code
//     row is written at all.
//
// Before #139 the insert ran on its own connection with no transaction, so a code inserted after
// the termination's sweep and before its commit escaped the sweep, and the compensating read that
// followed still saw the uncommitted-deleted session. Measured open on PostgreSQL and SQL Server.
// A test of this shape against that code fails in the first subtest, on RevokedCodeCount and on
// the code's marker.
func TestIssuanceOrdering_AgainstTermination(t *testing.T) {
	runIssuanceOrderingAgainstTermination(t, database, secondDatabase(t))
}

// TestIssuanceOrdering_AgainstTermination_RCSI is the same pair against a SQL Server database with
// READ_COMMITTED_SNAPSHOT on, which is the configuration nothing on this branch had ever measured
// (#139 stage 8). It skips on the other three engines: RCSI is a SQL Server setting, PostgreSQL
// and MySQL are MVCC already, and SQLite has one writer.
//
// This pair is the load-bearing one to run there: it is the only test on the branch whose
// assertions are about the OUTCOME the ordering produces, either the code carries the revocation
// marker or no code is issued at all, rather than about the absence of a cycle.
//
// It is not the only one that runs there. An earlier draft of this comment argued that the
// lock-order pairs need not run under RCSI because RCSI can only remove lock conflicts, never add
// one, so a cycle that does not form with it off cannot appear with it on. That does not follow.
// Removing a conflict changes which interleavings are REACHABLE: a transaction that no longer
// stops at a read runs on and asks for locks it previously never reached, and a cycle can close
// there. DeleteClient has exactly that shape, a plain association read sitting between its
// exclusive client acquisition and the session rows it takes next. So the two client-deletion
// gates run under RCSI too, in lock_order_client_delete_test.go, and the reasoning above is
// recorded as an expectation rather than as a reason to skip the measurement.
func TestIssuanceOrdering_AgainstTermination_RCSI(t *testing.T) {
	f := rcsiDatabase(t)
	runIssuanceOrderingAgainstTermination(t, f.primary, f.secondary)
}

// runIssuanceOrderingAgainstTermination is the pair, over two handles it is given rather than the
// package's. Both handles must point at the SAME database and be two distinct pools: the
// interleaving needs two connections, and sqlitedb caps a pool at one.
func runIssuanceOrderingAgainstTermination(t *testing.T, db data.Database, other data.Database) {
	t.Run("issuance goes first and the termination waits", func(t *testing.T) {
		client := createTestClientOn(t, db)
		user := createTestUserOn(t, db)
		session := createTestUserSessionOn(t, db, user.Id)

		tx, err := db.BeginTransaction()
		require.NoError(t, err, "opening the ceremony's transaction")
		defer func() { _ = db.RollbackTransaction(tx) }()

		require.NoError(t, db.AcquireUserRow(tx, user.Id), "the ceremony takes the user row")
		require.NoError(t, db.AcquireClientRowShared(tx, client.Id), "the ceremony takes the client row, shared")
		live, err := db.AcquireUserSessionRow(tx, session.SessionIdentifier)
		require.NoError(t, err, "the ceremony takes the session row")
		require.True(t, live, "the session row is still there when the ceremony takes it")

		// The real termination, on the other handle, arriving while the ceremony holds the row.
		// Its first statement is the delete, which is what makes it wait.
		type terminationOutcome struct {
			result handlers.TerminationResult
			err    error
		}
		termination := goBlocked(t, "the termination", tx, func(reached func()) terminationOutcome {
			reached()
			result, err := handlers.TerminateUserSessionTx(other, session)
			return terminationOutcome{result: result, err: err}
		})

		// THE INSERT COMES AFTER THE TERMINATION HAS ARRIVED. This is the window the issue is
		// about: the termination is in flight, and the code does not exist yet.
		termination.requireBlocked(t)

		code, err := mintCode(db, tx, client, user, session.SessionIdentifier)
		require.NoError(t, err, "the ceremony's insert on the transaction holding the row")
		termination.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(tx), "committing the ceremony")

		outcome := termination.await(t)
		require.NoError(t, outcome.err,
			"the termination must wait for the ceremony and then commit, not deadlock with it or be refused")

		// The whole value of the termination waiting: its sweep ran after the insert committed,
		// so it found the code this ceremony minted. Before #139 this count was 0, the sweep
		// having run before the row existed. Under RCSI this is the assertion that would move if
		// the sweep read a snapshot taken before the insert rather than the committed row.
		assert.Equal(t, int64(1), outcome.result.RevokedCodeCount,
			"the termination's code sweep must mark the code inserted while it was waiting")
		assertCodeRevokedOn(t, db, code.Id, true, "the code the client received")
		assertSessionGoneOn(t, db, session.Id, "the terminated session")
	})

	t.Run("the termination goes first and issuance waits", func(t *testing.T) {
		client := createTestClientOn(t, db)
		user := createTestUserOn(t, db)
		session := createTestUserSessionOn(t, db, user.Id)

		// TerminateUserSessionTx owns and commits its own transaction, so an ordering that needs
		// the termination HELD OPEN across the ceremony's arrival replays its statements by hand;
		// the other subtest drives the real function.
		tx, err := db.BeginTransaction()
		require.NoError(t, err, "opening the termination's transaction")
		defer func() { _ = db.RollbackTransaction(tx) }()

		require.NoError(t, terminationStatements(db, tx, session),
			"the termination's statements on a session nothing else has touched yet")

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
				// Production commits only what it minted; a refusal rolls back.
				outcome.err = other.CommitTransaction(otherTx)
			}
			return outcome
		})

		ceremony.requireBlocked(t)
		ceremony.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(tx), "committing the termination")

		outcome := ceremony.await(t)
		require.NoError(t, outcome.err,
			"the ceremony must wait for the termination and then read its answer, not deadlock with it or be refused")

		// The whole value of the ceremony waiting: its acquisition reads its answer AFTER the
		// wait, so it sees the row the termination removed and refuses. This is the other
		// assertion RCSI could move: a writer released from the queue must re-read the current
		// committed row rather than the snapshot it opened with.
		assert.False(t, outcome.live,
			"the acquisition must report the session gone, which is what waiting for the termination buys")
		assert.Nil(t, outcome.code, "a ceremony whose session is gone writes no code at all")

		// And the catalog agrees: nothing of this session is left for a sweep to mark. A ceremony
		// that inserted after the termination committed would leave exactly one unrevoked code
		// here, on a session whose termination has already run.
		leftBehind, err := db.RevokeCodesBySessionIdentifier(nil, session.SessionIdentifier)
		require.NoError(t, err, "sweeping the terminated session once more")
		assert.Zero(t, leftBehind, "no code of the terminated session may exist unrevoked")
		assertSessionGoneOn(t, db, session.Id, "the terminated session")
	})
}
