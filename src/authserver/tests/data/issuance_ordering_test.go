package datatests

import (
	"context"
	"database/sql"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issuanceOutcome is what one authorization ceremony's transaction came to: the code it minted,
// and the error if any, ErrIssuingSessionGone for a refusal.
type issuanceOutcome struct {
	code *record.Code
	err  error
}

// ceremonyCodeInput is the code a ceremony for this client, user and session asks the issuer for.
func ceremonyCodeInput(client *record.Client, user *record.User, sessionIdentifier string) *issuance.CreateCodeInput {
	return &issuance.CreateCodeInput{
		ClientId:          client.ClientIdentifier,
		UserId:            user.Id,
		RedirectURI:       "https://example.com/callback",
		Scope:             "openid profile",
		AcrLevel:          "urn:goiabada:level1",
		AuthMethods:       "pwd",
		SessionIdentifier: sessionIdentifier,
	}
}

// TestIssuanceOrdering_AgainstTermination is #139 itself, measured where it has to hold: on a real
// catalog, on every engine, with the code insert and the session termination genuinely
// overlapping. It is section 4's "there is no third case" as a test rather than a probe.
//
// The ceremony is issuance.CodeIssuer.IssueAuthCode itself, on a transaction this test holds open,
// so the statements measured are the ones /auth/issue ships. Both parties write the one
// user_sessions row before touching anything else, the termination by deleting it and the
// ceremony by AcquireUserSessionRow, so on every engine one of them waits for the other and reads
// its answer AFTER the wait rather than from a snapshot taken before it. That leaves exactly two
// outcomes, one per subtest:
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
// One expectation is recorded here rather than relied on: RCSI can only remove lock conflicts,
// never add one, but removing a conflict changes which interleavings are REACHABLE. A transaction
// that no longer stops at a read runs on and asks for locks it previously never reached, and a
// cycle can close there. So a pair measured clean with RCSI off has not been measured with it on.
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

		tx, err := db.BeginTransaction(context.Background())
		require.NoError(t, err, "opening the ceremony's transaction")
		defer func() { _ = db.RollbackTransaction(context.Background(), tx) }()

		// The acquisition and the insert, both on the transaction the ceremony holds. The code is
		// written and not yet committed, which is the window the issue is about: an uncommitted
		// insert is invisible to a sweep, so without the acquisition ahead of it the termination
		// below would not wait, and its sweep would run past a code that then commits.
		code, err := issuance.NewCodeIssuer(db).IssueAuthCode(context.Background(), tx,
			ceremonyCodeInput(client, user, session.SessionIdentifier))
		require.NoError(t, err, "the ceremony takes the session row and inserts on its transaction")
		require.NotNil(t, code)

		// The real termination, on the other handle, arriving while the ceremony holds the row.
		// Its first statement is the delete, which is what makes it wait.
		type terminationOutcome struct {
			result revocation.TerminationResult
			err    error
		}
		termination := goBlocked(t, "the termination", tx, func(reached func()) terminationOutcome {
			reached()
			result, terminateErr := revocation.TerminateUserSessionTx(context.Background(), other, session)
			return terminationOutcome{result: result, err: terminateErr}
		})

		termination.requireBlocked(t)
		termination.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(context.Background(), tx), "committing the ceremony")

		outcome := termination.await(t)
		require.NoError(t, outcome.err,
			"the termination must wait for the ceremony and then commit, not deadlock with it or be refused")

		// The whole value of the termination waiting: its sweep ran after the insert committed,
		// so it found the code this ceremony minted. Before #139 this count was 0, the sweep
		// having run before the row was visible. Under RCSI this is the assertion that would move
		// if the sweep read a snapshot taken before the insert rather than the committed row.
		assert.Equal(t, int64(1), outcome.result.RevokedCodeCount,
			"the termination's code sweep must mark the code inserted before it arrived")
		assertCodeRevokedOn(t, db, code.Id, true, "the code the client received")
		assertSessionGoneOn(t, db, session.Id, "the terminated session")
	})

	t.Run("the termination goes first and issuance waits", func(t *testing.T) {
		client := createTestClientOn(t, db)
		user := createTestUserOn(t, db)
		session := createTestUserSessionOn(t, db, user.Id)

		// revocation.TerminateUserSessionTx owns and commits its own transaction, so an ordering that needs
		// the termination HELD OPEN across the ceremony's arrival replays its statements by hand;
		// the other subtest drives the real function.
		tx, err := db.BeginTransaction(context.Background())
		require.NoError(t, err, "opening the termination's transaction")
		defer func() { _ = db.RollbackTransaction(context.Background(), tx) }()

		require.NoError(t, terminationStatements(db, tx, session),
			"the termination's statements on a session nothing else has touched yet")

		ceremony := goBlocked(t, "the ceremony", tx, func(reached func()) issuanceOutcome {
			otherTx, beginErr := other.BeginTransaction(context.Background())
			if beginErr != nil {
				reached()
				return issuanceOutcome{err: beginErr}
			}
			defer func() { _ = other.RollbackTransaction(context.Background(), otherTx) }()

			reached()
			code, issueErr := issuance.NewCodeIssuer(other).IssueAuthCode(context.Background(), otherTx,
				ceremonyCodeInput(client, user, session.SessionIdentifier))
			if issueErr != nil {
				// Production commits only what it minted; a refusal rolls back.
				return issuanceOutcome{code: code, err: issueErr}
			}
			return issuanceOutcome{code: code, err: other.CommitTransaction(context.Background(), otherTx)}
		})

		ceremony.requireBlocked(t)
		ceremony.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(context.Background(), tx), "committing the termination")

		outcome := ceremony.await(t)

		// The whole value of the ceremony waiting: its acquisition reads its answer AFTER the
		// wait, so it sees the row the termination removed and refuses. This is the other
		// assertion RCSI could move: a writer released from the queue must re-read the current
		// committed row rather than the snapshot it opened with. A deadlock or any other failure
		// is a different error and fails here too.
		require.ErrorIs(t, outcome.err, issuance.ErrIssuingSessionGone,
			"the ceremony must wait for the termination and then refuse, not deadlock with it or insert")
		assert.Nil(t, outcome.code, "a ceremony whose session is gone writes no code at all")

		// And the catalog agrees: nothing of this session is left for a sweep to mark. A ceremony
		// that inserted after the termination committed would leave exactly one unrevoked code
		// here, on a session whose termination has already run.
		leftBehind, err := db.RevokeCodesBySessionIdentifier(context.Background(), nil, session.SessionIdentifier)
		require.NoError(t, err, "sweeping the terminated session once more")
		assert.Zero(t, leftBehind, "no code of the terminated session may exist unrevoked")
		assertSessionGoneOn(t, db, session.Id, "the terminated session")
	})
}

// terminationStatements issues, on the caller's transaction, what revocation.TerminateUserSessionTx issues
// in the order it issues them. The real function owns and commits its own transaction, so an
// ordering that needs the termination HELD OPEN across the other party's arrival cannot call it;
// the ordering that does not is driven through the real function.
func terminationStatements(db data.Database, tx *sql.Tx, session *record.UserSession) error {
	if err := db.DeleteUserSession(context.Background(), tx, session.Id); err != nil {
		return err
	}
	if _, err := db.RevokeCodesBySessionIdentifier(context.Background(), tx, session.SessionIdentifier); err != nil {
		return err
	}
	tokens, err := db.GetRefreshTokensBySessionIdentifier(context.Background(), tx, session.SessionIdentifier)
	if err != nil {
		return err
	}
	for _, rt := range tokens {
		if rt.Revoked {
			continue
		}
		rt.Revoked = true
		if err := db.UpdateRefreshToken(context.Background(), tx, rt); err != nil {
			return err
		}
	}
	return nil
}

// assertSessionGoneOn reloads through the handle it is given, for the reason assertCodeRevokedOn
// does.
func assertSessionGoneOn(t *testing.T, db data.Database, sessionId int64, what string) {
	t.Helper()
	session, err := db.GetUserSessionById(context.Background(), nil, sessionId)
	require.NoErrorf(t, err, "reloading %s", what)
	assert.Nilf(t, session, "%s must be gone", what)
}
