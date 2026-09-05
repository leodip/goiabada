package datatests

import (
	"database/sql"
	"testing"
	"time"

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
// authorization code branch: the session row first, then the code. When the acquisition reports
// the row gone it inserts nothing, which is the refusal (#139 decision 3), and the caller decides
// whether to commit.
//
// The handler itself cannot be driven from this tier: it owns its transaction and answers over
// HTTP. The pairing is the one #139 uses throughout: the unit tests in the handlers package pin
// that production issues exactly this sequence in exactly this order, and this tier answers what
// a mock cannot, what two real transactions of these shapes do to each other on a real catalog.
func issuanceStatements(db data.Database, tx *sql.Tx, client *models.Client, user *models.User, sessionIdentifier string) issuanceOutcome {
	live, err := db.AcquireUserSessionRow(tx, sessionIdentifier)
	if err != nil || !live {
		return issuanceOutcome{live: live, err: err}
	}
	code, err := mintCode(db, tx, client, user, sessionIdentifier)
	return issuanceOutcome{live: true, code: code, err: err}
}

// requireStillWaiting is the assertion that makes these tests worth running: the second party
// must NOT have returned while the first still holds the session row. Without it the test passes
// whether or not the two transactions ever overlapped, and a race test that cannot tell "waited
// for the other side" from "ran after it" proves nothing about the window it claims to close.
func requireStillWaiting[T any](t *testing.T, done <-chan T, what string) {
	t.Helper()
	select {
	case <-done:
		t.Fatalf("%s returned while the other party still held the session row: the two never overlapped, so nothing here was measured", what)
	default:
	}
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
	t.Run("issuance goes first and the termination waits", func(t *testing.T) {
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

		// The real termination, on the other handle, arriving while the ceremony holds the row.
		// Its first statement is the delete, which is what makes it wait.
		type terminationOutcome struct {
			result handlers.TerminationResult
			err    error
		}
		terminated := make(chan terminationOutcome, 1)
		go func() {
			result, err := handlers.TerminateUserSessionTx(other, session)
			terminated <- terminationOutcome{result: result, err: err}
		}()

		// THE INSERT COMES AFTER THE TERMINATION HAS ARRIVED. This is the window the issue is
		// about: the termination is in flight, and the code does not exist yet.
		time.Sleep(blockedFor)
		requireStillWaiting(t, terminated, "the termination")

		code, err := mintCode(database, tx, client, user, session.SessionIdentifier)
		require.NoError(t, err, "the ceremony's insert on the transaction holding the row")
		require.NoError(t, database.CommitTransaction(tx), "committing the ceremony")

		outcome := awaitParty(t, terminated, "the termination")
		require.NoError(t, outcome.err,
			"the termination must wait for the ceremony and then commit, not deadlock with it or be refused")

		// The whole value of the termination waiting: its sweep ran after the insert committed,
		// so it found the code this ceremony minted. Before #139 this count was 0, the sweep
		// having run before the row existed.
		assert.Equal(t, int64(1), outcome.result.RevokedCodeCount,
			"the termination's code sweep must mark the code inserted while it was waiting")
		assertCodeRevoked(t, code.Id, true, "the code the client received")
		assertSessionGone(t, session.Id, "the terminated session")
	})

	t.Run("the termination goes first and issuance waits", func(t *testing.T) {
		other := secondDatabase(t)

		client := createTestClient(t)
		user := createTestUser(t)
		session := createTestUserSession(t, user.Id)

		// TerminateUserSessionTx owns and commits its own transaction, so an ordering that needs
		// the termination HELD OPEN across the ceremony's arrival replays its statements by hand;
		// the other subtest drives the real function.
		tx, err := database.BeginTransaction()
		require.NoError(t, err, "opening the termination's transaction")
		defer func() { _ = database.RollbackTransaction(tx) }()

		require.NoError(t, terminationStatements(database, tx, session),
			"the termination's statements on a session nothing else has touched yet")

		issued := make(chan issuanceOutcome, 1)
		go func() {
			otherTx, err := other.BeginTransaction()
			if err != nil {
				issued <- issuanceOutcome{err: err}
				return
			}
			defer func() { _ = other.RollbackTransaction(otherTx) }()

			outcome := issuanceStatements(other, otherTx, client, user, session.SessionIdentifier)
			if outcome.err == nil && outcome.code != nil {
				// Production commits only what it minted; a refusal rolls back.
				outcome.err = other.CommitTransaction(otherTx)
			}
			issued <- outcome
		}()

		time.Sleep(blockedFor)
		requireStillWaiting(t, issued, "the ceremony")
		require.NoError(t, database.CommitTransaction(tx), "committing the termination")

		outcome := awaitParty(t, issued, "the ceremony")
		require.NoError(t, outcome.err,
			"the ceremony must wait for the termination and then read its answer, not deadlock with it or be refused")

		// The whole value of the ceremony waiting: its acquisition reads its answer AFTER the
		// wait, so it sees the row the termination removed and refuses.
		assert.False(t, outcome.live,
			"the acquisition must report the session gone, which is what waiting for the termination buys")
		assert.Nil(t, outcome.code, "a ceremony whose session is gone writes no code at all")

		// And the catalog agrees: nothing of this session is left for a sweep to mark. A ceremony
		// that inserted after the termination committed would leave exactly one unrevoked code
		// here, on a session whose termination has already run.
		leftBehind, err := database.RevokeCodesBySessionIdentifier(nil, session.SessionIdentifier)
		require.NoError(t, err, "sweeping the terminated session once more")
		assert.Zero(t, leftBehind, "no code of the terminated session may exist unrevoked")
		assertSessionGone(t, session.Id, "the terminated session")
	})
}
