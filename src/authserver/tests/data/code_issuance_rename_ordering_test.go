package datatests

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A rename of a client revokes its codes in the rename's transaction (#710 decision 5). Code
// issuance looks its client up by the identifier the ceremony named with a plain read, which on
// PostgreSQL and MySQL, and on SQL Server with READ_COMMITTED_SNAPSHOT on, does not wait for a
// rename holding the row, so it reads the client's row again with GetClientByIdForShare, a shared
// lock held to the end of its transaction, and refuses when the identifier is no longer the one it
// looked up. Either the code commits before the rename takes the row, and the rename's sweep revokes
// it, or the rename commits first and issuance writes nothing. Never a live code under the identifier
// the rename gave (#866). This file shows both orders on a real engine, with the statements that
// ship: issuance.CodeIssuer and revocation.RevokeClientGrantsTx around SetClientIdentifier.

// TestGetClientByIdForShare: the read answers the client GetClientById answers, nothing for a
// client that is not there, writes nothing, and requires a transaction, without which the lock
// would be released before the caller decides.
func TestGetClientByIdForShare(t *testing.T) {
	ctx := context.Background()
	client := createIdentifierTestClient(t)
	plain, err := database.GetClientById(ctx, nil, client.Id)
	require.NoError(t, err)

	tx := beginTx(t)
	held, err := database.GetClientByIdForShare(ctx, tx, client.Id)
	require.NoError(t, err)
	assert.Equal(t, plain, held, "the same client GetClientById reads")
	missing, err := database.GetClientByIdForShare(ctx, tx, client.Id+1_000_000)
	require.NoError(t, err)
	assert.Nil(t, missing)
	require.NoError(t, database.RollbackTransaction(ctx, tx))

	_, err = database.GetClientByIdForShare(ctx, nil, client.Id)
	require.Error(t, err)

	after, err := database.GetClientById(ctx, nil, client.Id)
	require.NoError(t, err)
	assert.Equal(t, plain.UpdatedAt, after.UpdatedAt, "the read writes nothing, updated_at included")
}

// Two transactions holding the shared lock on one client's row do not wait for each other, so
// sign-ins to one client are not queued behind one another. The second read is bounded: a read
// that waited for the first transaction would reach the deadline instead of answering.
func TestGetClientByIdForShare_TwoHoldersDoNotWaitForEachOther(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)
	ctx := context.Background()
	client := createIdentifierTestClient(t)

	first := beginTx(t)
	_, err := database.GetClientByIdForShare(ctx, first, client.Id)
	require.NoError(t, err)

	second := beginTx(t)
	bounded, cancel := context.WithTimeout(ctx, blockedCeiling)
	defer cancel()
	held, err := database.GetClientByIdForShare(bounded, second, client.Id)
	require.NoError(t, err, "the second shared read answers while the first transaction holds its lock")
	require.NotNil(t, held)
}

// TestCodeIssuanceOrdering_AgainstRename is the race on a real engine, both ways round.
func TestCodeIssuanceOrdering_AgainstRename(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)
	runCodeIssuanceOrderingAgainstRename(t, database, secondDatabase(t))
}

// TestCodeIssuanceOrdering_AgainstRename_RCSI is the same pair on a SQL Server database with
// READ_COMMITTED_SNAPSHOT on, where the plain lookup by identifier no longer waits for a rename
// holding the row. It skips on the other three engines.
func TestCodeIssuanceOrdering_AgainstRename_RCSI(t *testing.T) {
	f := rcsiDatabase(t)
	runCodeIssuanceOrderingAgainstRename(t, f.primary, f.secondary)
}

// runCodeIssuanceOrderingAgainstRename is the pair, over two handles to the SAME database, two
// distinct pools.
func runCodeIssuanceOrderingAgainstRename(t *testing.T, db data.Database, other data.Database) {
	t.Run("issuance goes first and the rename waits", func(t *testing.T) {
		ctx := context.Background()
		client := createTestClientOn(t, db)
		user := createTestUserOn(t, db)
		session := createTestUserSessionOn(t, db, user.Id)

		// The real issuance, on a transaction this test holds open: it has read the client's row
		// under the shared lock and inserted the code, and not yet committed.
		tx, err := db.BeginTransaction(ctx)
		require.NoError(t, err, "opening the ceremony's transaction")
		defer func() { _ = db.RollbackTransaction(ctx, tx) }()
		code, err := issuance.NewCodeIssuer(db).IssueAuthCode(ctx, tx,
			ceremonyCodeInput(client, user, session.SessionIdentifier))
		require.NoError(t, err, "the ceremony issues while the client keeps its identifier")
		require.NotNil(t, code)

		type renameOutcome struct {
			result revocation.ClientGrantResult
			err    error
		}
		rename := goBlocked(t, "the rename", tx, func(reached func()) renameOutcome {
			reached()
			result, renameErr := renameRevoking(ctx, other, client.Id, "renamed_"+fake.LetterN(8))
			return renameOutcome{result, renameErr}
		})

		rename.requireBlocked(t)
		rename.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(ctx, tx), "committing the ceremony")

		renamed := rename.await(t)
		require.NoError(t, renamed.err, "the rename waits for the ceremony and then commits")
		assert.Equal(t, int64(1), renamed.result.RevokedCodeCount,
			"the rename's sweep ran after the code committed, so it found it")
		assertCodeRevokedOn(t, db, code.Id, true, "the code the ceremony issued")
	})

	t.Run("the rename goes first and issuance waits", func(t *testing.T) {
		ctx := context.Background()
		client := createTestClientOn(t, db)
		user := createTestUserOn(t, db)
		session := createTestUserSessionOn(t, db, user.Id)
		input := ceremonyCodeInput(client, user, session.SessionIdentifier)

		// RevokeClientGrantsTx owns and commits its own transaction, so the rename HELD OPEN across
		// the ceremony's arrival runs its statements by hand; the other order drives the real
		// function.
		tx, err := db.BeginTransaction(ctx)
		require.NoError(t, err, "opening the rename's transaction")
		defer func() { _ = db.RollbackTransaction(ctx, tx) }()
		changed, err := db.SetClientIdentifier(ctx, tx, client.Id, "renamed_"+fake.LetterN(8))
		require.NoError(t, err)
		require.True(t, changed)
		_, err = revocation.RevokeClientGrants(ctx, db, tx, client.Id, revocation.ReasonClientIdentifierChanged)
		require.NoError(t, err)

		ceremony := goBlocked(t, "the ceremony", tx, func(reached func()) issuanceOutcome {
			reached()
			issued, issueErr := issuance.NewCodeIssuer(other).IssueAuthCodeTx(ctx, input)
			return issuanceOutcome{code: issued, err: issueErr}
		})

		ceremony.requireBlocked(t)
		ceremony.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(ctx, tx), "committing the rename")

		outcome := ceremony.await(t)
		require.ErrorIs(t, outcome.err, issuance.ErrIssuingClientGone,
			"the ceremony waits for the rename, then reads the identifier it gave the client and refuses")
		assert.Nil(t, outcome.code)

		// And the catalog agrees: a ceremony that inserted after the rename's sweep would leave
		// exactly one unrevoked code here, redeemable under the identifier the rename gave.
		leftBehind, err := db.RevokeCodesBySessionIdentifier(ctx, nil, session.SessionIdentifier)
		require.NoError(t, err, "sweeping the ceremony's session once more")
		assert.Zero(t, leftBehind, "no live code of the renamed client is left")
	})
}
