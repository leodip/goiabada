package datatests

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A rename of a client revokes its codes in the rename's transaction (#710 decision 5). Code
// issuance looks its client up by the identifier the ceremony named with a plain read, which on
// PostgreSQL and MySQL, and on SQL Server with READ_COMMITTED_SNAPSHOT on, does not wait for a
// rename holding the row, so it reads the client's row again with GetClientByIDForShare, a shared
// lock held to the end of its transaction, and refuses when the identifier is no longer the one it
// looked up. Either the code commits before the rename can change the row, and the rename's sweep
// revokes it, or the rename commits first and issuance writes nothing. Never a live code under the
// identifier the rename gave (#866). This file shows both orders on a real engine, with the
// statements that ship: issuance.CodeIssuer and revocation.RevokeClientGrantsTx around
// SetClientIdentifier.

// TestGetClientByIDForShare: the read answers the client GetClientByID answers, nothing for a
// client that is not there, writes nothing, and requires a transaction, without which the lock
// would be released before the caller decides.
func TestGetClientByIDForShare(t *testing.T) {
	ctx := context.Background()
	client := createIdentifierTestClient(t)
	plain, err := database.GetClientByID(ctx, nil, client.ID)
	require.NoError(t, err)

	tx := beginTx(t)
	held, err := database.GetClientByIDForShare(ctx, tx, client.ID)
	require.NoError(t, err)
	assert.Equal(t, plain, held, "the same client GetClientByID reads")
	missing, err := database.GetClientByIDForShare(ctx, tx, client.ID+1_000_000)
	require.NoError(t, err)
	assert.Nil(t, missing)
	require.NoError(t, database.RollbackTransaction(ctx, tx))

	_, err = database.GetClientByIDForShare(ctx, nil, client.ID)
	require.Error(t, err)

	after, err := database.GetClientByID(ctx, nil, client.ID)
	require.NoError(t, err)
	assert.Equal(t, plain.UpdatedAt, after.UpdatedAt, "the read writes nothing, updated_at included")
}

// Two transactions holding the shared lock on one client's row do not wait for each other, so
// sign-ins to one client in different sessions are not queued behind one another on its row. The
// second read is bounded: a read that waited for the first transaction would reach the deadline
// instead of answering.
func TestGetClientByIDForShare_TwoHoldersDoNotWaitForEachOther(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)
	ctx := context.Background()
	client := createIdentifierTestClient(t)

	first := beginTx(t)
	_, err := database.GetClientByIDForShare(ctx, first, client.ID)
	require.NoError(t, err)

	second := beginTx(t)
	bounded, cancel := context.WithTimeout(ctx, blockedCeiling)
	defer cancel()
	held, err := database.GetClientByIDForShare(bounded, second, client.ID)
	require.NoError(t, err, "the second shared read answers while the first transaction holds its lock")
	require.NotNil(t, held)
}

// pausingCodeInserts holds code issuance at its insert, after it has looked the client up and read
// the client's row under the shared lock, so a test can start a rename while that lock is the only
// one issuance holds on the row: the insert's own foreign key lock comes after it. Only the first
// insert pauses. proceed lets it go, and the test's cleanup calls it too, so a failing assertion
// never leaves the transaction parked with its locks held.
type pausingCodeInserts struct {
	data.Database
	paused      chan struct{}
	release     chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

func newPausingCodeInserts(t *testing.T, db data.Database) *pausingCodeInserts {
	p := &pausingCodeInserts{Database: db, paused: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(p.proceed)
	return p
}

func (p *pausingCodeInserts) CreateCode(ctx context.Context, tx *sql.Tx, code *record.Code) error {
	p.once.Do(func() {
		close(p.paused)
		<-p.release
	})
	return p.Database.CreateCode(ctx, tx, code)
}

func (p *pausingCodeInserts) proceed() {
	p.releaseOnce.Do(func() { close(p.release) })
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
		ctx, cancel := context.WithCancel(context.Background())
		client := createTestClientOn(t, db)
		user := createTestUserOn(t, db)
		session := createTestUserSessionOn(t, db, user.ID)

		// The real issuance, on a transaction this test holds open, held at its insert: it has read
		// the client's row under the shared lock and written no code yet, so what the rename waits
		// for below is that lock alone, and a lock released before the insert would let the rename
		// commit in between and the code land after its sweep.
		tx, err := db.BeginTransaction(ctx)
		require.NoError(t, err, "opening the ceremony's transaction")
		defer func() { _ = db.RollbackTransaction(context.Background(), tx) }()
		// Deferred after the rollback so it runs first: a failure below cancels any statement still
		// in flight on the ceremony's transaction or the rename's, so the rollback does not wait on it.
		defer cancel()
		pause := newPausingCodeInserts(t, db)
		issued := make(chan issuanceOutcome, 1)
		go func() {
			code, issueErr := issuance.NewCodeIssuer(pause).IssueAuthCode(ctx, tx,
				ceremonyCodeInput(client, user, session.SessionIdentifier))
			issued <- issuanceOutcome{code: code, err: issueErr}
		}()
		select {
		case <-pause.paused:
		case o := <-issued:
			t.Fatalf("the ceremony finished before it inserted its code: %v", o.err)
		case <-time.After(blockedCeiling):
			t.Fatal("the ceremony never reached its insert")
		}

		type renameOutcome struct {
			result revocation.ClientGrantResult
			err    error
		}
		rename := goBlocked(t, "the rename", tx, func(reached func()) renameOutcome {
			reached()
			result, renameErr := renameRevoking(ctx, other, client.ID, "renamed_"+fake.LetterN(8))
			return renameOutcome{result, renameErr}
		})

		rename.requireBlocked(t)
		rename.requireStillWaiting(t)
		pause.proceed()

		var outcome issuanceOutcome
		select {
		case outcome = <-issued:
		case <-time.After(lockWaitCeiling):
			t.Fatal("the ceremony never finished its insert once released")
		}
		require.NoError(t, outcome.err, "the ceremony held the client's row first, and inserts its code")
		require.NotNil(t, outcome.code)
		code := outcome.code
		require.NoError(t, db.CommitTransaction(ctx, tx), "committing the ceremony")

		renamed := rename.await(t)
		require.NoError(t, renamed.err, "the rename waits for the ceremony and then commits")
		assert.Equal(t, int64(1), renamed.result.RevokedCodeCount,
			"the rename's sweep ran after the code committed, so it found it")
		assertCodeRevokedOn(t, db, code.ID, true, "the code the ceremony issued")
	})

	t.Run("the rename goes first and issuance waits", func(t *testing.T) {
		ctx := context.Background()
		client := createTestClientOn(t, db)
		user := createTestUserOn(t, db)
		session := createTestUserSessionOn(t, db, user.ID)
		input := ceremonyCodeInput(client, user, session.SessionIdentifier)

		// RevokeClientGrantsTx owns and commits its own transaction, so the rename HELD OPEN across
		// the ceremony's arrival runs its statements by hand; the other order drives the real
		// function.
		tx, err := db.BeginTransaction(ctx)
		require.NoError(t, err, "opening the rename's transaction")
		defer func() { _ = db.RollbackTransaction(ctx, tx) }()
		changed, err := db.SetClientIdentifier(ctx, tx, client.ID, "renamed_"+fake.LetterN(8))
		require.NoError(t, err)
		require.True(t, changed)
		_, err = revocation.RevokeClientGrants(ctx, db, tx, client.ID, revocation.ReasonClientIdentifierChanged)
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
