package datatests

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RunInTransaction against the real engines. The attempt count, the backoff and the warning
// are the scripted driver's to pin (authserver/internal/data/commondb/run_in_transaction_test.go);
// what only a real engine can answer is whether the rows end up where the contract says, and
// whether the dialect's classifier recognises the deadlock its own driver actually raises. The
// last case here is the smallest deadlock that can be forced, two rows taken in opposite orders,
// and it is the shape the production-pair tests build on (#301).

// deadlockCeiling bounds the forced deadlock. PostgreSQL looks for cycles after deadlock_timeout,
// one second by default; SQL Server's monitor runs every five seconds; InnoDB detects at once.
// The ceiling is far above all three so a slow engine is never mistaken for a broken retry.
const deadlockCeiling = 60 * time.Second

// newClientModel is a client that has not been inserted, for bodies that insert it themselves.
func newClientModel() *record.Client {
	return &record.Client{
		ClientIdentifier: "rit_client_" + fake.LetterN(8),
		Description:      "RunInTransaction test client",
	}
}

func TestRunInTransaction_ABodyThatReturnsNilIsCommittedAndItsRowsAreVisible(t *testing.T) {
	client := newClientModel()

	err := database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		return database.CreateClient(context.Background(), tx, client)
	})

	require.NoError(t, err)
	require.NotZero(t, client.Id)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })

	got, err := database.GetClientById(context.Background(), nil, client.Id)
	require.NoError(t, err)
	require.NotNil(t, got, "the row is visible through the pool after the helper returned, so it was committed")
	assert.Equal(t, client.ClientIdentifier, got.ClientIdentifier)
}

func TestRunInTransaction_ABodyThatReturnsAnErrorIsRolledBackAndTheErrorComesBackUnchanged(t *testing.T) {
	client := newClientModel()
	refused := errors.New("the body decided against it")

	err := database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		if err := database.CreateClient(context.Background(), tx, client); err != nil {
			return err
		}
		// Enlisted: the insert is visible on the transaction that made it, which is what a
		// write handed nil instead of tx would not show from here, having autocommitted.
		inside, err := database.GetClientById(context.Background(), tx, client.Id)
		if err != nil {
			return err
		}
		if inside == nil {
			return errors.New("the insert is not visible on its own transaction")
		}
		return refused
	})

	require.Error(t, err)
	assert.Equal(t, refused, err, "the body's error is returned as it was, not wrapped and not replaced")
	require.NotZero(t, client.Id, "the insert ran before the body refused")

	got, err := database.GetClientById(context.Background(), nil, client.Id)
	require.NoError(t, err)
	assert.Nil(t, got, "the insert did not survive the rollback: the write was enlisted in the transaction the body was handed")
}

// TestRunInTransaction_ARealDeadlockIsRerunAndBothPartiesFinish forces the engine to choose a
// victim and proves the victim's rerun succeeds.
//
// Two transactions on two handles take two client rows in opposite orders, each waiting until
// the other holds its first row before asking for the second, so the cycle is certain rather
// than likely. Which party the engine picks as victim differs per engine and per run, so both
// go through RunInTransaction and the assertion is engine-neutral: both return nil, the body
// ran three times in total (one party twice), and both rows are still there.
//
// The rerun's coordination is the reason for the sync.Once: a body that closed its channel a
// second time would panic, and the victim's rerun must not wait for a signal the survivor has
// already sent. On the rerun the first acquisition simply waits for the survivor's commit.
//
// SQLite skips: its pool has one connection, so the second transaction cannot open while the
// first is held and there is no cycle to force, which is also why its classifier is always false.
func TestRunInTransaction_ARealDeadlockIsRerunAndBothPartiesFinish(t *testing.T) {
	if dbType() == data.SQLite {
		t.Skip("SQLite's pool has one connection, so two transactions cannot overlap and nothing can deadlock")
	}

	// The second handle first, before anything is held: see secondDatabase for why.
	other := secondDatabase(t)

	rowA := createTestClient(t)
	rowB := createTestClient(t)
	t.Cleanup(func() {
		_ = database.DeleteClient(context.Background(), nil, rowA.Id)
		_ = database.DeleteClient(context.Background(), nil, rowB.Id)
	})

	aHeld := make(chan struct{})
	bHeld := make(chan struct{})
	var closeA, closeB sync.Once
	var attempts atomic.Int32

	party := func(db data.Database, first, second *record.Client, held *sync.Once, mine, theirs chan struct{}) error {
		return db.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
			attempts.Add(1)
			if err := db.AcquireClientRow(context.Background(), tx, first.Id); err != nil {
				return err
			}
			held.Do(func() { close(mine) })
			select {
			case <-theirs:
			case <-time.After(deadlockCeiling):
				return errors.New("the other party never took its first row")
			}
			return db.AcquireClientRow(context.Background(), tx, second.Id)
		})
	}

	otherDone := make(chan error, 1)
	go func() { otherDone <- party(other, rowB, rowA, &closeB, bHeld, aHeld) }()
	errMain := party(database, rowA, rowB, &closeA, aHeld, bHeld)

	var errOther error
	select {
	case errOther = <-otherDone:
	case <-time.After(deadlockCeiling):
		t.Fatal("the second party never returned: the deadlock was neither broken by the engine nor resolved by the retry")
	}

	require.NoError(t, errMain, "the party on the package handle finished, whether it was the victim or the survivor")
	require.NoError(t, errOther, "and so did the party on the second handle")
	assert.Equal(t, int32(3), attempts.Load(),
		"exactly one party was chosen as the victim and ran its body a second time; %d attempts in total", attempts.Load())

	for _, row := range []*record.Client{rowA, rowB} {
		got, err := database.GetClientById(context.Background(), nil, row.Id)
		require.NoError(t, err)
		assert.NotNil(t, got, "both rows are still there after both parties committed")
	}
}

// cancelledCommitRuns is how many runs the next test cancels. On SQL Server, a run whose commit
// rolled back on the caller's goroutine failed the next BEGIN in one or two runs of every hundred,
// so this many leave such a regression almost no chance of passing once the test runs there again.
const cancelledCommitRuns = 500

// TestRunInTransaction_ARunCancelledBeforeItsCommitLeavesTheNextTransactionAWorkingConnection
// cancels each run between its body and its commit, then opens the next transaction at once on
// the same goroutine, as a caller carrying on with a live context would. database/sql's goroutine
// rolls the cancelled run back while it holds the connection. When commondb rolled back on the
// caller's goroutine instead, go-mssqldb answered that rollback with the context's error before it
// had read the reply and kept the connection, so the next transaction drew it and its BEGIN failed
// with "Read: EOF" (#371). Every engine owes the same answer, but it is skipped on SQL Server until
// the driver is fixed; see the skip below.
func TestRunInTransaction_ARunCancelledBeforeItsCommitLeavesTheNextTransactionAWorkingConnection(t *testing.T) {
	// Skipped on SQL Server because of a driver bug that no Goiabada code can avoid.
	//
	// What happened: removing commondb's own rollback (#371) put this path back to what the code
	// did before #371. Commit does not ask the driver when the context is already done, and
	// database/sql's awaitDone goroutine makes the one rollback. In that state the test passed
	// 3,000 runs on the dev container's SQL Server, but CI's failed at run 110 with the same
	// "unable to begin transaction: Read: EOF". The driver still has the race: awaitDone's
	// (*mssql.Conn).Rollback returns before its response reader has finished, database/sql puts
	// the connection back in the pool, and the next checkout collides with that reader. Here that
	// checkout is the next BEGIN. It depends on timing, so a slower runner hits it and a faster
	// one rarely does. The code before #371 has the same exposure, since database/sql's Tx.Commit
	// never asks the driver on a done context either.
	//
	// Upstream: https://github.com/microsoft/go-mssqldb/issues/390 reports the race, still open
	// and still reproduced on v1.11.2, the version src/authserver/go.mod pins.
	// https://github.com/microsoft/go-mssqldb/pull/486 fixes it: Rollback drains the reply on
	// context.Canceled, and on a deadline it marks the connection bad.
	//
	// To re-enable: once a go-mssqldb release includes #486, or an equivalent fix, bump it in
	// go.mod and delete this skip. Then run the test on SQL Server several times
	// (stack.sh run --type data --db mssql --run '<this test>'), and once in CI, before trusting
	// it. Do not make the test pass on SQL Server by retrying the BEGIN or tolerating EOF: that
	// would also hide the regression it exists to catch, a rollback on the caller's goroutine,
	// which hits the same EOF far more often.
	if dbType() == data.MSSQL {
		t.Skip("go-mssqldb v1.11.2 returns a connection to the pool while a cancelled rollback's reply " +
			"is still being read, so the next BEGIN can fail with EOF whatever commondb does: " +
			"https://github.com/microsoft/go-mssqldb/issues/390, fixed by " +
			"https://github.com/microsoft/go-mssqldb/pull/486, not yet released")
	}
	for i := range cancelledCommitRuns {
		ctx, cancel := context.WithCancel(context.Background())
		err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			if _, readErr := database.GetSettingsById(ctx, tx, 1); readErr != nil {
				return readErr
			}
			cancel()
			return nil
		})
		cancel()
		require.ErrorIs(t, err, context.Canceled, "run %d: the cancelled run answers with the context's error", i)
		require.NotErrorIs(t, err, data.ErrCommitOutcomeUnknown,
			"run %d: its commit was refused before the driver was asked, so its outcome is known", i)

		err = database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
			_, readErr := database.GetSettingsById(context.Background(), tx, 1)
			return readErr
		})
		require.NoError(t, err, "run %d: the transaction after a cancelled one opens and runs", i)
	}
}
