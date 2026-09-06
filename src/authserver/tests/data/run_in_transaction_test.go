package datatests

import (
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RunInTransaction against the real engines. The attempt count, the backoff and the warning
// are the scripted driver's to pin (core/data/commondb/run_in_transaction_test.go); what only a
// real engine can answer is whether the rows end up where the contract says, and whether the
// dialect's classifier recognises the deadlock its own driver actually raises. The last case
// here is the smallest deadlock that can be forced, two rows taken in opposite orders, and it
// is the shape the production-pair tests build on (#301).

// deadlockCeiling bounds the forced deadlock. PostgreSQL looks for cycles after deadlock_timeout,
// one second by default; SQL Server's monitor runs every five seconds; InnoDB detects at once.
// The ceiling is far above all three so a slow engine is never mistaken for a broken retry.
const deadlockCeiling = 60 * time.Second

// newClientModel is a client that has not been inserted, for bodies that insert it themselves.
func newClientModel() *models.Client {
	return &models.Client{
		ClientIdentifier: "rit_client_" + gofakeit.LetterN(8),
		Description:      "RunInTransaction test client",
	}
}

func TestRunInTransaction_ABodyThatReturnsNilIsCommittedAndItsRowsAreVisible(t *testing.T) {
	client := newClientModel()

	err := database.RunInTransaction(func(tx *sql.Tx) error {
		return database.CreateClient(tx, client)
	})

	require.NoError(t, err)
	require.NotZero(t, client.Id)
	t.Cleanup(func() { _ = database.DeleteClient(nil, client.Id) })

	got, err := database.GetClientById(nil, client.Id)
	require.NoError(t, err)
	require.NotNil(t, got, "the row is visible through the pool after the helper returned, so it was committed")
	assert.Equal(t, client.ClientIdentifier, got.ClientIdentifier)
}

func TestRunInTransaction_ABodyThatReturnsAnErrorIsRolledBackAndTheErrorComesBackUnchanged(t *testing.T) {
	client := newClientModel()
	refused := errors.New("the body decided against it")

	err := database.RunInTransaction(func(tx *sql.Tx) error {
		if err := database.CreateClient(tx, client); err != nil {
			return err
		}
		// Enlisted: the insert is visible on the transaction that made it, which is what a
		// write handed nil instead of tx would not show from here, having autocommitted.
		inside, err := database.GetClientById(tx, client.Id)
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

	got, err := database.GetClientById(nil, client.Id)
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
	if dbType() == "sqlite" || dbType() == "" {
		t.Skip("SQLite's pool has one connection, so two transactions cannot overlap and nothing can deadlock")
	}

	// The second handle first, before anything is held: see secondDatabase for why.
	other := secondDatabase(t)

	rowA := createTestClient(t)
	rowB := createTestClient(t)
	t.Cleanup(func() {
		_ = database.DeleteClient(nil, rowA.Id)
		_ = database.DeleteClient(nil, rowB.Id)
	})

	aHeld := make(chan struct{})
	bHeld := make(chan struct{})
	var closeA, closeB sync.Once
	var attempts atomic.Int32

	party := func(db data.Database, first, second *models.Client, held *sync.Once, mine, theirs chan struct{}) error {
		return db.RunInTransaction(func(tx *sql.Tx) error {
			attempts.Add(1)
			if err := db.AcquireClientRow(tx, first.Id); err != nil {
				return err
			}
			held.Do(func() { close(mine) })
			select {
			case <-theirs:
			case <-time.After(deadlockCeiling):
				return errors.New("the other party never took its first row")
			}
			return db.AcquireClientRow(tx, second.Id)
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

	for _, row := range []*models.Client{rowA, rowB} {
		got, err := database.GetClientById(nil, row.Id)
		require.NoError(t, err)
		assert.NotNil(t, got, "both rows are still there after both parties committed")
	}
}
