package commondb

import (
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file pins RunInTransaction's contract against the scripted driver, which is the only
// place the ATTEMPT COUNT, the backoff, the warning and the already-rolled-back victim can be
// observed: a real engine reports the outcome of a transaction and nothing about how many times
// the helper asked for one. The other half of the seam, that the same helper does the same thing
// against the four real engines and their real deadlock errors, is the data tier's
// (authserver/tests/data/run_in_transaction_test.go), and the per-driver classification of what
// IS a deadlock is each dialect package's own table.
//
// The classifier here is a test one, matching a sentinel with errors.Is, so these cases say
// nothing about any driver's error type. What they hold is the loop around the classifier: how
// many attempts, which errors are retried, which are returned as they were, and what a retry
// costs in time and in noise.

// errDeadlock stands in for the engine aborting a transaction as a deadlock victim.
var errDeadlock = errors.New("the engine chose this transaction as the deadlock victim")

// retryWarning is the text RunInTransaction logs once per rerun.
const retryWarning = "rerunning a transaction"

// retryingDB is the scripted database with the sentinel installed as its deadlock.
func retryingDB(t *testing.T, d *scriptedDriver) *CommonDatabase {
	t.Helper()
	db := scriptedDB(t, d)
	db.IsDeadlock = func(err error) bool { return errors.Is(err, errDeadlock) }
	return db
}

// recordBackoff swaps the helper's sleep for one that records what was asked of it, so the
// assertion is on the durations REQUESTED and never on the wall clock: a scheduler pause longer
// than 75ms inside the first interval would otherwise reverse a comparison of two measured gaps
// on a helper that is correct.
func recordBackoff(t *testing.T) *[]time.Duration {
	t.Helper()
	requested := []time.Duration{}
	previous := sleep
	sleep = func(d time.Duration) { requested = append(requested, d) }
	t.Cleanup(func() { sleep = previous })
	return &requested
}

// retryWarnings counts the reruns the helper announced.
func retryWarnings(logs *capturedLogs) int {
	n := 0
	for _, m := range logs.messagesAt(slog.LevelWarn) {
		if strings.Contains(m, retryWarning) {
			n++
		}
	}
	return n
}

// oneStatement is a body that issues one write on the transaction it was handed and returns
// whatever the driver answered, which is how a scripted failure reaches the helper by the path a
// real one takes: through ExecSql's wrapping, not as a bare sentinel.
func oneStatement(db *CommonDatabase, ran *int) func(tx *sql.Tx) error {
	return func(tx *sql.Tx) error {
		*ran++
		_, err := db.ExecSql(tx, "UPDATE settings SET updated_at = updated_at")
		return err
	}
}

func TestRunInTransaction_ASuccessfulBodyCommitsOnce(t *testing.T) {
	logs := captureLogs(t)
	requested := recordBackoff(t)
	d := &scriptedDriver{}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(oneStatement(db, &ran))

	require.NoError(t, err)
	assert.Equal(t, 1, ran, "the body runs exactly once when it succeeds")
	assert.Equal(t, 1, d.commits, "and its transaction is committed")
	assert.Zero(t, d.rollbacks)
	assert.Zero(t, d.openTx, "nothing is left open")
	assert.Empty(t, *requested, "nothing precedes the first attempt")
	assert.Zero(t, retryWarnings(logs), "a success is not worth a warning")
}

func TestRunInTransaction_APlainErrorRollsBackAndIsReturnedAsItWas(t *testing.T) {
	logs := captureLogs(t)
	requested := recordBackoff(t)
	boom := errors.New("connection reset by peer")
	d := &scriptedDriver{}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(func(tx *sql.Tx) error {
		ran++
		return boom
	})

	require.Error(t, err)
	assert.Equal(t, boom, err, "the body's error comes back IDENTICAL, not wrapped: callers match it with errors.Is and read it as they wrote it")
	assert.Equal(t, 1, ran, "an error that is not a deadlock is not retried")
	assert.Equal(t, 1, d.rollbacks, "the transaction is rolled back")
	assert.Zero(t, d.commits)
	assert.Zero(t, d.openTx)
	assert.Empty(t, *requested)
	assert.Zero(t, retryWarnings(logs))
}

func TestRunInTransaction_ADeadlockInTheBodyIsRerunAndTheRerunCommits(t *testing.T) {
	logs := captureLogs(t)
	requested := recordBackoff(t)
	// The first attempt's statement is the engine's deadlock abort; the second is answered
	// cleanly by running past the end of the script.
	d := &scriptedDriver{execs: []*scriptedExec{{err: errDeadlock}}}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(oneStatement(db, &ran))

	require.NoError(t, err, "the second attempt succeeded, so the call does")
	assert.Equal(t, 2, ran, "two attempts")
	assert.Equal(t, 1, d.rollbacks, "the aborted attempt was rolled back")
	assert.Equal(t, 1, d.commits, "and the rerun committed")
	assert.Zero(t, d.openTx)
	assert.Equal(t, []time.Duration{25 * time.Millisecond}, *requested, "one pause, before the second attempt")
	assert.Equal(t, 1, retryWarnings(logs), "exactly one warning, for the one rerun")
}

func TestRunInTransaction_ThreeDeadlocksExhaustTheAttemptsAndTheLastOneSurfaces(t *testing.T) {
	logs := captureLogs(t)
	requested := recordBackoff(t)
	d := &scriptedDriver{execs: []*scriptedExec{{err: errDeadlock}, {err: errDeadlock}, {err: errDeadlock}}}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(oneStatement(db, &ran))

	require.Error(t, err)
	assert.ErrorIs(t, err, errDeadlock, "the error unwraps to the last deadlock, so the caller can still see what it was")
	assert.Contains(t, err.Error(), "all 3 attempts", "and says the attempts were spent")
	assert.Equal(t, 3, ran, "three attempts, no more")
	assert.Equal(t, 3, d.rollbacks)
	assert.Zero(t, d.commits, "nothing was ever committed")
	assert.Zero(t, d.openTx)
	assert.Equal(t, []time.Duration{25 * time.Millisecond, 100 * time.Millisecond}, *requested,
		"the backoff before attempts two and three, in that order, and nothing before the first")
	assert.Equal(t, 2, retryWarnings(logs), "one warning per rerun")
}

// TestRunInTransaction_AVictimTheEngineAlreadyRolledBackIsStillRerun is MySQL's shape. InnoDB
// rolls the victim back itself and the client's ROLLBACK then has nothing to do; some paths
// report that as an error. A helper that returned the rollback's error would replace the
// deadlock, which is the error that decides whether to retry, with a bookkeeping one, and the
// retry would never happen. This is the case that fails if rollback errors are returned.
func TestRunInTransaction_AVictimTheEngineAlreadyRolledBackIsStillRerun(t *testing.T) {
	rolledBackAlready := errors.New("Error 1213: this transaction was already rolled back")
	d := &scriptedDriver{
		execs:        []*scriptedExec{{err: errDeadlock}, {err: errDeadlock}, {err: errDeadlock}},
		rollbackErrs: []error{rolledBackAlready, rolledBackAlready, rolledBackAlready},
	}
	db := retryingDB(t, d)
	recordBackoff(t)
	ran := 0

	err := db.RunInTransaction(oneStatement(db, &ran))

	require.Error(t, err)
	assert.Equal(t, 3, ran, "the rollback's complaint does not stop the rerun")
	assert.ErrorIs(t, err, errDeadlock, "and what surfaces at exhaustion is the deadlock")
	assert.NotErrorIs(t, err, rolledBackAlready, "never the rollback failure")
}

func TestRunInTransaction_ADeadlockAtCommitIsRerunAndTheRerunCommits(t *testing.T) {
	logs := captureLogs(t)
	requested := recordBackoff(t)
	// The body succeeds both times; it is the COMMIT that the engine aborts on the first.
	d := &scriptedDriver{commitErrs: []error{errDeadlock}}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(oneStatement(db, &ran))

	require.NoError(t, err, "the second commit went through, so the call succeeds")
	assert.Equal(t, 2, ran, "two attempts")
	assert.Equal(t, 2, d.commits, "two commits asked for, the first refused")
	assert.Zero(t, d.rollbacks, "a transaction whose commit failed is finished; database/sql refuses a rollback after it and none is attempted")
	assert.Zero(t, d.openTx)
	assert.Equal(t, []time.Duration{25 * time.Millisecond}, *requested)
	assert.Equal(t, 1, retryWarnings(logs))
}

func TestRunInTransaction_ThreeDeadlocksAtCommitExhaustTheAttempts(t *testing.T) {
	recordBackoff(t)
	d := &scriptedDriver{commitErrs: []error{errDeadlock, errDeadlock, errDeadlock}}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(oneStatement(db, &ran))

	require.Error(t, err)
	assert.ErrorIs(t, err, errDeadlock)
	assert.Equal(t, 3, ran)
	assert.Equal(t, 3, d.commits)
}

// TestRunInTransaction_ACommitThatFailsForAnyOtherReasonIsNotReplayed holds the decided line
// between an abort the engine DECLARED, which is known to have rolled back, and a commit whose
// outcome the client cannot know: the server may have committed before the failure reached the
// client, and replaying the body would apply it twice.
func TestRunInTransaction_ACommitThatFailsForAnyOtherReasonIsNotReplayed(t *testing.T) {
	logs := captureLogs(t)
	requested := recordBackoff(t)
	boom := errors.New("write: broken pipe")
	d := &scriptedDriver{commitErrs: []error{boom}}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(oneStatement(db, &ran))

	require.Error(t, err)
	assert.ErrorIs(t, err, boom, "the commit's own failure comes back")
	assert.NotContains(t, err.Error(), "attempts", "with no retry wrapping, because there was no retry")
	assert.Equal(t, 1, ran, "ONE attempt")
	assert.Equal(t, 1, d.commits)
	assert.Empty(t, *requested)
	assert.Zero(t, retryWarnings(logs))
}

func TestRunInTransaction_APanicInTheBodyPropagatesAndLeavesNoOpenTransaction(t *testing.T) {
	d := &scriptedDriver{}
	db := retryingDB(t, d)

	require.PanicsWithValue(t, "the body blew up", func() {
		_ = db.RunInTransaction(func(tx *sql.Tx) error {
			panic("the body blew up")
		})
	}, "the panic is the caller's to see, not something the helper swallows")

	assert.Equal(t, 1, d.rollbacks, "the transaction was rolled back on the way out")
	assert.Zero(t, d.commits)
	assert.Zero(t, d.openTx, "so nothing holds its locks until the pool closes the connection")
}

// TestRunInTransaction_WithNoClassifierNothingIsADeadlock is the default a handle gets when no
// dialect installed a classifier, which is every CommonDatabase built directly in a test and
// any future embedder that forgets: today's behaviour, one attempt, the error as it was.
func TestRunInTransaction_WithNoClassifierNothingIsADeadlock(t *testing.T) {
	requested := recordBackoff(t)
	d := &scriptedDriver{}
	db := scriptedDB(t, d)
	require.Nil(t, db.IsDeadlock, "the fixture only says anything if no classifier is installed")
	ran := 0

	err := db.RunInTransaction(func(tx *sql.Tx) error {
		ran++
		return errDeadlock
	})

	require.Error(t, err)
	assert.Equal(t, errDeadlock, err, "returned as it was")
	assert.Equal(t, 1, ran, "after one attempt")
	assert.Equal(t, 1, d.rollbacks)
	assert.Empty(t, *requested)
}

// TestInTransaction_OnlyTheOwnerRetries pins which half of inTransaction retries. Handed no
// transaction it is the owner and goes through RunInTransaction; handed one it is a nested
// callee, and a deadlock inside it has to reach the owner untouched, because the owner's rerun
// covers the whole body and a callee that retried on its own would rerun a fragment of it
// inside a transaction the engine has already rolled back.
func TestInTransaction_OnlyTheOwnerRetries(t *testing.T) {
	recordBackoff(t)

	t.Run("handed nil, it owns the transaction and retries", func(t *testing.T) {
		d := &scriptedDriver{execs: []*scriptedExec{{err: errDeadlock}}}
		db := retryingDB(t, d)
		ran := 0

		err := db.inTransaction(nil, oneStatement(db, &ran))

		require.NoError(t, err)
		assert.Equal(t, 2, ran, "the deadlock was retried")
		assert.Equal(t, 1, d.commits)
	})

	t.Run("handed a transaction, it runs once and returns the deadlock to the owner", func(t *testing.T) {
		d := &scriptedDriver{execs: []*scriptedExec{{err: errDeadlock}}}
		db := retryingDB(t, d)
		tx, err := db.BeginTransaction()
		require.NoError(t, err)
		ran := 0

		err = db.inTransaction(tx, oneStatement(db, &ran))

		require.Error(t, err)
		assert.ErrorIs(t, err, errDeadlock, "the owner gets the deadlock and decides")
		assert.Equal(t, 1, ran, "no retry from inside a transaction it does not own")
		assert.Zero(t, d.commits, "and it neither commits nor rolls back what is not its own")
		assert.Zero(t, d.rollbacks)
		require.NoError(t, db.RollbackTransaction(tx))
	})
}
