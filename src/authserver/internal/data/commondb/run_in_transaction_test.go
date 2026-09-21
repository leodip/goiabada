package commondb

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/testutil"
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
	swapSleep(t, func(_ context.Context, d time.Duration) error {
		requested = append(requested, d)
		return nil
	})
	return &requested
}

// swapSleep installs a backoff for the duration of one test and puts the real one back. It is
// separate from recordBackoff because the cancellation case needs the REAL wait, with a cancel
// fired at it, so that the select on ctx.Done() is the thing under test rather than a stub
// imitating its answer.
func swapSleep(t *testing.T, replacement func(context.Context, time.Duration) error) {
	t.Helper()
	previous := sleep
	sleep = replacement
	t.Cleanup(func() { sleep = previous })
}

// retryWarnings counts the reruns the helper announced.
func retryWarnings(logs *testutil.SlogCapture) int {
	return warningsContaining(logs, retryWarning)
}

// rollbackWarning is the opener of the record the deferred rollback writes when the rollback it
// asked for answered with something other than success.
const rollbackWarning = "rolling back a failed transaction reported an error"

// rollbackWarnings counts those records, which is the only observable the deferred rollback's
// error arm has: it returns nothing and changes nothing the caller can see.
func rollbackWarnings(logs *testutil.SlogCapture) int {
	return warningsContaining(logs, rollbackWarning)
}

func warningsContaining(logs *testutil.SlogCapture, text string) int {
	n := 0
	for _, m := range messagesAt(logs, slog.LevelWarn) {
		if strings.Contains(m, text) {
			n++
		}
	}
	return n
}

// oneStatement is a body that issues one write on the transaction it was handed and returns
// whatever the driver answered, which is how a scripted failure reaches the helper by the path a
// real one takes: through ExecSql's wrapping, not as a bare sentinel.
func oneStatement(db *CommonDatabase, ran *int) func(tx *sql.Tx) error {
	return oneStatementOn(context.Background(), db, ran)
}

// oneStatementOn is oneStatement with the statement issued on a context of the caller's choosing,
// which is what the cancelled-inside-the-body case needs: the migration's end state is a body
// whose statements run on the same context RunInTransaction was given, and the exit being pinned
// is the one where the cancellation lands between the BEGIN and the statement.
func oneStatementOn(ctx context.Context, db *CommonDatabase, ran *int) func(tx *sql.Tx) error {
	return func(tx *sql.Tx) error {
		*ran++
		_, err := db.ExecSql(ctx, tx, "UPDATE settings SET updated_at = updated_at")
		return err
	}
}

func TestRunInTransaction_ASuccessfulBodyCommitsOnce(t *testing.T) {
	logs := testutil.CaptureSlog(t)
	requested := recordBackoff(t)
	d := &scriptedDriver{}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(context.Background(), oneStatement(db, &ran))

	require.NoError(t, err)
	assert.Equal(t, 1, ran, "the body runs exactly once when it succeeds")
	c := d.settled(t)
	assert.Equal(t, 1, c.commits, "and its transaction is committed")
	assert.Zero(t, c.rollbacks)
	assert.Zero(t, c.openTx, "nothing is left open")
	assert.Empty(t, *requested, "nothing precedes the first attempt")
	assert.Zero(t, retryWarnings(logs), "a success is not worth a warning")
}

func TestRunInTransaction_APlainErrorRollsBackAndIsReturnedAsItWas(t *testing.T) {
	logs := testutil.CaptureSlog(t)
	requested := recordBackoff(t)
	boom := errors.New("connection reset by peer")
	d := &scriptedDriver{}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		ran++
		return boom
	})

	require.Error(t, err)
	assert.Equal(t, boom, err, "the body's error comes back IDENTICAL, not wrapped: callers match it with errors.Is and read it as they wrote it")
	assert.Equal(t, 1, ran, "an error that is not a deadlock is not retried")
	c := d.settled(t)
	assert.Equal(t, 1, c.rollbacks, "the transaction is rolled back")
	assert.Zero(t, c.commits)
	assert.Zero(t, c.openTx)
	assert.Empty(t, *requested)
	assert.Zero(t, retryWarnings(logs))
}

func TestRunInTransaction_ADeadlockInTheBodyIsRerunAndTheRerunCommits(t *testing.T) {
	logs := testutil.CaptureSlog(t)
	requested := recordBackoff(t)
	// The first attempt's statement is the engine's deadlock abort; the second is answered
	// cleanly by running past the end of the script.
	d := &scriptedDriver{execs: []*scriptedExec{{err: errDeadlock}}}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(context.Background(), oneStatement(db, &ran))

	require.NoError(t, err, "the second attempt succeeded, so the call does")
	assert.Equal(t, 2, ran, "two attempts")
	c := d.settled(t)
	assert.Equal(t, 1, c.rollbacks, "the aborted attempt was rolled back")
	assert.Equal(t, 1, c.commits, "and the rerun committed")
	assert.Zero(t, c.openTx)
	assert.Equal(t, []time.Duration{25 * time.Millisecond}, *requested, "one pause, before the second attempt")
	assert.Equal(t, 1, retryWarnings(logs), "exactly one warning, for the one rerun")
}

func TestRunInTransaction_ThreeDeadlocksExhaustTheAttemptsAndTheLastOneSurfaces(t *testing.T) {
	logs := testutil.CaptureSlog(t)
	requested := recordBackoff(t)
	d := &scriptedDriver{execs: []*scriptedExec{{err: errDeadlock}, {err: errDeadlock}, {err: errDeadlock}}}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(context.Background(), oneStatement(db, &ran))

	require.Error(t, err)
	assert.ErrorIs(t, err, errDeadlock, "the error unwraps to the last deadlock, so the caller can still see what it was")
	assert.Contains(t, err.Error(), "all 3 attempts", "and says the attempts were spent")
	assert.Equal(t, 3, ran, "three attempts, no more")
	c := d.settled(t)
	assert.Equal(t, 3, c.rollbacks)
	assert.Zero(t, c.commits, "nothing was ever committed")
	assert.Zero(t, c.openTx)
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
	logs := testutil.CaptureSlog(t)
	rolledBackAlready := errors.New("Error 1213: this transaction was already rolled back")
	d := &scriptedDriver{
		execs:        []*scriptedExec{{err: errDeadlock}, {err: errDeadlock}, {err: errDeadlock}},
		rollbackErrs: []error{rolledBackAlready, rolledBackAlready, rolledBackAlready},
	}
	db := retryingDB(t, d)
	recordBackoff(t)
	ran := 0

	err := db.RunInTransaction(context.Background(), oneStatement(db, &ran))

	require.Error(t, err)
	assert.Equal(t, 3, ran, "the rollback's complaint does not stop the rerun")
	assert.ErrorIs(t, err, errDeadlock, "and what surfaces at exhaustion is the deadlock")
	assert.NotErrorIs(t, err, rolledBackAlready, "never the rollback failure")
	assert.Equal(t, 3, rollbackWarnings(logs),
		"a rollback that failed on a LIVE context is still recorded, once per attempt; this is the negative that keeps the cancelled-transaction suppression narrow")
}

func TestRunInTransaction_ADeadlockAtCommitIsRerunAndTheRerunCommits(t *testing.T) {
	logs := testutil.CaptureSlog(t)
	requested := recordBackoff(t)
	// The body succeeds both times; it is the COMMIT that the engine aborts on the first.
	d := &scriptedDriver{commitErrs: []error{errDeadlock}}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(context.Background(), oneStatement(db, &ran))

	require.NoError(t, err, "the second commit went through, so the call succeeds")
	assert.Equal(t, 2, ran, "two attempts")
	c := d.settled(t)
	assert.Equal(t, 2, c.commits, "two commits asked for, the first refused")
	assert.Zero(t, c.rollbacks, "a transaction whose commit failed is finished; database/sql refuses a rollback after it and none is attempted")
	assert.Zero(t, c.openTx)
	assert.Equal(t, []time.Duration{25 * time.Millisecond}, *requested)
	assert.Equal(t, 1, retryWarnings(logs))
}

func TestRunInTransaction_ThreeDeadlocksAtCommitExhaustTheAttempts(t *testing.T) {
	recordBackoff(t)
	d := &scriptedDriver{commitErrs: []error{errDeadlock, errDeadlock, errDeadlock}}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(context.Background(), oneStatement(db, &ran))

	require.Error(t, err)
	assert.ErrorIs(t, err, errDeadlock)
	assert.Equal(t, 3, ran)
	assert.Equal(t, 3, d.settled(t).commits)
}

// TestRunInTransaction_ACommitThatFailsForAnyOtherReasonIsNotReplayed holds the decided line
// between an abort the engine DECLARED, which is known to have rolled back, and a commit whose
// outcome the client cannot know: the server may have committed before the failure reached the
// client, and replaying the body would apply it twice.
func TestRunInTransaction_ACommitThatFailsForAnyOtherReasonIsNotReplayed(t *testing.T) {
	logs := testutil.CaptureSlog(t)
	requested := recordBackoff(t)
	boom := errors.New("write: broken pipe")
	d := &scriptedDriver{commitErrs: []error{boom}}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(context.Background(), oneStatement(db, &ran))

	require.Error(t, err)
	assert.ErrorIs(t, err, boom, "the commit's own failure comes back")
	assert.NotContains(t, err.Error(), "attempts", "with no retry wrapping, because there was no retry")
	assert.Equal(t, 1, ran, "ONE attempt")
	assert.Equal(t, 1, d.settled(t).commits)
	assert.Empty(t, *requested)
	assert.Zero(t, retryWarnings(logs))
}

func TestRunInTransaction_APanicInTheBodyPropagatesAndLeavesNoOpenTransaction(t *testing.T) {
	d := &scriptedDriver{}
	db := retryingDB(t, d)

	require.PanicsWithValue(t, "the body blew up", func() {
		_ = db.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
			panic("the body blew up")
		})
	}, "the panic is the caller's to see, not something the helper swallows")

	c := d.settled(t)
	assert.Equal(t, 1, c.rollbacks, "the transaction was rolled back on the way out")
	assert.Zero(t, c.commits)
	assert.Zero(t, c.openTx, "so nothing holds its locks until the pool closes the connection")
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

	err := db.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		ran++
		return errDeadlock
	})

	require.Error(t, err)
	assert.Equal(t, errDeadlock, err, "returned as it was")
	assert.Equal(t, 1, ran, "after one attempt")
	assert.Equal(t, 1, d.settled(t).rollbacks)
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

		err := db.inTransaction(context.Background(), nil, oneStatement(db, &ran))

		require.NoError(t, err)
		assert.Equal(t, 2, ran, "the deadlock was retried")
		assert.Equal(t, 1, d.settled(t).commits)
	})

	t.Run("handed a transaction, it runs once and returns the deadlock to the owner", func(t *testing.T) {
		d := &scriptedDriver{execs: []*scriptedExec{{err: errDeadlock}}}
		db := retryingDB(t, d)
		tx, err := db.BeginTransaction(context.Background())
		require.NoError(t, err)
		ran := 0

		err = db.inTransaction(context.Background(), tx, oneStatement(db, &ran))

		require.Error(t, err)
		assert.ErrorIs(t, err, errDeadlock, "the owner gets the deadlock and decides")
		assert.Equal(t, 1, ran, "no retry from inside a transaction it does not own")
		held := d.counts()
		assert.Zero(t, held.commits, "and it neither commits nor rolls back what is not its own")
		assert.Zero(t, held.rollbacks)
		require.NoError(t, db.RollbackTransaction(tx))
	})
}

// THE FOUR CANCELLATION EXITS, decision 13 of #386.
//
// A transaction helper that reruns a body has four places a cancellation can arrive: before the
// first attempt, inside the body, inside the pause between attempts, and between a deadlock and
// the rerun it triggered. Each is below, and each asserts the error IDENTITY it produces rather
// than merely that something failed, because the whole of the decision is which error wins and
// what stays reachable beside it.
//
// The scripted driver is the only seam where these are observable: a real engine reports the
// outcome of a transaction and nothing about how many attempts asked for one. It answers them
// truthfully only because it implements ConnBeginTx, StmtExecContext and StmtQueryContext --
// probe/driverfallback measured a legacy driver ignoring a 100ms deadline for 700ms and
// reporting no error at all, against which every case here would pass on a helper that dropped
// the context on the floor.

func TestRunInTransaction_ACancelledContextIsRefusedBeforeTheFirstAttempt(t *testing.T) {
	requested := recordBackoff(t)
	d := &scriptedDriver{}
	db := retryingDB(t, d)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ran := 0

	err := db.RunInTransaction(ctx, oneStatement(db, &ran))

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled, "the context error is what the caller matches on")
	assert.Zero(t, ran, "the body never ran")
	c := d.settled(t)
	assert.Zero(t, c.openTx, "and no transaction was ever opened")
	assert.Zero(t, c.commits)
	assert.Zero(t, c.rollbacks)
	assert.Empty(t, *requested, "nothing precedes the first attempt, cancelled or not")
}

// TestRunInTransaction_ADeadlineInsideTheBodyComesBackUnretried is the exit that does NOT go
// through abandoned: the statement's own context error is not a deadlock, so the ordinary
// not-a-deadlock arm returns it after one attempt. Asserted because the alternative -- a helper
// that classified a context error as retryable -- would spend three attempts and two backoffs on
// a caller that has already gone.
func TestRunInTransaction_ADeadlineInsideTheBodyComesBackUnretried(t *testing.T) {
	requested := recordBackoff(t)
	// The statement takes longer than the deadline allows, interruptibly.
	d := &scriptedDriver{execs: []*scriptedExec{{delay: 2 * time.Second}}}
	db := retryingDB(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	ran := 0

	err := db.RunInTransaction(ctx, oneStatementOn(ctx, db, &ran))

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded, "the deadline the statement met is what surfaces")
	assert.Equal(t, 1, ran, "one attempt: a context error is not a deadlock and is not rerun")
	c := d.settled(t)
	assert.Equal(t, 1, c.rollbacks, "the open transaction was rolled back on the way out")
	assert.Zero(t, c.commits)
	assert.Zero(t, c.openTx)
	assert.Empty(t, *requested, "and no backoff was spent on it")
}

// TestRunInTransaction_ACancelledTransactionsRollbackIsNotRecordedAsAFailure is the log half of
// the case above, and it is a consequence of BeginTx that BeginTransaction's own tests cannot
// see. database/sql starts a goroutine at BeginTx that rolls the transaction back as soon as the
// context is done, so the deferred rollback in runTransactionOnce arrives second and is answered
// with sql.ErrTxDone. Nothing failed -- the rollback the caller needed already happened -- and
// recording it would put a warning in the log for every cancelled request that was inside a
// transaction, which is an operator sent after a non-event (#386).
func TestRunInTransaction_ACancelledTransactionsRollbackIsNotRecordedAsAFailure(t *testing.T) {
	logs := testutil.CaptureSlog(t)
	recordBackoff(t)
	d := &scriptedDriver{execs: []*scriptedExec{{delay: 2 * time.Second}}}
	db := retryingDB(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	ran := 0

	err := db.RunInTransaction(ctx, oneStatementOn(ctx, db, &ran))

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded, "the deadline is still what the caller gets")
	assert.Zero(t, rollbackWarnings(logs),
		"the transaction database/sql had already rolled back is not a rollback failure")
	assert.Equal(t, 1, d.settled(t).rollbacks, "and it was rolled back exactly once")
}

// TestRunInTransaction_AnAlreadyDoneRollbackOnALiveContextIsStillRecorded is the other side of
// that suppression, and the reason it is written as two conditions rather than one. ErrTxDone
// with no cancellation to explain it means the transaction was finished by something other than
// this helper, which is a defect and not a non-event, so it keeps its record. Suppressing on the
// error alone would have swallowed it (#386).
func TestRunInTransaction_AnAlreadyDoneRollbackOnALiveContextIsStillRecorded(t *testing.T) {
	logs := testutil.CaptureSlog(t)
	recordBackoff(t)
	boom := errors.New("connection reset by peer")
	d := &scriptedDriver{
		execs:        []*scriptedExec{{err: boom}},
		rollbackErrs: []error{sql.ErrTxDone},
	}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(context.Background(), oneStatement(db, &ran))

	require.Error(t, err)
	assert.ErrorIs(t, err, boom, "the body's error is still what the caller gets")
	assert.Equal(t, 1, rollbackWarnings(logs),
		"a transaction that was already finished with nothing cancelled is worth the record")
}

// TestRunInTransaction_ACancellationDuringTheBackoffStopsTheRerun exercises the real select: the
// stub cancels and then delegates to the sleep the helper actually ships with, so what is under
// test is that wait's ctx.Done() arm and not a stub's imitation of it.
func TestRunInTransaction_ACancellationDuringTheBackoffStopsTheRerun(t *testing.T) {
	logs := testutil.CaptureSlog(t)
	d := &scriptedDriver{execs: []*scriptedExec{{err: errDeadlock}, {err: errDeadlock}}}
	db := retryingDB(t, d)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	realSleep := sleep
	requested := []time.Duration{}
	swapSleep(t, func(ctx context.Context, delay time.Duration) error {
		requested = append(requested, delay)
		cancel()
		return realSleep(ctx, delay)
	})
	ran := 0

	err := db.RunInTransaction(ctx, oneStatement(db, &ran))

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled, "the context error wins")
	assert.ErrorIs(t, err, errDeadlock, "and the deadlock that caused the retry is joined to it, not dropped")
	assert.Equal(t, 1, ran, "the rerun never happened")
	c := d.settled(t)
	assert.Equal(t, 1, c.rollbacks)
	assert.Zero(t, c.commits)
	assert.Equal(t, []time.Duration{25 * time.Millisecond}, requested,
		"the pause was entered, which is what makes this a cancellation DURING the backoff")
	assert.Zero(t, retryWarnings(logs), "a rerun that never happened is not announced")
}

// TestRunInTransaction_ACancellationBetweenADeadlockAndItsRerunStopsTheLoop is the other joined
// case, and the one the loop's own ctx.Err() check owns: the cancellation is already in force
// when the next iteration begins, so the helper stops before it even reaches the pause.
func TestRunInTransaction_ACancellationBetweenADeadlockAndItsRerunStopsTheLoop(t *testing.T) {
	logs := testutil.CaptureSlog(t)
	requested := recordBackoff(t)
	d := &scriptedDriver{execs: []*scriptedExec{{err: errDeadlock}, {err: errDeadlock}}}
	db := retryingDB(t, d)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := 0

	err := db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		ran++
		_, execErr := db.ExecSql(context.Background(), tx, "UPDATE settings SET updated_at = updated_at")
		// The caller goes away while the first attempt is being rolled back.
		cancel()
		return execErr
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.ErrorIs(t, err, errDeadlock, "errors.Is still reaches the engine's abort")
	assert.Equal(t, 1, ran, "one attempt, and no second one")
	assert.Empty(t, *requested, "the loop stopped before the pause, so no backoff was requested")
	assert.Zero(t, retryWarnings(logs))
}

// TestRunInTransaction_AnExhaustedRunIsStillTheDeadlockAndNotAContextError is the negative that
// makes the four above attributable. Decision 13 changes what a CANCELLED run returns and
// nothing else: three real deadlocks on a live context still answer exactly as they did, with
// the deadlock and the attempts-spent text and no context error anywhere in the tree.
func TestRunInTransaction_AnExhaustedRunIsStillTheDeadlockAndNotAContextError(t *testing.T) {
	recordBackoff(t)
	d := &scriptedDriver{execs: []*scriptedExec{{err: errDeadlock}, {err: errDeadlock}, {err: errDeadlock}}}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(context.Background(), oneStatement(db, &ran))

	require.Error(t, err)
	assert.ErrorIs(t, err, errDeadlock)
	assert.Contains(t, err.Error(), "all 3 attempts")
	assert.NotErrorIs(t, err, context.Canceled, "a live context contributes nothing to the error")
	assert.NotErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, 3, ran)
}

// TestRunInTransaction_OpensWithTheDefaultIsolationLevel pins the one thing BeginTx could have
// changed and did not. Nothing in this repository asks for an isolation level, and
// tests/data/rcsi_test.go's argument that SQL Server's error 3960 is unreachable rests on it.
func TestRunInTransaction_OpensWithTheDefaultIsolationLevel(t *testing.T) {
	d := &scriptedDriver{}
	db := retryingDB(t, d)
	ran := 0

	require.NoError(t, db.RunInTransaction(context.Background(), oneStatement(db, &ran)))

	require.Len(t, d.txOptions, 1)
	assert.Equal(t, sql.LevelDefault, sql.IsolationLevel(d.txOptions[0].Isolation),
		"BeginTx is called with nil options, which is LevelDefault")
	assert.False(t, d.txOptions[0].ReadOnly)
}
