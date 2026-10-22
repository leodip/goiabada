package commondb

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fifth cancellation exit, and the one the other four could not see.
//
// run_in_transaction_test.go pins the other five: cancelled before the first attempt, cancelled
// inside a statement, cancelled during the backoff, cancelled between a deadlock and its rerun,
// and cancelled inside a rerun. Each of those leaves fn with an error to return, so the context
// error is already in the tree by the time RunInTransaction looks at it. The fifth is the one where fn SUCCEEDS and the cancellation lands
// between its last statement and the commit, and there decision 13 was not being kept: database/sql
// starts a goroutine at BeginTx that rolls the transaction back as soon as the context is done, and
// Tx.Commit answers a finished transaction with sql.ErrTxDone, which matches neither
// context.Canceled nor context.DeadlineExceeded. The caller was handed "unable to commit
// transaction: sql: transaction has already been committed or rolled back" -- a bookkeeping
// sentinel with nothing in it about why -- for a run that was cancelled (#386 decision 13, final
// review round 1 finding 7).
//
// WHY IT WAS NOT MERELY UNTIDY. Tx.Commit races its own rollback goroutine: it checks the context
// first and returns ctx.Err() when the rollback has not finished and sql.ErrTxDone when it has. So
// a cancelled commit answered with the matchable error SOMETIMES, and which one a caller got was
// decided by goroutine scheduling. The tests below remove the race in both directions rather than
// asserting on whichever arm won.

// TestRunInTransaction_ACancellationAfterASuccessfulBodyReturnsTheContextError forces the losing
// arm: the body waits for the rollback goroutine to have finished before it returns, so Commit is
// guaranteed to find the transaction already done and answer sql.ErrTxDone.
func TestRunInTransaction_ACancellationAfterASuccessfulBodyReturnsTheContextError(t *testing.T) {
	d := &scriptedDriver{}
	db := retryingDB(t, d)
	requested := recordBackoff(db)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := 0

	err := db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		ran++
		if _, execErr := db.ExecSQL(ctx, tx, "UPDATE settings SET updated_at = updated_at"); execErr != nil {
			return execErr
		}
		cancel()
		// The wait is what makes this deterministic, and it is waiting for database/sql's own
		// goroutine rather than for a timer: once the driver has recorded the rollback, tx.done
		// is set and Commit has only one answer left to give.
		require.Eventually(t, func() bool { return d.counts().rollbacks == 1 },
			2*time.Second, time.Millisecond,
			"database/sql never rolled back the transaction whose context was cancelled")
		return nil
	})

	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled,
		"a cancelled run answers with the context error, whatever the commit reported (decision 13)")
	require.NotErrorIs(t, err, sql.ErrTxDone,
		"and not with the sentinel that says only that the transaction was already over")
	require.NotErrorIs(t, err, data.ErrCommitOutcomeUnknown,
		"and not tagged as an unknown outcome: no COMMIT reached the engine, so it was rolled back (#371)")
	assert.Equal(t, 1, ran, "one attempt: a cancelled run is not rerun")
	assert.Empty(t, *requested, "and no backoff was spent on it")
	c := d.settled(t)
	assert.Zero(t, c.openTx, "nothing was left open")
	assert.Zero(t, c.commits, "the driver was never asked to commit: database/sql refused before it")
}

// TestRunInTransaction_ACancellationAfterASuccessfulBodyJoinsTheDeadlockItWasRerunFor is the same
// exit reached after a deadlock, and it is what says the fix goes through abandoned() rather than
// past it: decision 13 keeps the engine's abort reachable beside the context error, and a run
// cancelled at the commit of its second attempt has one to keep.
func TestRunInTransaction_ACancellationAfterASuccessfulBodyJoinsTheDeadlockItWasRerunFor(t *testing.T) {
	d := &scriptedDriver{execs: []*scriptedExec{{err: errDeadlock}}}
	db := retryingDB(t, d)
	recordBackoff(db)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := 0

	err := db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		ran++
		_, execErr := db.ExecSQL(ctx, tx, "UPDATE settings SET updated_at = updated_at")
		if execErr != nil {
			return execErr
		}
		cancel()
		require.Eventually(t, func() bool { return d.counts().rollbacks == 2 },
			2*time.Second, time.Millisecond,
			"database/sql never rolled back the transaction whose context was cancelled")
		return nil
	})

	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled, "the context error is still what decided the outcome")
	require.ErrorIs(t, err, errDeadlock, "and the abort the helper was rerunning for stays reachable")
	require.NotErrorIs(t, err, data.ErrCommitOutcomeUnknown,
		"and the commit database/sql refused is not an unknown outcome (#371)")
	assert.Contains(t, err.Error(), "transaction abandoned after the engine aborted it")
	assert.Equal(t, 2, ran, "the deadlock was rerun once, and the rerun was the cancelled one")
}

// TestRunInTransaction_ACommitThatFindsTheTransactionDoneOnALiveContextIsStillTheSentinel is the
// negative that makes the two above attributable, and the reason the fix tests two conditions
// rather than one. sql.ErrTxDone with no cancellation to explain it means the transaction was
// finished by something other than this helper, which is a defect and not a cancellation, so it
// surfaces exactly as it did -- the same shape as the rollback suppression's own negative.
func TestRunInTransaction_ACommitThatFindsTheTransactionDoneOnALiveContextIsStillTheSentinel(t *testing.T) {
	d := &scriptedDriver{commitErrs: []error{sql.ErrTxDone}}
	db := retryingDB(t, d)
	recordBackoff(db)
	ran := 0

	err := db.RunInTransaction(context.Background(), oneStatement(db, &ran))

	require.Error(t, err)
	require.ErrorIs(t, err, sql.ErrTxDone, "a live context leaves the commit's own error alone")
	require.NotErrorIs(t, err, context.Canceled, "and contributes no context error")
	require.NotErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorIs(t, err, data.ErrCommitOutcomeUnknown,
		"and with no cancellation to explain it, whatever finished the transaction may have committed it (#371)")
	assert.Equal(t, 1, ran, "a commit failure that is not a deadlock is not replayed")
}

// TestRunInTransaction_ACancellationAfterASuccessfulBodyIsNeverAnUnknownOutcome leaves the race
// in, where the two tests above remove it: the body cancels and returns at once, so Tx.Commit
// answers the context's own error when its rollback goroutine has not finished and sql.ErrTxDone
// when it has. Neither asks the driver to commit, so the transaction is known to be rolled back
// whichever arm wins, and neither may carry data.ErrCommitOutcomeUnknown. Before the tag looked
// at what Tx.Commit answered, the context's-error arm carried it, and that arm wins nearly every
// time (#371).
func TestRunInTransaction_ACancellationAfterASuccessfulBodyIsNeverAnUnknownOutcome(t *testing.T) {
	for i := range 300 {
		d := &scriptedDriver{}
		db := retryingDB(t, d)
		recordBackoff(db)
		ctx, cancel := context.WithCancel(context.Background())

		err := db.RunInTransaction(ctx, func(tx *sql.Tx) error {
			if _, execErr := db.ExecSQL(ctx, tx, "UPDATE settings SET updated_at = updated_at"); execErr != nil {
				return execErr
			}
			cancel()
			return nil
		})
		cancel()

		run := fmt.Sprintf("run %d", i)
		require.Error(t, err, run)
		require.ErrorIs(t, err, context.Canceled, run)
		require.NotErrorIs(t, err, data.ErrCommitOutcomeUnknown,
			"%s: database/sql refused the commit before the driver, so its outcome is known", run)
		c := d.settled(t)
		require.Zero(t, c.commits, "%s: the driver was never asked to commit", run)
		require.Zero(t, c.openTx, "%s: nothing was left open", run)
	}
}

// TestRunInTransaction_ACancellationDuringTheDriversCommitIsStillAnUnknownOutcome is the other
// side of the identity test: a cancellation that lands while the driver's COMMIT is in flight.
// database/sql has asked the driver by then, and the driver answers with an error of its own
// wrapping context.Canceled, as pgx's stdlib driver does, which commits on the context BeginTx
// was given. The server may have committed before the cancellation reached it, so the tag stays,
// though the context is done and errors.Is finds context.Canceled in the error (#371).
func TestRunInTransaction_ACancellationDuringTheDriversCommitIsStillAnUnknownOutcome(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &scriptedDriver{
		commitErrs:   []error{fmt.Errorf("commit interrupted: %w", context.Canceled)},
		duringCommit: cancel,
	}
	db := retryingDB(t, d)
	recordBackoff(db)
	ran := 0

	err := db.RunInTransaction(ctx, oneStatement(db, &ran))

	require.Error(t, err)
	require.ErrorIs(t, err, data.ErrCommitOutcomeUnknown,
		"the driver was asked to commit, so whether the engine did is unknown")
	require.ErrorIs(t, err, context.Canceled, "and the driver's own error stays in the tree")
	assert.Equal(t, 1, ran, "a commit whose outcome is unknown is not replayed")
	assert.Equal(t, 1, d.settled(t).commits, "the driver was asked to commit once")
}
