package commondb

import (
	"context"
	"database/sql"
	"testing"
	"time"

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
	requested := recordBackoff(t)
	d := &scriptedDriver{}
	db := retryingDB(t, d)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := 0

	err := db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		ran++
		if _, execErr := db.ExecSql(ctx, tx, "UPDATE settings SET updated_at = updated_at"); execErr != nil {
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
	assert.ErrorIs(t, err, context.Canceled,
		"a cancelled run answers with the context error, whatever the commit reported (decision 13)")
	assert.NotErrorIs(t, err, sql.ErrTxDone,
		"and not with the sentinel that says only that the transaction was already over")
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
	recordBackoff(t)
	d := &scriptedDriver{execs: []*scriptedExec{{err: errDeadlock}}}
	db := retryingDB(t, d)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := 0

	err := db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		ran++
		_, execErr := db.ExecSql(ctx, tx, "UPDATE settings SET updated_at = updated_at")
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
	assert.ErrorIs(t, err, context.Canceled, "the context error is still what decided the outcome")
	assert.ErrorIs(t, err, errDeadlock, "and the abort the helper was rerunning for stays reachable")
	assert.Contains(t, err.Error(), "transaction abandoned after the engine aborted it")
	assert.Equal(t, 2, ran, "the deadlock was rerun once, and the rerun was the cancelled one")
}

// TestRunInTransaction_ACommitThatFindsTheTransactionDoneOnALiveContextIsStillTheSentinel is the
// negative that makes the two above attributable, and the reason the fix tests two conditions
// rather than one. sql.ErrTxDone with no cancellation to explain it means the transaction was
// finished by something other than this helper, which is a defect and not a cancellation, so it
// surfaces exactly as it did -- the same shape as the rollback suppression's own negative.
func TestRunInTransaction_ACommitThatFindsTheTransactionDoneOnALiveContextIsStillTheSentinel(t *testing.T) {
	recordBackoff(t)
	d := &scriptedDriver{commitErrs: []error{sql.ErrTxDone}}
	db := retryingDB(t, d)
	ran := 0

	err := db.RunInTransaction(context.Background(), oneStatement(db, &ran))

	require.Error(t, err)
	assert.ErrorIs(t, err, sql.ErrTxDone, "a live context leaves the commit's own error alone")
	assert.NotErrorIs(t, err, context.Canceled, "and contributes no context error")
	assert.NotErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, 1, ran, "a commit failure that is not a deadlock is not replayed")
}
