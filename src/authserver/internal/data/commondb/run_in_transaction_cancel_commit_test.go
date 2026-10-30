package commondb

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/core/logging/logtest"
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
			20*time.Second, time.Millisecond,
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
	assert.Zero(t, c.commits, "the driver was never asked to commit: the context was done first")
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
			20*time.Second, time.Millisecond,
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
// in, where the two tests above remove it: the body cancels and returns at once, racing
// database/sql's rollback goroutine. commit finds the context done and answers without asking the
// driver, and the goroutine rolls the transaction back, so it is known to be rolled back whichever
// wins, and the run may not carry data.ErrCommitOutcomeUnknown. Before the
// tag looked at whether the driver was asked, Tx.Commit's context's-error arm carried it, and that
// arm wins nearly every time (#371).
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
			"%s: the commit was refused before the driver was asked, so its outcome is known", run)
		c := d.settled(t)
		require.Zero(t, c.commits, "%s: the driver was never asked to commit", run)
		require.Zero(t, c.openTx, "%s: nothing was left open", run)
	}
}

// TestRunInTransaction_ACancellationDuringTheDriversCommitIsStillAnUnknownOutcome is the other
// side of the refusal: a cancellation that lands while the driver's COMMIT is in flight. database/sql
// has asked the driver by then, and the server may have committed before the cancellation reached
// it, so the tag stays whatever the driver answers. The rows are the shapes the shipped drivers
// answer with: an error of the driver's own wrapping context.Canceled, and the context's own error,
// bare, which is what pgx's normalizeTimeoutError returns on PostgreSQL and what go-mssqldb returns
// on SQL Server, a deadline included. The bare rows are identical to ctx.Err(), so an error's
// identity cannot tell them from a commit database/sql refused, and commit no longer asks it to
// (#371).
func TestRunInTransaction_ACancellationDuringTheDriversCommitIsStillAnUnknownOutcome(t *testing.T) {
	for _, tc := range []struct {
		name string
		// end ends the context, and is what the driver runs while its COMMIT is in flight.
		end       func(ctx *handCtx)
		commitErr error
		ctxErr    error
		// deadlockFirst has the first attempt's statement aborted as a deadlock victim, so the
		// cancelled commit is the rerun's, which RunInTransaction answers through abandoned().
		deadlockFirst bool
	}{
		{
			name:      "a driver error wrapping context.Canceled",
			end:       func(ctx *handCtx) { ctx.end(context.Canceled, true) },
			commitErr: fmt.Errorf("commit interrupted: %w", context.Canceled),
			ctxErr:    context.Canceled,
		},
		{
			name:      "the bare context.Canceled, as pgx answers",
			end:       func(ctx *handCtx) { ctx.end(context.Canceled, true) },
			commitErr: context.Canceled,
			ctxErr:    context.Canceled,
		},
		{
			name:      "the bare context.DeadlineExceeded, as go-mssqldb answers",
			end:       func(ctx *handCtx) { ctx.end(context.DeadlineExceeded, true) },
			commitErr: context.DeadlineExceeded,
			ctxErr:    context.DeadlineExceeded,
		},
		{
			name:          "the bare context.Canceled at the commit of a rerun",
			end:           func(ctx *handCtx) { ctx.end(context.Canceled, true) },
			commitErr:     context.Canceled,
			ctxErr:        context.Canceled,
			deadlockFirst: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newHandCtx()
			defer ctx.end(context.Canceled, true)
			d := &scriptedDriver{
				commitErrs:   []error{tc.commitErr},
				duringCommit: func() { tc.end(ctx) },
			}
			wantRuns := 1
			if tc.deadlockFirst {
				d.execs = []*scriptedExec{{err: errDeadlock}}
				wantRuns = 2
			}
			db := retryingDB(t, d)
			recordBackoff(db)
			ran := 0

			err := db.RunInTransaction(ctx, oneStatementOn(ctx, db, &ran))

			require.Error(t, err)
			require.ErrorIs(t, err, data.ErrCommitOutcomeUnknown,
				"the driver was asked to commit, so whether the engine did is unknown")
			require.ErrorIs(t, err, tc.ctxErr, "and the driver's own error stays in the tree")
			if tc.deadlockFirst {
				require.ErrorIs(t, err, errDeadlock, "and the abort the helper was rerunning for stays reachable")
			}
			assert.Equal(t, wantRuns, ran, "a commit whose outcome is unknown is not replayed")
			assert.Equal(t, 1, d.settled(t).commits, "the driver was asked to commit once")
		})
	}
}

// TestRunInTransaction_ACommitOnADoneContextLeavesTheRollbackToDatabaseSQL pins what commit does
// with a context that is done before it is asked to commit: it answers the context's error without
// asking the driver, and rolls nothing back itself, leaving that to the goroutine database/sql
// started at BeginTx, which rolls back every transaction whose context's Done closes. A rollback
// of commit's own ran on the caller's goroutine, and go-mssqldb answers one on a cancelled context
// before it has read the reply, keeping the connection: the caller's next transaction drew that
// connection and its BEGIN failed with "Read: EOF" (#371). With logSQL on, RollbackTransaction is
// the one place the helper rolls back that writes a record, and database/sql's goroutine writes
// none, so the record's absence is what says commit did not roll back. The rows are both ways a
// real context ends: cancelled, and a deadline, which FailureLimiter.reserveShared's WithTimeout
// reaches this path with.
func TestRunInTransaction_ACommitOnADoneContextLeavesTheRollbackToDatabaseSQL(t *testing.T) {
	for _, tc := range []struct {
		name string
		// start returns a live context and the function the body calls to end it.
		start  func() (context.Context, func())
		ctxErr error
	}{
		{
			name: "cancelled",
			start: func() (context.Context, func()) {
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				return ctx, cancel
			},
			ctxErr: context.Canceled,
		},
		{
			name: "past its deadline",
			start: func() (context.Context, func()) {
				// bodyDeadline, so the statement, which the scripted driver answers at once, runs
				// well inside it; the body then waits the timer out, so the context ends with the
				// error a timer firing leaves rather than one a test chose.
				ctx, cancel := context.WithTimeout(context.Background(), bodyDeadline)
				t.Cleanup(cancel)
				return ctx, func() {}
			},
			ctxErr: context.DeadlineExceeded,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			ctx, end := tc.start()
			d := &scriptedDriver{}
			db := retryingDB(t, d)
			db.logSQL = true
			requested := recordBackoff(db)
			ran := 0

			err := db.RunInTransaction(ctx, func(tx *sql.Tx) error {
				ran++
				if _, execErr := db.ExecSQL(ctx, tx, "UPDATE settings SET updated_at = updated_at"); execErr != nil {
					return execErr
				}
				end()
				<-ctx.Done()
				return nil
			})

			require.Error(t, err)
			require.ErrorIs(t, err, tc.ctxErr, "the context's own error is the answer")
			require.NotErrorIs(t, err, data.ErrCommitOutcomeUnknown,
				"no COMMIT reached the engine, so the transaction is known to be rolled back")
			assert.Equal(t, 1, ran, "a cancelled run is not rerun")
			assert.Empty(t, *requested)
			require.Eventually(t, func() bool { return d.counts().rollbacks == 1 },
				20*time.Second, time.Millisecond,
				"database/sql's goroutine rolled the transaction back")
			c := d.settled(t)
			assert.Zero(t, c.commits, "the driver was never asked to commit")
			assert.Equal(t, 1, c.rollbacks, "and the one rollback is database/sql's")
			assert.Zero(t, c.openTx, "nothing was left open")
			assert.NotContains(t, messagesAt(logs, slog.LevelInfo), "rolling back transaction",
				"commit did not roll back on the caller's goroutine")
			assert.Empty(t, messagesAt(logs, slog.LevelWarn), "and nothing was warned about")
		})
	}
}

// TestCommit_AfterTheDriverWasAskedOnlyTheTransactionDoneSentinelIsARefusal pins commit's flag
// itself, below RunInTransaction, whose own sql.ErrTxDone arm answers a done context the same way
// and so hides it. Once Tx.Commit has run, sql.ErrTxDone on a done context is database/sql's
// rollback goroutine having finished the transaction first, a refusal; the context's own error,
// bare, is a driver whose COMMIT was in flight, which is not (#371).
func TestCommit_AfterTheDriverWasAskedOnlyTheTransactionDoneSentinelIsARefusal(t *testing.T) {
	for _, tc := range []struct {
		name        string
		commitErr   error
		wantRefused bool
	}{
		{name: "sql.ErrTxDone on a done context", commitErr: sql.ErrTxDone, wantRefused: true},
		{name: "the bare context.Canceled on a done context", commitErr: context.Canceled, wantRefused: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newHandCtx()
			defer ctx.end(context.Canceled, true)
			d := &scriptedDriver{
				commitErrs:   []error{tc.commitErr},
				duringCommit: func() { ctx.end(context.Canceled, false) },
			}
			db := scriptedDB(t, d)
			tx, err := db.BeginTransaction(ctx)
			require.NoError(t, err)

			refused, err := db.commit(ctx, tx)

			require.ErrorIs(t, err, tc.commitErr)
			assert.Equal(t, tc.wantRefused, refused)
			assert.Equal(t, 1, d.settled(t).commits, "the driver was asked to commit")
		})
	}
}

// handCtx is a context a test ends by hand, choosing the error it ends with and whether its Done
// channel closes. Ended with context.DeadlineExceeded, it is a deadline firing at the instant the
// test picks, which no timer promises. Ended quietly, Err set and Done left open, it keeps
// database/sql's rollback goroutine asleep, so what Tx.Commit answers is the driver's scripted
// answer and not a race against that goroutine. No real context is ever quiet; that half exists
// only for commit's flag below RunInTransaction.
type handCtx struct {
	context.Context
	done chan struct{}

	mu     sync.Mutex
	err    error
	closed bool
}

func newHandCtx() *handCtx {
	return &handCtx{Context: context.Background(), done: make(chan struct{})}
}

func (c *handCtx) Done() <-chan struct{} { return c.done }

func (c *handCtx) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// end sets the context's error, keeping the first, and closes Done when closeDone is set. The
// error is stored before Done closes, so anything woken by Done reads it.
func (c *handCtx) end(err error, closeDone bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.err = err
	}
	if closeDone && !c.closed {
		c.closed = true
		close(c.done)
	}
}
