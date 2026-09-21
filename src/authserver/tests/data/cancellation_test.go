package datatests

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A cancelled context against a real engine, seam 2 of #386.
//
// The unit tier owns RunInTransaction's loop -- how many attempts, which exit, which error --
// against a scripted driver. What only a real engine and a real driver can answer is whether the
// context reaches them at all, which is the whole claim the acceptance criterion makes, and it is
// exactly the claim a scripted driver cannot support: the script is this package's own code and
// would honour a context the shipped driver ignores.
//
// Two of the three cases run on all four engines. The third is SQLite's and says so.

// cancelled returns a context that is already over, which is the only cancellation every engine
// and every driver answers identically: database/sql refuses the call before the driver is
// reached at all (probe/cancel.out).
func cancelled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestBeginTransaction_RefusesAnAlreadyCancelledContext(t *testing.T) {
	tx, err := database.BeginTransaction(cancelled())

	require.Error(t, err, "a cancelled caller must not be given a transaction")
	assert.ErrorIs(t, err, context.Canceled, "and the reason must be matchable, not a sentence")
	assert.Nil(t, tx, "nothing is returned to roll back")
}

func TestRunInTransaction_WithACancelledContextNeverRunsTheBody(t *testing.T) {
	ran := 0

	err := database.RunInTransaction(cancelled(), func(tx *sql.Tx) error {
		ran++
		return nil
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, ran, "the body never ran, so nothing was written and nothing needs undoing")
}

// TestBeginTransaction_OnSqliteABlockedOpenReturnsOnItsDeadline is the fact neither #386 nor #413
// states, and the reason decision 9 records it: on SQLite the pool is one connection, so a second
// transaction opened while the first is held waits for that connection. Without a context it waits
// for ever -- probe/cancel.out measured a plain Query still blocked after two seconds -- and that
// unbounded wait is what #413's five nil-transaction reads produced: a stuck goroutine, not an
// error. With a context the wait ends at the deadline and the caller gets something it can answer
// a request with.
//
// It does not close #413. The read still escapes the transaction and still answers from before its
// writes on the other three engines; this only removes the hang.
//
// SQLite alone, and not as a convenience: the other three engines have pools of more than one
// connection, so there is nothing for a second open to block on and the case would measure
// nothing at all there.
func TestBeginTransaction_OnSqliteABlockedOpenReturnsOnItsDeadline(t *testing.T) {
	if dbType() != "sqlite" && dbType() != "" {
		t.Skip("the single-connection pool is SQLite's; on the other engines a second open has nothing to wait for")
	}

	held, err := database.BeginTransaction(context.Background())
	require.NoError(t, err, "the holder takes the only connection")
	defer func() { _ = database.RollbackTransaction(held) }()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// THE OPEN RUNS ON ITS OWN GOROUTINE, and the case has a ceiling of its own, because the
	// failure being guarded against is a wait that never ends. Called inline, a BeginTransaction
	// that dropped the context would block this test until the whole tier's timeout fired --
	// measured at ten minutes while mutating exactly that. A regression should cost five seconds
	// and name itself.
	//
	// The gaveUp arm is the other half of that, and is not ceremony. On the failing path the
	// abandoned open eventually gets the connection anyway, once this test's own holder is
	// rolled back on the way out; a transaction nobody rolls back would then hold SQLite's only
	// connection for the rest of the package and every later test would fail on the tier's
	// timeout instead of on this one line.
	type opened struct {
		tx  *sql.Tx
		err error
	}
	answered := make(chan opened)
	gaveUp := make(chan struct{})
	started := time.Now()
	go func() {
		tx, err := database.BeginTransaction(ctx)
		select {
		case answered <- opened{tx: tx, err: err}:
		case <-gaveUp:
			if tx != nil {
				_ = database.RollbackTransaction(tx)
			}
		}
	}()

	var result opened
	select {
	case result = <-answered:
	case <-time.After(5 * time.Second):
		close(gaveUp)
		t.Fatal("the second open was still blocked five seconds after a 300ms deadline: the context is not reaching the pool")
	}

	require.Error(t, result.err, "the second open cannot succeed while the only connection is held")
	assert.True(t, errors.Is(result.err, context.DeadlineExceeded),
		"the deadline is what ended the wait, and it must be matchable: got %v", result.err)
	assert.Nil(t, result.tx)
	assert.Less(t, time.Since(started), 5*time.Second)
}
