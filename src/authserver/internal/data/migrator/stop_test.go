package migrator

import (
	"context"
	"database/sql/driver"
	"errors"
	"io/fs"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"modernc.org/sqlite"
)

// The runner's half of #390 decision 9. A stop that arrives while the schema is being stepped, a
// shutdown signal during startup, cancels a wait at once but never cuts a migration file short: the
// file running when it arrives runs to its end and is recorded clean, no further file starts, and
// the lock comes back. A file cut off mid-way is left dirty, and on MySQL and SQL Server partly
// applied, which no start can carry on from without an operator.
//
// The file that is running when the stop arrives is held there by a SQL function that blocks until
// the case releases it, so the stop lands inside the file whatever the machine's speed.

// blockingFunction is the SQL function a migration file calls to hold the runner inside it.
const blockingFunction = "goiabada_test_block_until_released"

var (
	registerBlockingFunction sync.Once
	// blocking is the current case's hold; the function is registered once per process, so it
	// reads the hold from here.
	blockingMu sync.Mutex
	blocking   *fileHold
)

// fileHold is one case's hold on a running migration file: entered closes once the file reaches
// the function, and the function returns once release is closed.
type fileHold struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

// holdTheFile arranges for the next file calling blockingFunction to stop inside it, and answers
// the hold. It is called before the case opens its database: a function registered with the driver
// reaches only the connections opened after it. The release is registered on t too, so a failing case never leaves a runner blocked.
func holdTheFile(t *testing.T) *fileHold {
	t.Helper()
	registerBlockingFunction.Do(func() {
		sqlite.MustRegisterScalarFunction(blockingFunction, 0,
			func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) {
				blockingMu.Lock()
				h := blocking
				blockingMu.Unlock()
				if h == nil {
					return int64(0), nil
				}
				close(h.entered)
				<-h.release
				return int64(1), nil
			})
	})
	h := &fileHold{entered: make(chan struct{}), release: make(chan struct{})}
	blockingMu.Lock()
	blocking = h
	blockingMu.Unlock()
	t.Cleanup(func() {
		h.let()
		blockingMu.Lock()
		blocking = nil
		blockingMu.Unlock()
	})
	return h
}

// let releases the file.
func (h *fileHold) let() { h.once.Do(func() { close(h.release) }) }

// awaitEntered waits until the runner is inside the held file.
func (h *fileHold) awaitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-h.entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the runner never reached the held migration file")
	}
}

// blockingAtTwo is threeVersions with version 2's up file held inside the function, and version
// 5's down file likewise, so a case can stop the runner in either direction.
func blockingAtTwo() fs.FS {
	return set(map[string]string{
		"00001_initial_create.up.sql":   "CREATE TABLE t1 (id INTEGER);",
		"00001_initial_create.down.sql": "DROP TABLE t1;",
		"000002_second.up.sql":          "SELECT " + blockingFunction + "(); CREATE TABLE t2 (id INTEGER);",
		"000002_second.down.sql":        "DROP TABLE t2;",
		"000005_fifth.up.sql":           "CREATE TABLE t5 (id INTEGER);",
		"000005_fifth.down.sql":         "SELECT " + blockingFunction + "(); DROP TABLE t5;",
	})
}

// runInTheBackground runs op and answers its error on a buffered channel.
func runInTheBackground(op func() error) <-chan error {
	done := make(chan error, 1)
	go func() { done <- op() }()
	return done
}

func awaitResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("the runner did not return after the held file was released")
		return nil
	}
}

func TestUpToHead_AStopWhileAFileRunsFinishesThatFileAndStartsNoOther(t *testing.T) {
	hold := holdTheFile(t)
	db := openTestDB(t)
	m := newTestMigrator(t, db, blockingAtTwo())

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := runInTheBackground(func() error {
		_, err := m.UpToHead(ctx, "v1.6.0", nil)
		return err
	})

	hold.awaitEntered(t)
	stop()
	// The file goes on running past the stop; a runner that cut it short has already answered by
	// the time it is released, and the release then changes nothing.
	time.Sleep(50 * time.Millisecond)
	hold.let()
	err := awaitResult(t, done)

	var stopped StoppedError
	require.Truef(t, errors.As(err, &stopped), "a stop is answered as one, not as a failure: %v", err)
	assert.Equal(t, NilVersion, stopped.From, "the database had never been migrated")
	assert.Equal(t, 2, stopped.Reached, "the file running when the stop arrived ran to its end")
	assert.Equal(t, 2, stopped.Applied, "000001 and 000002")
	assert.Equal(t, 1, stopped.Remaining, "000005 never started")
	assert.ErrorIs(t, err, context.Canceled, "and the stop's cause is matchable, so the start can tell it from a failure")

	assert.Equal(t, []RecordedVersion{{Version: 2, Dirty: false}}, recorded(t, db),
		"the schema is clean at the version the stop reached")
	assert.True(t, tableExists(t, db, "t2"), "000002 applied whole")
	assert.False(t, tableExists(t, db, "t5"), "000005 did not run")
	assertPoolReturned(t, db)

	// The lock came back and the stop is resumable: the next start carries on from 000002.
	migrated, err := m.UpToHead(context.Background(), "v1.6.0", nil)
	require.NoError(t, err)
	assert.True(t, migrated)
	assert.Equal(t, []RecordedVersion{{Version: 5, Dirty: false}}, recorded(t, db))
}

func TestUpToHead_AStopBeforeTheFirstFileRunsNothing(t *testing.T) {
	db := openTestDB(t)
	m := newTestMigrator(t, db, threeVersions())

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	// Migrating is reported after the lock is taken and before the first marker is written, so a
	// stop arriving there is a stop between files with none applied.
	progress := &recordingProgress{onMigrating: stop}

	migrated, err := m.UpToHead(ctx, "v1.6.0", progress)

	assert.False(t, migrated)
	var stopped StoppedError
	require.Truef(t, errors.As(err, &stopped), "a stop is answered as one, not as a failure: %v", err)
	assert.Equal(t, NilVersion, stopped.From)
	assert.Equal(t, NilVersion, stopped.Reached)
	assert.Equal(t, 0, stopped.Applied)
	assert.Equal(t, 3, stopped.Remaining)
	assert.Empty(t, recorded(t, db), "no marker was written")
	assert.False(t, tableExists(t, db, "t1"))
	assert.Equal(t, []progressEvent{{Kind: "migrating", From: NilVersion, To: 5, Count: 3}}, progress.events,
		"the schema did not reach head, so nothing may say it was migrated")
	assertPoolReturned(t, db)
}

// TestMigrate_AStopWhileARollbackRunsFinishesThatFile is the same rule going down, where the
// version reached is the marker below the file rather than the file's own.
func TestMigrate_AStopWhileARollbackRunsFinishesThatFile(t *testing.T) {
	hold := holdTheFile(t)
	db := openTestDB(t)
	m := newTestMigrator(t, db, blockingAtTwo())
	require.NoError(t, m.Force(context.Background(), 5))
	_, err := db.Exec("CREATE TABLE t1 (id INTEGER); CREATE TABLE t2 (id INTEGER); CREATE TABLE t5 (id INTEGER);")
	require.NoError(t, err)

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := runInTheBackground(func() error { return m.Migrate(ctx, NilVersion) })

	hold.awaitEntered(t)
	stop()
	time.Sleep(50 * time.Millisecond)
	hold.let()
	err = awaitResult(t, done)

	var stopped StoppedError
	require.Truef(t, errors.As(err, &stopped), "a stop is answered as one, not as a failure: %v", err)
	assert.Equal(t, 5, stopped.From)
	assert.Equal(t, 2, stopped.Reached, "000005's rollback ran to its end and recorded 000002")
	assert.Equal(t, 1, stopped.Applied)
	assert.Equal(t, 2, stopped.Remaining, "000002's and 000001's rollbacks never started")
	assert.Equal(t, []RecordedVersion{{Version: 2, Dirty: false}}, recorded(t, db))
	assert.False(t, tableExists(t, db, "t5"))
	assert.True(t, tableExists(t, db, "t2"))
	assertPoolReturned(t, db)
}
