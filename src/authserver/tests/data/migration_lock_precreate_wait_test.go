package datatests

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SQL Server's schema_migrations pre-create takes the migration lock when it finds no table, a
// first start, and a start can queue there behind another process that has since created the
// table and begun migrating: the runner holds the lock across its whole chain. So the queue at the
// pre-create is the runner's queue in every way an operator sees, and these hold it to the same
// rules: the start says it is waiting, once, and a stop ends the wait at once, at the start and in
// `migrate to` alike (#390 decisions 7, 9 and 10).
//
// SQL Server only: it is the one engine whose pre-create takes the lock at all.

// TestMigrationLock_AFirstStartQueuedAtThePreCreateSaysSo: a start against a database with no
// version table, whose migration lock another session holds. The holder creates the table while
// the start waits, as another pod's pre-create would before it migrates, and then releases.
//
// Run via: ./run-tests.sh --type data --db mssql --run TestMigrationLock
func TestMigrationLock_AFirstStartQueuedAtThePreCreateSaysSo(t *testing.T) {
	if dbType() != data.MSSQL {
		t.Skipf("%s pre-creates schema_migrations without a lock: only SQL Server has no atomic form of that check-then-create", dbType())
	}

	h := newIsolatedDB(t)
	eng := migrationLockEngine(t, h.Name)
	dropTheVersionTable(t, h)

	release := holdMigrationLock(t, h, eng)
	capture := logtest.CaptureSlog(t)
	done := startInBackground(t, h.Name)

	awaitRecord(t, capture, done, "waiting for the migration lock")
	awaitQueuedForTheLock(t, h)

	// The holder's own pre-create, while it keeps the lock to migrate.
	createTheVersionTable(t, h)
	release()
	select {
	case res := <-done:
		require.NoError(t, res.err, "the start must migrate once the lock is released")
	case <-time.After(migrationLockFinishBudget):
		t.Fatalf("the start did not finish within %s after the migration lock was released", migrationLockFinishBudget)
	}

	assert.Len(t, recordsNamed(capture, "waiting for the migration lock"), 1, "the wait is said once, however many times the start queues")
	assert.Equal(t,
		[]string{"opening the database", "waiting for the migration lock", "migrating the database", "database migrated"},
		messageOrder(capture, "opening the database", "waiting for the migration lock", "migrating the database",
			"database migrated", "no need to migrate the database"),
		"the start waited at the pre-create, then migrated the never-migrated database")

	requireMigrationLockIsFree(t, h, eng, "after a start that waited for it at the pre-create")
}

// TestMigrationLock_AStopWhileQueuedAtThePreCreateEndsTheWait: the same queue, and a stop arriving
// in it, ends the wait at once, answered as the cancellation it was, and leaves nothing behind.
//
// Run via: ./run-tests.sh --type data --db mssql --run TestMigrationLock
func TestMigrationLock_AStopWhileQueuedAtThePreCreateEndsTheWait(t *testing.T) {
	if dbType() != data.MSSQL {
		t.Skipf("%s pre-creates schema_migrations without a lock: only SQL Server has no atomic form of that check-then-create", dbType())
	}

	h := newIsolatedDB(t)
	eng := migrationLockEngine(t, h.Name)
	dropTheVersionTable(t, h)

	release := holdMigrationLock(t, h, eng)
	capture := logtest.CaptureSlog(t)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := startInBackgroundWith(t, ctx, h.Name)

	awaitRecord(t, capture, done, "waiting for the migration lock")
	stop()
	select {
	case res := <-done:
		require.ErrorIs(t, res.err, context.Canceled,
			"the stop is answered as the cancellation it was, so the process can tell it from a failure")
	case <-time.After(migrationLockHoldBudget):
		t.Fatalf("the start went on waiting at the pre-create for %s after it was asked to stop", migrationLockHoldBudget)
	}
	assert.Empty(t, recordsNamed(capture, "migrating the database"), "a stopped start migrates nothing")
	assert.False(t, versionTableExists(t, h), "and creates nothing")

	release()
	requireMigrationLockIsFree(t, h, eng, "after a start queued at the pre-create was stopped")
}

// TestMigrationLock_MigrateToInterruptedAtThePreCreateLeavesTheDatabaseUnchanged is decision 10 at
// the process: the real `goiabada-authserver migrate to` against a database with no version table
// whose migration lock another session holds, interrupted with SIGINT once its pre-create is queued.
// It prints the stop, says the database is unchanged and exits 1, as every other stop of the
// subcommand does; it used to report a failure to prepare the runner, with a stack trace.
//
// The binary is built from this tree, since the subcommand's entry point is package main and no
// other seam reaches the classification of its preparation step against a real lock.
//
// Run via: ./run-tests.sh --type data --db mssql --run TestMigrationLock
func TestMigrationLock_MigrateToInterruptedAtThePreCreateLeavesTheDatabaseUnchanged(t *testing.T) {
	if dbType() != data.MSSQL {
		t.Skipf("%s pre-creates schema_migrations without a lock: only SQL Server has no atomic form of that check-then-create", dbType())
	}

	binary := buildAuthServer(t)
	h := newIsolatedDB(t)
	eng := migrationLockEngine(t, h.Name)
	head := h.Migrator.Head()
	dropTheVersionTable(t, h)
	release := holdMigrationLock(t, h, eng)

	ctx, cancel := context.WithTimeout(context.Background(), migrationLockFinishBudget)
	defer cancel()
	cfg := appConfig.Database
	cmd := exec.CommandContext(ctx, binary, "migrate", "to", strconv.Itoa(head))
	cmd.Env = append(os.Environ(),
		"GOIABADA_DB_TYPE=mssql",
		"GOIABADA_DB_HOST="+cfg.Host,
		"GOIABADA_DB_PORT="+strconv.Itoa(cfg.Port),
		"GOIABADA_DB_USERNAME="+cfg.Username,
		"GOIABADA_DB_PASSWORD="+cfg.Password,
		"GOIABADA_DB_NAME="+h.Name,
		"GOIABADA_DB_CREATE=false",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	require.NoError(t, cmd.Start())
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	awaitQueuedForTheLockOr(t, h, exited, &stdout, &stderr)
	require.NoError(t, cmd.Process.Signal(os.Interrupt))

	var err error
	select {
	case err = <-exited:
	case <-time.After(migrationLockHoldBudget):
		t.Fatalf("migrate went on waiting at the pre-create for %s after SIGINT\nstdout: %s\nstderr: %s",
			migrationLockHoldBudget, stdout.String(), stderr.String())
	}
	var exitErr *exec.ExitError
	require.Truef(t, errors.As(err, &exitErr), "migrate must exit non-zero on a stop: %v\nstdout: %s\nstderr: %s",
		err, stdout.String(), stderr.String())
	assert.Equalf(t, 1, exitErr.ExitCode(), "the target was not reached, so the stop exits 1\nstderr: %s", stderr.String())
	assert.Equalf(t, "stopped by a signal before any migration ran: the database is unchanged\n", stdout.String(),
		"the stop is printed as a stop\nstderr: %s", stderr.String())
	assert.NotContains(t, stderr.String(), "unable to prepare the migration runner", "a stop is not a failure to prepare the runner")
	assert.False(t, versionTableExists(t, h), "the database is unchanged")

	release()
	requireMigrationLockIsFree(t, h, eng, "after migrate was interrupted at the pre-create")
}

// buildAuthServer builds the auth server's binary from this tree into the test's temporary
// directory.
func buildAuthServer(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "goiabada-authserver")
	ctx, cancel := context.WithTimeout(context.Background(), migrationLockFinishBudget)
	defer cancel()
	out, err := exec.CommandContext(ctx, "go", "build", "-o", binary,
		"github.com/leodip/goiabada/authserver/cmd/goiabada-authserver").CombinedOutput()
	require.NoErrorf(t, err, "build the auth server: %s", out)
	return binary
}

// dropTheVersionTable drops the schema_migrations table the fixture's own construction created, so
// the next pre-create finds none, as on a first start.
func dropTheVersionTable(t *testing.T, h *isolatedDB) {
	t.Helper()
	_, err := h.SQL.Exec("DROP TABLE schema_migrations")
	require.NoError(t, err, "clear the table the fixture's own construction created")
}

// createTheVersionTable creates schema_migrations at the shape the pre-create gives it.
func createTheVersionTable(t *testing.T, h *isolatedDB) {
	t.Helper()
	_, err := h.SQL.Exec("CREATE TABLE schema_migrations (version BIGINT PRIMARY KEY NOT NULL, dirty BIT NOT NULL)")
	require.NoError(t, err, "create the version table as the holder's pre-create would")
}

func versionTableExists(t *testing.T, h *isolatedDB) bool {
	t.Helper()
	var id *int64
	require.NoError(t, h.SQL.QueryRow("SELECT OBJECT_ID(N'schema_migrations', N'U')").Scan(&id))
	return id != nil
}

// queuedForTheLock counts the application lock requests waiting in the isolated database, which,
// with the test holding the migration lock, are requests for it.
func queuedForTheLock(t *testing.T, h *isolatedDB) int {
	t.Helper()
	var waiting int
	require.NoError(t, h.SQL.QueryRow(`SELECT COUNT(*) FROM sys.dm_tran_locks
		WHERE resource_type = 'APPLICATION' AND request_status = 'WAIT' AND resource_database_id = DB_ID(@p1)`,
		h.Name).Scan(&waiting))
	return waiting
}

// awaitQueuedForTheLock waits until a session is queued for the migration lock.
func awaitQueuedForTheLock(t *testing.T, h *isolatedDB) {
	t.Helper()
	awaitQueuedForTheLockOr(t, h, nil, nil, nil)
}

// awaitQueuedForTheLockOr is awaitQueuedForTheLock, failing with the process's output if it exits
// first.
func awaitQueuedForTheLockOr(t *testing.T, h *isolatedDB, exited <-chan error, stdout, stderr *bytes.Buffer) {
	t.Helper()
	deadline := time.After(migrationLockRecordBudget)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for queuedForTheLock(t, h) == 0 {
		select {
		case err := <-exited:
			t.Fatalf("migrate exited (%v) before queueing for the migration lock\nstdout: %s\nstderr: %s",
				err, stdout.String(), stderr.String())
		case <-deadline:
			t.Fatalf("nothing queued for the migration lock within %s", migrationLockRecordBudget)
		case <-tick.C:
		}
	}
}
