package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"modernc.org/sqlite"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
)

// #390 decision 10: `migrate to` follows the start's rule on SIGINT and SIGTERM. A wait is
// cancelled, a running file finishes and no new one starts; the command prints where it stopped,
// the version reached and how many files were applied and remained, and exits 1, because the
// target the operator asked for was not reached. Ctrl-C used to end it mid-file, with the shell's
// 130 and a dirty, possibly partly applied file.

// blockingFunction is the SQL function a test migration file calls to hold the runner inside it.
const blockingFunction = "goiabada_test_migrate_block_until_released"

var (
	registerBlockingFunction sync.Once
	blockingMu               sync.Mutex
	blocking                 *fileHold
)

// fileHold is one case's hold on a running migration file: entered closes once the file reaches
// the function, and the function returns once release is closed.
type fileHold struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

// holdTheFile arranges for the next file calling blockingFunction to stop inside it. It is called
// before the case opens its database, since a function registered with the driver reaches only the
// connections opened after it.
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

func (h *fileHold) let() { h.once.Do(func() { close(h.release) }) }

// newHeldMigrator answers a SQLite file database and a migrator over three migrations, 1, 2 and 3,
// whose second holds the runner inside it until the case releases it.
func newHeldMigrator(t *testing.T) (*sqlitedb.Database, *migrator.Migrator) {
	t.Helper()
	db, err := sqlitedb.New(context.Background(), "file:"+filepath.Join(t.TempDir(), "held.db"), false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.DB.Close() })
	// The engine's own migrator is built first for what it creates on the way, schema_migrations.
	_, err = db.NewMigrator(context.Background(), nil)
	require.NoError(t, err)

	files := fstest.MapFS{
		"migrations/000001_first.up.sql":    {Data: []byte("CREATE TABLE t1 (id INTEGER);")},
		"migrations/000001_first.down.sql":  {Data: []byte("DROP TABLE t1;")},
		"migrations/000002_second.up.sql":   {Data: []byte("SELECT " + blockingFunction + "(); CREATE TABLE t2 (id INTEGER);")},
		"migrations/000002_second.down.sql": {Data: []byte("DROP TABLE t2;")},
		"migrations/000003_third.up.sql":    {Data: []byte("CREATE TABLE t3 (id INTEGER);")},
		"migrations/000003_third.down.sql":  {Data: []byte("DROP TABLE t3;")},
	}
	m, err := migrator.New(db.DB, files, "migrations", migrator.SQLite())
	require.NoError(t, err)
	return db, m
}

func TestMigrateTo_AStopWhileAFileRunsFinishesThatFileAndExits1(t *testing.T) {
	hold := holdTheFile(t)
	db, m := newHeldMigrator(t)

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	var out bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- runMigrate(ctx, []string{"to", "3"}, db, m, 0, &out) }()

	select {
	case <-hold.entered:
	case code := <-done:
		t.Fatalf("migrate returned %d before reaching the held migration file\n%s", code, out.String())
	case <-time.After(30 * time.Second):
		t.Fatal("the runner never reached the held migration file")
	}
	stop()
	// The file goes on running past the stop; a command that cut it short has already answered.
	time.Sleep(50 * time.Millisecond)
	hold.let()

	var code int
	select {
	case code = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("migrate did not return after the held file was released")
	}

	// 1, not 0: the target was not reached, and a script must not read the stop as success.
	require.Equal(t, 1, code, out.String())
	assert.Contains(t, out.String(),
		"stopped by a signal: the database is at schema version 000002, clean, with 2 migrations applied and 1 remaining",
		"it says where it stopped, the version reached, and how many files ran and remain")
	assert.NotContains(t, out.String(), "done:")
	assert.NotContains(t, out.String(), "migration failed", "a stop is not a failure")

	version, dirty, err := m.Version(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, version, "the file running when the stop arrived ran to its end")
	assert.False(t, dirty, "and the schema is left clean")

	// The stop is resumable: the same command carries on from 000002.
	out.Reset()
	require.Equal(t, 0, runMigrate(context.Background(), []string{"to", "3"}, db, m, 0, &out), out.String())
	version, dirty, err = m.Version(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, version)
	assert.False(t, dirty)
}

// A stop that arrives before the runner has the database, during a wait for the connection or the
// lock, ends that wait and runs nothing.
func TestMigrateTo_AStopBeforeAnyFileRunsLeavesTheDatabaseUnchanged(t *testing.T) {
	db, m, _ := newTestMigrator(t)

	ctx, stop := context.WithCancel(context.Background())
	stop()
	var out bytes.Buffer
	code := runMigrate(ctx, []string{"to", strconv.Itoa(head(m))}, db, m, rollbackFloor, &out)

	require.Equal(t, 1, code, out.String())
	assert.Contains(t, out.String(), "stopped by a signal before any migration ran: the database is unchanged")
	assert.NotContains(t, out.String(), "done:")

	_, _, err := m.Version(context.Background())
	assert.ErrorIs(t, err, migrator.ErrNilVersion, "nothing was applied")
}

// TestMain_MigrateStopsCleanlyOnSIGINT is decision 10 at the process: the real main, `migrate to`
// the head over a fresh SQLite file, sent SIGINT, what Ctrl-C sends, the moment it prints the plan.
// The embedded chain is dozens of files, so the signal lands inside it.
func TestMain_MigrateStopsCleanlyOnSIGINT(t *testing.T) {
	_, m, _ := newTestMigrator(t)
	path := filepath.Join(t.TempDir(), "m.db")

	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "migrate", "to", strconv.Itoa(head(m)))
	cmd.Env = []string{
		runMainMarker + "=1",
		"GOIABADA_DB_TYPE=sqlite",
		"GOIABADA_DB_DSN=file:" + path,
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	var printed strings.Builder
	signalled := false
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		printed.WriteString(scanner.Text() + "\n")
		if !signalled && strings.HasPrefix(scanner.Text(), "migrations to run, in order:") {
			signalled = true
			require.NoError(t, cmd.Process.Signal(syscall.SIGINT))
		}
	}
	err = cmd.Wait()
	require.NoErrorf(t, ctx.Err(), "migrate did not exit within %s\n%s", mainProcessBound, printed.String())
	require.Truef(t, signalled, "migrate never printed its plan\nstdout: %s\nstderr: %s", printed.String(), stderr.String())

	var exitErr *exec.ExitError
	require.Truef(t, errors.As(err, &exitErr), "a stop short of the target is not success: %v\n%s", err, printed.String())
	require.Equalf(t, 1, exitErr.ExitCode(), "a signal handled, not one that killed the process\n%s", printed.String())

	match := regexp.MustCompile(`stopped by a signal: the database is at schema version (\d{6}|none \(never migrated\)), clean`).
		FindStringSubmatch(printed.String())
	require.NotNilf(t, match, "it says where it stopped\n%s", printed.String())

	version, dirty, err := schemaVersion(t, path)
	if match[1] == "none (never migrated)" {
		// The signal reached the runner before its first file: nothing ran.
		assert.Truef(t, migrator.IsNilVersion(err), "nothing was applied: %v", err)
		return
	}
	require.NoError(t, err)
	reached, err := strconv.Atoi(match[1])
	require.NoError(t, err)
	assert.False(t, dirty, "the schema is left clean")
	assert.Equal(t, reached, version, fmt.Sprintf("the schema is at the version printed\n%s", printed.String()))
	assert.Less(t, version, head(m), "the stop landed inside the chain")
}
