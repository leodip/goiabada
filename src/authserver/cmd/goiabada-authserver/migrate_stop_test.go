package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql/driver"
	"fmt"
	"io"
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

// #390 decision 10: `migrate to` follows the start's rule on SIGINT and SIGTERM, and since #487 on
// SIGHUP and SIGQUIT too. A wait is cancelled, a running file finishes and no new one starts; the
// command prints where it stopped, the version reached and how many files were applied and
// remained, and exits 1, because the target the operator asked for was not reached. Ctrl-C used to end it mid-file, with the shell's
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
	h := armTheHold()
	t.Cleanup(func() {
		h.let()
		blockingMu.Lock()
		blocking = nil
		blockingMu.Unlock()
	})
	return h
}

// armTheHold is holdTheFile for a process with no test to clean up after: the child that
// runHeldMigrateChild runs.
func armTheHold() *fileHold {
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
	return h
}

func (h *fileHold) let() { h.once.Do(func() { close(h.release) }) }

// newHeldMigrator answers a SQLite file database and a migrator over three migrations, 1, 2 and 3,
// whose second holds the runner inside it until the case releases it.
func newHeldMigrator(t *testing.T) (*sqlitedb.Database, *migrator.Migrator) {
	t.Helper()
	db, m, err := openHeldMigrator(filepath.Join(t.TempDir(), "held.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.DB.Close() })
	return db, m
}

// openHeldMigrator is newHeldMigrator over the file at path, for the child runHeldMigrateChild
// runs and for the case that reads what that child left there.
func openHeldMigrator(path string) (*sqlitedb.Database, *migrator.Migrator, error) {
	db, err := sqlitedb.New(context.Background(), "file:"+path, false)
	if err != nil {
		return nil, nil, err
	}
	// The engine's own migrator is built first for what it creates on the way, schema_migrations.
	if _, err = db.NewMigrator(context.Background(), nil); err != nil {
		_ = db.DB.Close()
		return nil, nil, err
	}

	files := fstest.MapFS{
		"migrations/000001_first.up.sql":    {Data: []byte("CREATE TABLE t1 (id INTEGER);")},
		"migrations/000001_first.down.sql":  {Data: []byte("DROP TABLE t1;")},
		"migrations/000002_second.up.sql":   {Data: []byte("SELECT " + blockingFunction + "(); CREATE TABLE t2 (id INTEGER);")},
		"migrations/000002_second.down.sql": {Data: []byte("DROP TABLE t2;")},
		"migrations/000003_third.up.sql":    {Data: []byte("CREATE TABLE t3 (id INTEGER);")},
		"migrations/000003_third.down.sql":  {Data: []byte("DROP TABLE t3;")},
	}
	m, err := migrator.New(db.DB, files, "migrations", migrator.SQLite())
	if err != nil {
		_ = db.DB.Close()
		return nil, nil, err
	}
	return db, m, nil
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

// lockedWriter is the writer a test reads while answerEachSignal writes to it from its own
// goroutine: the buffer they share is locked rather than raced.
type lockedWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *lockedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// The two lines `migrate to` answers a stop signal with (#487). Both hold whether the signal caught
// a file running or ended a wait before any did.
const (
	stopAcknowledgement = "stopping: no further migration will start, and one already running finishes first"
	stopReminder        = "still stopping: a migration already running finishes first, and a further Ctrl-C changes nothing"
)

// TestAnswerEachSignal_TheFirstIsAcknowledgedAndEveryFurtherOneReminded is what a Ctrl-C, and a
// Ctrl-C pressed again, meet on screen (#487): the first is acknowledged with the stop rule it
// sets in motion, and every further one, which changes nothing, is told so.
func TestAnswerEachSignal_TheFirstIsAcknowledgedAndEveryFurtherOneReminded(t *testing.T) {
	further := make(chan os.Signal, 2)
	done := make(chan struct{})
	defer close(done)
	var out lockedWriter
	go answerEachSignal(further, done, &out, func() {})

	further <- syscall.SIGINT
	further <- syscall.SIGINT
	further <- syscall.SIGTERM

	require.Eventually(t, func() bool {
		return strings.Count(out.String(), "\n") == 3
	}, 10*time.Second, 10*time.Millisecond, "three signals are answered with three lines")

	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	require.Len(t, lines, 3, out.String())
	assert.Equal(t, stopAcknowledgement, lines[0], "the first is the acknowledgement")
	assert.Equal(t, stopReminder, lines[1], "the second is reminded that it changes nothing")
	assert.Equal(t, stopReminder, lines[2], "and so is every one after it")
}

// stopWitness records, at each line written to it, whether the stop had already been made.
type stopWitness struct {
	ctx     context.Context
	mu      sync.Mutex
	stopped []bool
}

func (w *stopWitness) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopped = append(w.stopped, w.ctx.Err() != nil)
	return len(p), nil
}

func (w *stopWitness) writes() []bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]bool(nil), w.stopped...)
}

// TestAnswerEachSignal_TheAcknowledgementIsWrittenBeforeTheStopIsMade is what keeps the
// acknowledgement ahead of reportStop's line: the command answers the stop only once its context
// has ended, and the goroutine that writes the acknowledgement ends it, after the write. Were the
// two independent receivers of the signal, the command could report, return and stop answering
// before the acknowledgement was written, printing it after the report or not at all.
func TestAnswerEachSignal_TheAcknowledgementIsWrittenBeforeTheStopIsMade(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	further := make(chan os.Signal, 2)
	done := make(chan struct{})
	defer close(done)
	out := &stopWitness{ctx: ctx}
	go answerEachSignal(further, done, out, stop)

	further <- syscall.SIGINT
	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the first signal never made the stop")
	}
	further <- syscall.SIGINT
	require.Eventually(t, func() bool { return len(out.writes()) == 2 },
		10*time.Second, 10*time.Millisecond, "both signals are answered")

	assert.Equal(t, []bool{false, true}, out.writes(),
		"the acknowledgement is written before the stop is made, and the reminder after it")
}

// TestMigrateTo_EveryStopSignalIsAnsweredWhileTheFileItCatchesRunningStillRuns is #487 at the held
// file, for each signal `migrate to` follows the stop rule on: Ctrl-C's SIGINT, SIGTERM, the SIGHUP
// of a closed terminal or a lost SSH session, and Ctrl-\'s SIGQUIT. The acknowledgement is printed
// the moment the signal arrives, while the migration file it catches running is still running,
// which reportStop cannot say, being written only once the file has ended. A second signal meets
// the reminder, and the command's answer, the schema it leaves and its exit code stay what they
// were. The signals are real, sent to this process, so the registration is what is tested: a
// signal left out of it ends the process at once, mid-file, and the case with it.
func TestMigrateTo_EveryStopSignalIsAnsweredWhileTheFileItCatchesRunningStillRuns(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT} {
		t.Run(sig.String(), func(t *testing.T) {
			hold := holdTheFile(t)
			db, m := newHeldMigrator(t)

			// The command's own wiring, as runMigrateCommand installs it for `migrate to` (#390
			// decision 10, #487).
			var out lockedWriter
			ctx, stopAnsweringSignals := answerSignals(context.Background(), &out)
			defer stopAnsweringSignals()

			done := make(chan int, 1)
			go func() { done <- runMigrate(ctx, []string{"to", "3"}, db, m, 0, &out) }()

			select {
			case <-hold.entered:
			case code := <-done:
				t.Fatalf("migrate returned %d before reaching the held migration file\n%s", code, out.String())
			case <-time.After(30 * time.Second):
				t.Fatal("the runner never reached the held migration file")
			}

			// The signal, and the signal again, what an operator presses while nothing answers.
			// The second is sent once the first has been answered, because the kernel coalesces
			// two identical signals still pending: one delivered is one taken. Both land while the
			// file is held, which is what makes what follows provable: the runner cannot have
			// moved, so what was printed was printed while the file ran.
			require.NoError(t, syscall.Kill(syscall.Getpid(), sig))
			require.Eventually(t, func() bool {
				return strings.Contains(out.String(), stopAcknowledgement)
			}, 10*time.Second, 10*time.Millisecond, "the first signal is answered while the file runs")
			require.NoError(t, syscall.Kill(syscall.Getpid(), sig))
			require.Eventually(t, func() bool {
				return strings.Count(out.String(), "\n") == 5
			}, 10*time.Second, 10*time.Millisecond, "the second signal is answered while the file runs")

			assert.Contains(t, out.String(), "migrations to run, in order: 000001, 000002, 000003\n"+
				stopAcknowledgement+"\n"+stopReminder+"\n",
				"the two answers, and nothing else, follow the plan")
			assert.NotContains(t, out.String(), "stopped by a signal",
				"the report is written only once the file has ended, so the answers preceded it: they were printed while it ran")

			hold.let()

			var code int
			select {
			case code = <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("migrate did not return after the held file was released")
			}
			require.Equal(t, 1, code, out.String())
			assert.Equal(t, "current schema version: none (never migrated)\n"+
				"target schema version: 000003\n"+
				"migrations to run, in order: 000001, 000002, 000003\n"+
				stopAcknowledgement+"\n"+
				stopReminder+"\n"+
				"stopped by a signal: the database is at schema version 000002, clean, with 2 migrations applied and 1 remaining; run the same command again to carry on\n",
				out.String(), "the answers precede the report, and the report stays what it was")

			version, dirty, err := m.Version(context.Background())
			require.NoError(t, err)
			assert.Equal(t, 2, version, "the file running when the signals arrived ran to its end")
			assert.False(t, dirty, "and the schema is left clean")
		})
	}
}

// runHeldMigrateMarker, set in a child's environment to a database path, makes this test binary
// run runHeldMigrateChild over that path instead of the tests.
const runHeldMigrateMarker = "GOIABADA_TEST_RUN_HELD_MIGRATE"

// The lines runHeldMigrateChild writes to stderr, so its parent can tell where it is with stdout
// gone.
const (
	heldFileEntered = "held: the file is running"
	heldStopMade    = "held: the stop is made"
)

// runHeldMigrateChild is the child of TestMigrateTo_AStopWhoseReaderIsGoneStillFinishesTheFile:
// `migrate to 3` over the held migrations at path, its signals wired as runMigrateCommand wires
// them, writing to the process's own stdout. The held file is released when stdin closes.
func runHeldMigrateChild(path string) int {
	hold := armTheHold()
	go func() {
		<-hold.entered
		_, _ = fmt.Fprintln(os.Stderr, heldFileEntered)
	}()
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		hold.let()
	}()

	db, m, err := openHeldMigrator(path)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return 3
	}
	defer func() { _ = db.DB.Close() }()

	ctx, stopAnsweringSignals := answerSignals(context.Background(), os.Stdout)
	defer stopAnsweringSignals()
	context.AfterFunc(ctx, func() { _, _ = fmt.Fprintln(os.Stderr, heldStopMade) })
	return runMigrate(ctx, []string{"to", "3"}, db, m, 0, os.Stdout)
}

// TestMigrateTo_AStopWhoseReaderIsGoneStillFinishesTheFile is the stop rule with nobody left
// reading stdout, as in `migrate to N | tee log`, whose tee the Ctrl-C reaching the whole process
// group ends. The acknowledgement is then written into a pipe with no reader, while a file runs,
// and Go's default for that write ends the process at once, mid-file, leaving the schema dirty.
// The command ignores the broken pipe instead: the write fails, the file runs to its end, and the
// command exits 1 with the schema clean, as it does with a reader.
func TestMigrateTo_AStopWhoseReaderIsGoneStillFinishesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "held.db")

	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0])
	cmd.Env = []string{runHeldMigrateMarker + "=" + path}
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	stderr, err := cmd.StderrPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	var said strings.Builder
	lines := bufio.NewScanner(stderr)
	reached := func(want string) bool {
		for lines.Scan() {
			said.WriteString(lines.Text() + "\n")
			if lines.Text() == want {
				return true
			}
		}
		return false
	}
	// A child that ended early is reported with how it ended.
	ended := func(where string) {
		for lines.Scan() {
			said.WriteString(lines.Text() + "\n")
		}
		t.Fatalf("the child ended %s: %v\nstderr: %s", where, cmd.Wait(), said.String())
	}

	if !reached(heldFileEntered) {
		ended("before reaching the held file")
	}
	// The reader is gone, then the stop arrives while the file is held.
	require.NoError(t, stdout.Close())
	require.NoError(t, cmd.Process.Signal(syscall.SIGINT))
	if !reached(heldStopMade) {
		ended("while answering the stop, mid-file")
	}
	require.NoError(t, stdin.Close())
	for lines.Scan() {
		said.WriteString(lines.Text() + "\n")
	}

	err = cmd.Wait()
	require.NoErrorf(t, ctx.Err(), "the child did not exit within %s\nstderr: %s", mainProcessBound, said.String())
	var exitErr *exec.ExitError
	require.ErrorAsf(t, err, &exitErr, "a stop short of the target is not success: %v\nstderr: %s", err, said.String())
	require.Equalf(t, 1, exitErr.ExitCode(), "a stop handled, not a broken pipe that killed the process: %v\nstderr: %s",
		err, said.String())

	db, m, err := openHeldMigrator(path)
	require.NoError(t, err)
	defer func() { _ = db.DB.Close() }()
	version, dirty, err := m.Version(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, version, "the file running when the stop arrived ran to its end")
	assert.False(t, dirty, "and the schema is left clean")
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
// The embedded chain is dozens of files, so the signal lands inside it. #487 adds the other half:
// the command answers the signal as it arrives, before the report that waits for the file it
// interrupted to end, while that report, the schema it leaves and the exit code stay what they
// were. A second Ctrl-C, which changes nothing, is answered at the held file below, where the
// landing of the signal is not a matter of when.
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
	require.ErrorAsf(t, err, &exitErr, "a stop short of the target is not success: %v\n%s", err, printed.String())
	require.Equalf(t, 1, exitErr.ExitCode(), "a signal handled, not one that killed the process\n%s", printed.String())

	// The plan is printed before the runner takes the lock, so on a slow run (-race) the signal can
	// end that wait instead, which reportStop answers with its own line.
	match := regexp.MustCompile(`stopped by a signal(?: before any migration ran: the database is unchanged|` +
		`: the database is at schema version (\d{6}|none \(never migrated\)), clean)`).
		FindStringSubmatch(printed.String())
	require.NotNilf(t, match, "it says where it stopped\n%s", printed.String())

	// #487: the Ctrl-C is answered as it arrives, so the acknowledgement precedes the report,
	// which is written only once the interrupted step has ended. An operator watching the
	// terminal sees the command take the signal before the running file has finished.
	ack := stopAcknowledgement
	require.Containsf(t, printed.String(), ack, "the first Ctrl-C is acknowledged at once\n%s", printed.String())
	assert.Lessf(t, strings.Index(printed.String(), ack), strings.Index(printed.String(), match[0]),
		"the acknowledgement is printed when the signal arrives, not once the file it waits for ends\n%s", printed.String())

	version, dirty, err := schemaVersion(t, path)
	if match[1] == "" || match[1] == "none (never migrated)" {
		// The signal reached the runner before its first file: nothing ran.
		assert.Truef(t, migrator.IsNilVersion(err), "nothing was applied: %v", err)
		return
	}
	require.NoError(t, err)
	reached, err := strconv.Atoi(match[1])
	require.NoError(t, err)
	assert.False(t, dirty, "the schema is left clean")
	assert.Equal(t, reached, version, "the schema is at the version printed\n%s", printed.String())
	assert.Less(t, version, head(m), "the stop landed inside the chain")
}
