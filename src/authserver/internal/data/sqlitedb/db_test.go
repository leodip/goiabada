package sqlitedb

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sqlitedriver "modernc.org/sqlite"
)

// sqliteCantOpen is SQLITE_CANTOPEN, the primary result code SQLite answers for a file it cannot
// open. Observed rather than remembered: modernc.org/sqlite v1.58.0 reported code 14 for a
// read-only DSN under a directory that does not exist.
const sqliteCantOpen = 14

// TestNew_AnUnopenableFileIsAConnectionError is #438 decision 4: the ping comes before the
// PRAGMAs, so a file SQLite cannot open fails there, under the same prefix the three server
// engines use for a database they cannot reach, with SQLite's own name for the code in the
// message and the driver's error still in the chain.
//
// Behind the PRAGMAs this input never reached the ping: the first PRAGMA opened the file and
// failed, and the operator read "failed to execute PRAGMA foreign_keys = ON;". The ping's own
// branch, a bare type assertion that replaced the driver's error with a code string, was
// unreachable for the one input that fails at connection.
//
// mode=ro under a directory that does not exist, so nothing can be created on the way to the
// error: the directory is under the test's own temporary one and is never made.
func TestNew_AnUnopenableFileIsAConnectionError(t *testing.T) {
	dsn := "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "absent", "dir", "x.db")) + "?mode=ro"

	db, err := New(context.Background(), dsn, false)

	require.Error(t, err, "a file SQLite cannot open must not construct")
	assert.Nil(t, db, "a failed construction returns no database")
	assert.Truef(t, strings.HasPrefix(err.Error(), "unable to connect to database: "),
		"an unopenable file is a connection failure, worded as the server engines word theirs; got %q", err.Error())
	assert.Containsf(t, err.Error(), "SQLITE_CANTOPEN",
		"the message names SQLite's code, which is what an operator searches for; got %q", err.Error())

	var sqliteErr *sqlitedriver.Error
	require.ErrorAsf(t, err, &sqliteErr,
		"the driver's error stays in the chain, so a caller can still match it with errors.As; got %v", err)
	assert.Equal(t, sqliteCantOpen, sqliteErr.Code(), "the driver's code survives the wrap")
}

// sqliteReadonlyDirectory is SQLITE_READONLY_DIRECTORY, SQLITE_READONLY (8) with 6 in its high
// byte, the extended code SQLite answers at connection for a database whose directory the server
// cannot write. The readonly-database troubleshooting page quotes the refusal it produces.
const sqliteReadonlyDirectory = 1544

// sqliteIOErrRead is SQLITE_IOERR_READ, an extended code the driver does name.
const sqliteIOErrRead = 266

// TestCodeName_AnExtendedCodeTheDriverLeavesOutIsNamedByItsPrimaryCode: the connection refusal
// names SQLite's code, and the driver's table names only some extended codes, so 1544 printed as
// "unable to connect to database: : attempt to write a readonly database (1544)", an empty name
// between two colons. A code the table does name, primary or extended, keeps its own name.
func TestCodeName_AnExtendedCodeTheDriverLeavesOutIsNamedByItsPrimaryCode(t *testing.T) {
	_, listed := sqlitedriver.ErrorCodeString[sqliteReadonlyDirectory]
	require.False(t, listed, "the driver now names 1544 itself, so this case no longer exercises the fallback")

	assert.Equal(t, "Attempt to write a readonly database (SQLITE_READONLY)", codeName(sqliteReadonlyDirectory))
	assert.Equal(t, "Unable to open the database file (SQLITE_CANTOPEN)", codeName(sqliteCantOpen))

	require.Contains(t, sqlitedriver.ErrorCodeString, sqliteIOErrRead)
	assert.Equal(t, sqlitedriver.ErrorCodeString[sqliteIOErrRead], codeName(sqliteIOErrRead),
		"an extended code the driver names keeps its own name rather than its primary code's")
	assert.NotEqual(t, sqlitedriver.ErrorCodeString[sqliteIOErrRead&0xff], codeName(sqliteIOErrRead))
}

// TestNew_ARefusedPragmaClosesThePool is the input that gets past the ping and is then refused: a
// real file in SQLite's default DELETE journal mode, opened read-only, connects and cannot be
// switched to WAL. The constructor returns no database, so the caller has nothing to close, and
// before #438 the pool kept its descriptor to the file for the life of the process.
func TestNew_ARefusedPragmaClosesThePool(t *testing.T) {
	path := filepath.Join(t.TempDir(), "read_only.db")
	seed, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = seed.Exec("CREATE TABLE t (x INTEGER)")
	require.NoError(t, err, "write the file in the default journal mode")
	require.NoError(t, seed.Close())
	dsn := "file:" + filepath.ToSlash(path) + "?mode=ro"

	// The counter has to see a descriptor it should see, or a zero below proves nothing.
	held, err := sql.Open("sqlite", dsn)
	require.NoError(t, err)
	require.NoError(t, held.PingContext(context.Background()))
	require.Positive(t, descriptorsTo(t, path), "an open pool on the file holds a descriptor to it")
	require.NoError(t, held.Close())
	require.Zero(t, descriptorsTo(t, path), "a closed pool holds none")

	db, err := New(context.Background(), dsn, false)

	require.Error(t, err, "a read-only file cannot take WAL, so it must not construct")
	assert.Nil(t, db, "a failed construction returns no database")
	assert.Containsf(t, err.Error(), "journal_mode",
		"the refusal is the WAL PRAGMA's, past the ping; got %q", err.Error())
	assert.Zero(t, descriptorsTo(t, path), "a refused construction leaves no descriptor to the file open")
}

// descriptorsTo counts this process's open descriptors on path, read from /proc/self/fd. The unit
// tier's container and CI are both Linux; elsewhere there is nothing to read and the test skips.
func descriptorsTo(t *testing.T, path string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("counting descriptors needs /proc/self/fd: %v", err)
	}
	want, err := filepath.EvalSymlinks(path)
	require.NoError(t, err)
	n := 0
	for _, e := range entries {
		if target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && target == want {
			n++
		}
	}
	return n
}

// endlessQuery never finishes on its own, so the context it runs under is what ends it, always
// while SQLite is stepping it.
const endlessQuery = "WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c) SELECT count(*) FROM c"

// interruptAQuery runs endlessQuery until its context ends, which the driver answers by
// interrupting the connection. SQLite clears an interrupt only when the connection's next
// statement starts, so the driver reports the connection unusable and database/sql closes it;
// the pool's next statement runs on a connection it opens in its place. That replacement is what
// both tests below are about, so its absence fails them rather than letting them pass on the
// connection New set up.
func interruptAQuery(t *testing.T, db *Database) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var n int64
	err := db.DB.QueryRowContext(ctx, endlessQuery).Scan(&n)
	require.ErrorIs(t, err, context.DeadlineExceeded, "the query ends with its context")
	require.Eventually(t, func() bool { return db.DB.Stats().OpenConnections == 0 }, time.Second, 10*time.Millisecond,
		"the interrupted connection is closed rather than kept, so the next statement opens another")
}

// A connection the pool opens after an interrupted query is configured as the first was: foreign
// keys enforced and a busy timeout set. Both are per-connection settings, and New applied them to
// the pool's first connection alone, so a request whose context ended mid-query left every later
// statement of the process with foreign keys off and no busy timeout (#562).
func TestNew_EveryConnectionIsConfigured(t *testing.T) {
	db, err := New(context.Background(), "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "s.db")), false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	interruptAQuery(t, db)

	var foreignKeys, busyTimeout int
	require.NoError(t, db.DB.QueryRowContext(context.Background(), "PRAGMA foreign_keys;").Scan(&foreignKeys))
	require.NoError(t, db.DB.QueryRowContext(context.Background(), "PRAGMA busy_timeout;").Scan(&busyTimeout))
	assert.Equal(t, 1, foreignKeys, "foreign keys are enforced on the replacement connection")
	assert.Equal(t, 5000, busyTimeout, "and it waits 5 seconds for a lock")
}

// Close leaves the database in one file even when the last query was interrupted. SQLite folds the
// WAL into the database file when its last connection closes, but a checkpoint gives up while an
// interrupt is pending, so the interrupted connection, the only one, closed and left the -wal and
// -shm beside the file, with the data in them. A server stopped as its first query ran did exactly
// that (#562): the -wal TestMain_AStopLeavesTheSQLiteDatabaseInOneFile found under load.
func TestDatabase_CloseLeavesOneFileAfterAnInterruptedQuery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.db")
	db, err := New(context.Background(), "file:"+filepath.ToSlash(path), false)
	require.NoError(t, err)
	_, err = db.DB.ExecContext(context.Background(), "CREATE TABLE t (x INTEGER)")
	require.NoError(t, err)
	_, err = db.DB.ExecContext(context.Background(), "INSERT INTO t VALUES (42)")
	require.NoError(t, err)

	interruptAQuery(t, db)
	require.NoError(t, db.Close())

	for _, suffix := range []string{"-wal", "-shm"} {
		_, statErr := os.Stat(path + suffix)
		require.ErrorIsf(t, statErr, fs.ErrNotExist, "the database's %s file is left beside it", suffix)
	}

	// The database file alone, copied as a backup of it would be, holds the row.
	backup := filepath.Join(t.TempDir(), "backup.db")
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(backup, contents, 0o600))
	copied, err := sql.Open("sqlite", "file:"+filepath.ToSlash(backup)+"?mode=ro")
	require.NoError(t, err)
	defer func() { _ = copied.Close() }()
	var x int
	require.NoError(t, copied.QueryRowContext(context.Background(), "SELECT x FROM t").Scan(&x))
	assert.Equal(t, 42, x)
}

// Close reports a checkpoint that did not complete (#570). A second connection holding a read
// transaction on the latest snapshot lets the checkpoint copy all three frames into the database
// file but not reset the log, so it answers busy with the log wholly copied, and the -wal stays
// beside the file holding nothing the file lacks. Close returns the three numbers as an error,
// which main's "unable to close the database" warning then says and
// TestMain_AStopLeavesTheSQLiteDatabaseInOneFile fails on.
func TestDatabase_CloseReportsACheckpointThatDidNotComplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.db")
	db, err := New(context.Background(), "file:"+filepath.ToSlash(path), false)
	require.NoError(t, err)
	_, err = db.DB.ExecContext(context.Background(), "CREATE TABLE t (x INTEGER)")
	require.NoError(t, err)
	_, err = db.DB.ExecContext(context.Background(), "INSERT INTO t VALUES (42)")
	require.NoError(t, err)

	// A second connection takes a read transaction on the same file and holds it: a deferred
	// BEGIN and then the read leave the read mark the checkpoint cannot reset, until the
	// transaction ends after Close has answered.
	other, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	require.NoError(t, err)
	t.Cleanup(func() { _ = other.Close() })
	otherConn, err := other.Conn(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = otherConn.Close() })
	_, err = otherConn.ExecContext(context.Background(), "BEGIN")
	require.NoError(t, err)
	var rows int
	require.NoError(t, otherConn.QueryRowContext(context.Background(), "SELECT count(*) FROM t").Scan(&rows))
	require.Positive(t, rows, "the read has to see a row, or the held transaction proves nothing")

	// The pool's one connection runs the checkpoint. With no busy timeout it answers busy at once,
	// rather than after the five seconds every connection is opened with.
	_, err = db.DB.ExecContext(context.Background(), "PRAGMA busy_timeout = 0")
	require.NoError(t, err)

	closeErr := db.Close()
	require.EqualError(t, closeErr, "the WAL checkpoint did not complete: busy=1, log=3, checkpointed=3",
		"a checkpoint the reader kept from resetting the log is not a close that succeeded")
	_, statErr := os.Stat(path + "-wal")
	require.NoError(t, statErr, "the WAL the checkpoint could not reset is still beside the file")
}

// The in-memory default has no journal to checkpoint, so wal_checkpoint answers busy=0, log=-1,
// checkpointed=-1, and that passes: the -1s are an equal pair, the answer of a database with no
// WAL (#570).
func TestDatabase_CloseOfTheInMemoryDefaultPasses(t *testing.T) {
	db, err := New(context.Background(), "", false)
	require.NoError(t, err)
	require.NoError(t, db.Close(), "an in-memory database has no WAL to fold in")
}
