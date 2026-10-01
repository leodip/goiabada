package sqlitedb

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	require.Truef(t, errors.As(err, &sqliteErr),
		"the driver's error stays in the chain, so a caller can still match it with errors.As; got %v", err)
	assert.Equal(t, sqliteCantOpen, sqliteErr.Code(), "the driver's code survives the wrap")
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
