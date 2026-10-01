package sqlitedb

import (
	"context"
	"errors"
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
