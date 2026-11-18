// Package sqlitedbtest hands unit tests SQLite databases already at the head of the real migration
// set, for a test whose subject runs over the schema rather than builds it. Test support, imported
// only by tests and compiled into no binary, as otptest and dpoptest are.
//
// Migrating a new file to head runs every migration the engine carries, and under the race
// detector that took seconds for each test that asked for a database. So each test binary migrates
// one database the first time a test asks, keeps its bytes, and gives every test a copy of its own:
// a separate file, so no test sees another's rows. The migrations themselves stay covered where they
// are the subject: the data tier's migration tests and the startup tests run them from empty.
package sqlitedbtest

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
)

// migrated is the database this test binary migrated, read back as one file's bytes.
var migrated struct {
	once  sync.Once
	bytes []byte
	err   error
}

// NewMigrated opens a database of t's own, at the head of the migration set, in t's temporary
// directory, and closes it when t ends.
func NewMigrated(t testing.TB) *sqlitedb.Database {
	t.Helper()
	path := filepath.Join(t.TempDir(), "migrated.db")
	WriteMigrated(t, path)
	db, err := sqlitedb.New(t.Context(), "file:"+path, false)
	if err != nil {
		t.Fatalf("sqlitedbtest: opening the copy: %v", err)
	}
	t.Cleanup(func() { _ = db.DB.Close() })
	return db
}

// WriteMigrated writes a database at the head of the migration set to path, for a test that hands
// the path, rather than an open handle, to the code it tests.
func WriteMigrated(t testing.TB, path string) {
	t.Helper()
	// The first test to ask migrates, under its own context, which lasts the whole migration.
	migrated.once.Do(func() { migrated.bytes, migrated.err = migrateOnce(t.Context()) })
	if migrated.err != nil {
		t.Fatalf("sqlitedbtest: migrating the database every test copies: %v", migrated.err)
	}
	if err := os.WriteFile(path, migrated.bytes, 0o600); err != nil {
		t.Fatalf("sqlitedbtest: writing the copy: %v", err)
	}
}

// migrateOnce migrates a new file to head and reads it back. Close checkpoints the write-ahead log
// into the file and refuses a checkpoint that did not complete, so after it the file alone is the
// whole database.
func migrateOnce(ctx context.Context) ([]byte, error) {
	dir, err := os.MkdirTemp("", "sqlitedbtest-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "migrated.db")

	db, err := sqlitedb.New(ctx, "file:"+path, false)
	if err != nil {
		return nil, err
	}
	m, err := db.NewMigrator(ctx, nil)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := m.Up(ctx); err != nil && !migrator.IsNoChange(err) {
		_ = db.Close()
		return nil, err
	}
	if err := db.Close(); err != nil {
		return nil, err
	}
	return os.ReadFile(path) //nolint:gosec // G304: the file this function created in its own temporary directory
}
