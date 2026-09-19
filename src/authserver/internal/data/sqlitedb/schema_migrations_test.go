package sqlitedb

import (
	"path/filepath"
	"testing"

	"github.com/leodip/goiabada/core/data/schemadump"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMigrator_PinsTheSchemaMigrationsShape holds the one engine whose version table
// NewMigrator actually changes (#284 decision 7).
//
// It runs a real database in the unit tier, which only SQLite allows: modernc.org/sqlite is
// pure Go, so there is no container and no server. The other three engines are checked the
// same way in the data tier, where they can be reached at all.
//
// What it is worth checking here rather than only there: golang-migrate's SQLite driver
// built (version uint64, dirty bool), nullable and keyless, and ran its own ensureVersionTable
// after this pre-create on every construction. Nothing runs behind the pre-create now, so this
// asserts the whole of the shape, the version_unique index included: that index used to be the
// driver's and is Goiabada's own statement since #268 decision 6, and it is the one part of the
// table a fresh install could lose without any other test noticing.
func TestNewMigrator_PinsTheSchemaMigrationsShape(t *testing.T) {
	// A file rather than :memory:, because NewSQLiteDatabase requires WAL, which an
	// in-memory database cannot provide, and because a shared-cache memory DSN is process
	// wide and would be shared with any other test that opened one.
	dsn := filepath.Join(t.TempDir(), "schema_migrations_test.db")
	db, err := NewSQLiteDatabase(&DatabaseConfig{Type: "sqlite", DSN: dsn}, false)
	require.NoError(t, err, "open the sqlite database")
	t.Cleanup(func() { _ = db.DB.Close() })

	// Constructed and then dropped: NewMigrator is what runs the pre-create, and there is
	// nothing to close (#268 decision 8).
	_, err = db.NewMigrator()
	require.NoError(t, err, "NewMigrator")

	shape, err := schemadump.DumpTable(db.DB, schemadump.SQLite, "schema_migrations")
	require.NoError(t, err, "dump schema_migrations")

	version, ok := shape.Column("version")
	require.True(t, ok, "schema_migrations carries a version column")
	assert.Equal(t, "INTEGER", version.Type,
		"only INTEGER PRIMARY KEY is a rowid alias; BIGINT makes SQLite build its own index for the key, and version_unique then lands on top of it")
	assert.False(t, version.Nullable,
		"version is NOT NULL on the other three engines too; on SQLite the rowid alias is what actually keeps a NULL out, by substituting a generated integer for it")
	assert.False(t, version.Generated,
		"the version is written by the runner's bookkeeping insert, not numbered by the engine, and it is not auto-numbered on any of the other three either")

	dirty, ok := shape.Column("dirty")
	require.True(t, ok, "schema_migrations carries a dirty column")
	assert.False(t, dirty.Nullable,
		"the NOT NULL that is genuinely enforced here: a NULL dirty breaks the version read's scan, which golang-migrate swallowed and reported as NilVersion, running the chain from 000001 against a populated database")

	// Exactly one, and over version. The rowid-alias primary key produces no index object
	// on SQLite, so the only one here is version_unique; on the other three the only one is
	// the primary key's. That is what lets the cross-engine comparison match them on the
	// tuple with no allowlist rule (#284 decision 2), and it is what would break if the
	// statement that survived golang-migrate's departure were dropped (#268 decision 6).
	var unique []schemadump.IndexShape
	for _, ix := range shape.Indexes {
		if ix.Unique {
			unique = append(unique, ix)
		}
	}
	require.Lenf(t, unique, 1, "one unique index on schema_migrations, got %v", shape.Indexes)
	assert.Equal(t, []string{"version"}, unique[0].Columns)
}
