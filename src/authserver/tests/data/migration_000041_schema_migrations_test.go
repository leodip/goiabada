package datatests

import (
	"testing"

	"github.com/leodip/goiabada/core/data/schemadump"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// schemaMigrationsDriverDDL000041 is the shape golang-migrate v4.19.1's SQLite driver builds
// for its own version table, and the shape a Goiabada install created before #284 therefore
// has. Written out here because it is the fixture the migration has to convert, and there is
// no other way to reach it: NewMigrator now pre-creates the pinned shape, so a database this
// package builds never has the old one.
const (
	schemaMigrationsDriverDDL000041   = `CREATE TABLE schema_migrations (version uint64,dirty bool)`
	schemaMigrationsDriverIndex000041 = `CREATE UNIQUE INDEX IF NOT EXISTS version_unique ON schema_migrations (version)`
)

// sqliteVersionBefore000041 is 39, not 40. 000040 is #283's collation migration and it
// exists on MySQL and SQL Server alone, so 000039 is the last version SQLite's own source
// carries before this one, and Migrate refuses a target version the engine's source does not
// have. The other three engines are taken to head with Up() for the same reason: their heads
// are 000040, 000039 and 000040, three different numbers.
const sqliteVersionBefore000041 = 39

// TestSchemaMigrations_PinnedShapeAfterConstruction is seam 4 of #284: after NewMigrator has
// run and before any migration, schema_migrations has Goiabada's shape rather than whichever
// one the pinned golang-migrate happens to build.
//
// It runs on all four engines and asserts the same three things on each, which is the point:
// the parity check reads schema_migrations like any other table (decision 7), so it is only
// worth reading if the four engines agree on it.
//
// The unique-index assertion is the one that is true on all four for different reasons.
// SQLite's version INTEGER PRIMARY KEY is a rowid alias and produces no index object at all,
// so its single unique index is the driver's own version_unique; on MySQL, PostgreSQL and
// SQL Server it is the primary key's index and there is no version_unique. Same tuple,
// (schema_migrations, [version], unique), which is what decision 2 keys an index on, so this
// costs the cross-engine allowlist nothing.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestSchemaMigrations_PinnedShapeAfterConstruction
func TestSchemaMigrations_PinnedShapeAfterConstruction(t *testing.T) {
	h := newIsolatedDB(t)

	// Deliberately at version 0. newIsolatedDB constructs the migrator and nothing else,
	// so what is read here was built by the pre-create and by the driver's own
	// ensureVersionTable running behind it, with no migration involved.
	assertSchemaMigrationsPinnedShape(t, h, "after construction")
}

// assertSchemaMigrationsPinnedShape is the shape itself, shared by seam 4's assertion above
// and seam 5's after-state below, so the migration and the pre-create are held to one
// definition rather than two that can drift apart.
func assertSchemaMigrationsPinnedShape(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()

	shape := dumpTable(t, h, "schema_migrations")

	version := shape.column(t, "version")
	assert.Falsef(t, version.Nullable,
		"[%s] version is NOT NULL on all four; on SQLite the rowid alias is what keeps a NULL out, by substituting a generated integer for it",
		phase)
	assert.Falsef(t, version.Generated,
		"[%s] the version is written by SetVersion and numbered by no engine", phase)

	dirty := shape.column(t, "dirty")
	assert.Falsef(t, dirty.Nullable,
		"[%s] dirty is NOT NULL on all four engines, and it is the one genuinely enforced on SQLite: a NULL here breaks Version()'s scan, which golang-migrate swallows and reports as NilVersion",
		phase)
	assert.Falsef(t, dirty.Generated, "[%s] dirty is numbered by no engine", phase)

	assert.Emptyf(t, shape.ForeignKeys,
		"[%s] schema_migrations references nothing on %s", phase, dbType())

	var unique []indexShape
	for _, ix := range shape.Indexes {
		if ix.Unique {
			unique = append(unique, ix)
		}
	}
	require.Lenf(t, unique, 1,
		"[%s] exactly one unique index on schema_migrations on %s, got %v", phase, dbType(), shape.Indexes)
	assert.Equalf(t, []string{"version"}, unique[0].Columns,
		"[%s] the unique index covers version on %s", phase, dbType())
}

// TestMigration000041_SchemaMigrationsShape is seam 5: the half of decision 7 that repairs an
// install created before the pre-create existed.
//
// SQLite alone carries the file, because the other three drivers already build the pinned
// shape, so on those engines this asserts the state at head and stops, the two-shape pattern
// migration_000036 established.
//
// The fixture has to be built by hand. NewMigrator now pre-creates the pinned shape, so no
// database this package can construct still has the driver's, and a test that skipped the
// rewrite would migrate a table that was already correct and pass whatever the migration did.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000041_SchemaMigrationsShape
func TestMigration000041_SchemaMigrationsShape(t *testing.T) {
	h := newIsolatedDB(t)

	if !isSQLite000041() {
		require.NoError(t, h.Migrator.Up(), "migrate to head")
		assertSchemaMigrationsPinnedShape(t, h, "at head")
		return
	}

	require.NoError(t, h.Migrator.Migrate(sqliteVersionBefore000041), "migrate to 000039")
	rewriteSchemaMigrationsToDriverShape000041(t, h)

	// The before-state, asserted rather than assumed: if the rewrite above ever stopped
	// producing the driver's shape, everything below would pass for the wrong reason.
	before := dumpTable(t, h, "schema_migrations")
	require.True(t, before.column(t, "version").Nullable,
		"the fixture must be the driver's shape, where version is nullable")
	require.True(t, before.column(t, "dirty").Nullable,
		"the fixture must be the driver's shape, where dirty is nullable")
	require.Equal(t, schemadump.OriginCreated, before.index("version_unique").Origin,
		"the driver carries uniqueness in a separate CREATE UNIQUE INDEX, not in a primary key")

	// Decision 7's "it is not cosmetic", stated in the direction that is actually true.
	// The driver's shape stores a NULL in either column, and golang-migrate's Version()
	// scans both into Go values and SWALLOWS the scan error, reporting NilVersion: the
	// value that makes it run the whole chain from 000001 against a populated database.
	_, err := h.SQL.Exec("INSERT INTO schema_migrations (version, dirty) VALUES (NULL, NULL)")
	require.NoError(t, err, "the driver's own shape stores a NULL in both columns")
	_, err = h.SQL.Exec("DELETE FROM schema_migrations WHERE version IS NULL")
	require.NoError(t, err, "clear the NULL row before migrating, which the pinned shape would refuse to carry")

	require.NoError(t, h.Migrator.Migrate(41), "apply 000041")
	assertSchemaMigrationsPinnedShape(t, h, "after apply")

	// The recorded version survived the rebuild. Losing it would leave golang-migrate
	// re-running the whole chain against a populated database, which is the worst outcome
	// this migration could have.
	var version int
	var dirty bool
	require.NoError(t, h.SQL.QueryRow("SELECT version, dirty FROM schema_migrations").Scan(&version, &dirty),
		"the version row survived the rebuild")
	assert.Equal(t, 41, version, "the row copied forward is the one golang-migrate wrote before Run()")
	assert.False(t, dirty, "000041 completed, so the dirty marker is cleared")

	// dirty is the column whose NOT NULL is genuinely enforced, and it is the one that
	// matters: a NULL there is what breaks Version()'s scan.
	_, err = h.SQL.Exec("INSERT INTO schema_migrations (version, dirty) VALUES (0, NULL)")
	assert.Error(t, err, "the pinned shape refuses a NULL dirty")

	// version is the surprise, pinned here so nobody later reads NOT NULL as a rejection
	// and "tidies" the migration on that reading. SQLite REPLACES a NULL in an INTEGER
	// PRIMARY KEY with a generated rowid whether or not NOT NULL is declared, so the
	// column never rejects a NULL and never stores one. The agreement's decision 7 says
	// it is refused; the probe behind that claim inserted (NULL, NULL) and read dirty's
	// refusal as version's (probe/sqlite_version_table.out case 5, corrected here).
	_, err = h.SQL.Exec("INSERT INTO schema_migrations (version, dirty) VALUES (NULL, 0)")
	require.NoError(t, err, "SQLite substitutes a rowid for a NULL INTEGER PRIMARY KEY rather than refusing it")
	var nulls int
	require.NoError(t, h.SQL.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version IS NULL").Scan(&nulls))
	assert.Zero(t, nulls, "the substituted rowid is stored, so no NULL version can be read back")
	_, err = h.SQL.Exec("DELETE FROM schema_migrations WHERE version <> 41")
	require.NoError(t, err, "remove the substituted row before the round trip below")

	// The rowid alias, stated directly. Spelled BIGINT the key would be enforced by
	// sqlite_autoindex_schema_migrations_1 and version_unique would sit on top of it, so
	// this is what the single-unique-index assertion above is resting on.
	assert.Equal(t, "INTEGER", dumpTable(t, h, "schema_migrations").column(t, "version").Type,
		"only INTEGER PRIMARY KEY is a rowid alias on SQLite")

	require.NoError(t, h.Migrator.Migrate(sqliteVersionBefore000041), "roll back 000041")
	rolledBack := dumpTable(t, h, "schema_migrations")
	assert.True(t, rolledBack.column(t, "version").Nullable,
		"the down migration restores the driver's own shape")
	assert.Truef(t, rolledBack.index("version_unique").Exists,
		"version_unique is recreated by the down migration, so the shape does not depend on when the process next restarts; got %v",
		rolledBack.Indexes)

	require.NoError(t, h.Migrator.Migrate(41), "re-apply 000041")
	assertSchemaMigrationsPinnedShape(t, h, "after down/up round trip")
}

// rewriteSchemaMigrationsToDriverShape000041 puts the table back the way golang-migrate's
// SQLite driver builds it, carrying the recorded version across, so the database looks like
// an install created before the pre-create existed.
func rewriteSchemaMigrationsToDriverShape000041(t *testing.T, h *isolatedDB) {
	t.Helper()

	var version int
	var dirty bool
	require.NoError(t, h.SQL.QueryRow("SELECT version, dirty FROM schema_migrations").Scan(&version, &dirty),
		"read the recorded version before rewriting the table")

	for _, stmt := range []string{
		"DROP TABLE schema_migrations",
		schemaMigrationsDriverDDL000041,
		schemaMigrationsDriverIndex000041,
	} {
		_, err := h.SQL.Exec(stmt)
		require.NoErrorf(t, err, "rewrite schema_migrations to the driver's shape: %s", stmt)
	}
	_, err := h.SQL.Exec("INSERT INTO schema_migrations (version, dirty) VALUES (?, ?)", version, dirty)
	require.NoError(t, err, "restore the recorded version into the driver-shaped table")
}

func isSQLite000041() bool {
	return dbType() == "" || dbType() == "sqlite"
}
