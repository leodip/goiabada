package migrator

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// The runner is exercised against a real SQLite database rather than a fake *sql.DB, because half
// of what it claims is about the database: that the bookkeeping write is one transaction, that a
// failing file leaves its earlier statements rolled back, and that the connection goes back to the
// pool. None of that is observable through a mock. SQLite is the one engine reachable in the unit
// tier at all, since modernc.org/sqlite is pure Go; the other three are seam 2's, in the data tier.
//
// The migration sets are testing/fstest.MapFS rather than the real ones, so a case can build the
// exact shape it is about: a five-digit filename, a version present in one direction only, a gap
// between versions.

// schemaMigrationsDDL is sqlitedb's pinned shape for the version table (#284), repeated here
// rather than imported: sqlitedb will import this package in stage 2, and a test importing it back
// would be a cycle.
const schemaMigrationsDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER NOT NULL PRIMARY KEY,
	dirty BOOLEAN NOT NULL
)`

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	// A file rather than :memory:, because a shared-cache memory DSN is process wide and would be
	// shared with any other test that opened one.
	dsn := filepath.Join(t.TempDir(), "migrator_test.db")
	db, err := sql.Open("sqlite", dsn)
	require.NoError(t, err, "open the sqlite database")
	// The same pool shape sqlitedb uses, which is what makes the connection assertions below mean
	// what they say.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.Exec(schemaMigrationsDDL)
	require.NoError(t, err, "create schema_migrations")
	return db
}

func set(files map[string]string) fs.FS {
	m := fstest.MapFS{}
	for name, body := range files {
		m["migrations/"+name] = &fstest.MapFile{Data: []byte(body)}
	}
	return m
}

// threeVersions carries 1, 2 and 5, with a gap, so next and prev have to walk the list rather
// than count. Version 1 is spelled with five digits, as sqlitedb's first migration is.
func threeVersions() fs.FS {
	return set(map[string]string{
		"00001_initial_create.up.sql":   "CREATE TABLE t1 (id INTEGER);",
		"00001_initial_create.down.sql": "DROP TABLE t1;",
		"000002_second.up.sql":          "CREATE TABLE t2 (id INTEGER);",
		"000002_second.down.sql":        "DROP TABLE t2;",
		"000005_fifth.up.sql":           "CREATE TABLE t5 (id INTEGER);",
		"000005_fifth.down.sql":         "DROP TABLE t5;",
	})
}

func newTestMigrator(t *testing.T, db *sql.DB, files fs.FS) *Migrator {
	t.Helper()
	m, err := New(db, files, "migrations", SQLite())
	require.NoError(t, err, "New")
	return m
}

// recorded reads schema_migrations directly. Reading storage is normally the wrong seam, but this
// table IS the runner's contract: what it records, and when, is the behaviour under test.
func recorded(t *testing.T, db *sql.DB) []RecordedVersion {
	t.Helper()
	rows, err := db.Query("SELECT version, dirty FROM schema_migrations ORDER BY version")
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var out []RecordedVersion
	for rows.Next() {
		var r RecordedVersion
		require.NoError(t, rows.Scan(&r.Version, &r.Dirty))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var count int
	require.NoError(t, db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", name).Scan(&count))
	return count == 1
}

// assertPoolReturned is the assertion behind goal 5: the runner takes a connection for one
// operation and gives it back.
//
// InUse and not OpenConnections. The pool here is SetMaxOpenConns(1)/SetMaxIdleConns(1), so
// conn.Close() returns the connection to the pool and correctly leaves OpenConnections at 1,
// idle. An OpenConnections == 0 assertion fails a correct runner, and the only ways to pass it
// are closing or reconfiguring a pool the runner does not own, which is the shape decision 8
// rejected. The data tier's RCSI fixture keeps OpenConnections == 0 because there the fixture
// closes the pool it owns first.
func assertPoolReturned(t *testing.T, db *sql.DB) {
	t.Helper()
	assert.Equal(t, 0, db.Stats().InUse, "the runner gave its connection back")
	// And the pool can still be borrowed from, which a connection returned in a broken state
	// would not allow.
	var one int
	require.NoError(t, db.QueryRow("SELECT 1").Scan(&one), "the pool still serves")
	assert.Equal(t, 1, one)
}

// ---------------------------------------------------------------------------
// Source
// ---------------------------------------------------------------------------

func TestSource_OrdersNumericallyAndReadsAFiveDigitName(t *testing.T) {
	s, err := newSource(threeVersions(), "migrations")
	require.NoError(t, err)

	// 00001 is version 1, not absent. Reading the number as six digits makes sqlitedb's first
	// migration read as missing and the chain start at 000002.
	assert.Equal(t, []int{1, 2, 5}, s.versions)
	assert.Equal(t, 1, s.first())
	assert.Equal(t, 5, s.head())

	// next and prev walk the carried list across the gap, rather than counting.
	assert.Equal(t, 2, s.next(1))
	assert.Equal(t, 5, s.next(2))
	assert.Equal(t, NilVersion, s.next(5))
	assert.Equal(t, 2, s.prev(5))
	assert.Equal(t, NilVersion, s.prev(1))

	assert.True(t, s.exists(1))
	assert.False(t, s.exists(3))
}

func TestSource_RefusesTwoFilesAtOneVersionAndDirection(t *testing.T) {
	_, err := newSource(set(map[string]string{
		"000007_alpha.up.sql": "SELECT 1;",
		"000007_beta.up.sql":  "SELECT 1;",
	}), "migrations")
	require.Error(t, err)
	// Both names, because there is no defensible way to choose between them and the operator has
	// to delete one.
	assert.Contains(t, err.Error(), "000007_alpha.up.sql")
	assert.Contains(t, err.Error(), "000007_beta.up.sql")
	assert.Contains(t, err.Error(), "000007")
}

func TestSource_SkipsAFileThatIsNotAMigration(t *testing.T) {
	s, err := newSource(set(map[string]string{
		"README.md":            "not a migration",
		"000001_only.up.sql":   "SELECT 1;",
		"000001_only.down.sql": "SELECT 1;",
	}), "migrations")
	require.NoError(t, err)
	assert.Equal(t, []int{1}, s.versions)
}

// ---------------------------------------------------------------------------
// Stepping
// ---------------------------------------------------------------------------

func TestMigrate_UpMarksTheVersionBeingApplied(t *testing.T) {
	db := openTestDB(t)
	m := newTestMigrator(t, db, threeVersions())

	require.NoError(t, m.Migrate(2))

	assert.Equal(t, []RecordedVersion{{Version: 2, Dirty: false}}, recorded(t, db))
	assert.True(t, tableExists(t, db, "t1"), "000001 ran")
	assert.True(t, tableExists(t, db, "t2"), "000002 ran")
	assert.False(t, tableExists(t, db, "t5"), "000005 did not")
	assertPoolReturned(t, db)
}

func TestUp_GoesToTheHighestVersionTheBinaryCarries(t *testing.T) {
	db := openTestDB(t)
	m := newTestMigrator(t, db, threeVersions())

	require.NoError(t, m.Up())

	assert.Equal(t, []RecordedVersion{{Version: 5, Dirty: false}}, recorded(t, db))
	assert.Equal(t, 5, m.Head())
	assert.Equal(t, "sqlite", m.Engine())
	assertPoolReturned(t, db)
}

func TestMigrate_DownMarksThePreviousVersionTheEngineCarries(t *testing.T) {
	db := openTestDB(t)
	m := newTestMigrator(t, db, threeVersions())
	require.NoError(t, m.Up())

	// 000005's down runs and the marker lands on 000002, the previous version this set carries,
	// not on 000004. The marker names where the schema now is, which is what an interrupted step
	// has to leave behind for an operator to read.
	require.NoError(t, m.Migrate(2))

	assert.Equal(t, []RecordedVersion{{Version: 2, Dirty: false}}, recorded(t, db))
	assert.False(t, tableExists(t, db, "t5"), "000005's down ran")
	assert.True(t, tableExists(t, db, "t2"))
	assertPoolReturned(t, db)
}

func TestMigrate_DownToTheFloorLeavesTheTableEmpty(t *testing.T) {
	db := openTestDB(t)
	m := newTestMigrator(t, db, threeVersions())
	require.NoError(t, m.Up())

	require.NoError(t, m.Migrate(NilVersion))

	// Empty, not a row saying -1: a clean nil version is an empty table, which is what a database
	// that was never migrated looks like, so the two are indistinguishable by design.
	assert.Empty(t, recorded(t, db))
	assert.False(t, tableExists(t, db, "t1"))
	assert.False(t, tableExists(t, db, "t2"))
	assert.False(t, tableExists(t, db, "t5"))
	assertPoolReturned(t, db)
}

func TestMigrate_NoChangeWhenAlreadyThere(t *testing.T) {
	db := openTestDB(t)
	m := newTestMigrator(t, db, threeVersions())
	require.NoError(t, m.Up())

	assert.ErrorIs(t, m.Migrate(5), ErrNoChange)
	assert.ErrorIs(t, m.Up(), ErrNoChange)
	// And on a database nothing has touched, where current and target are both the nil version.
	fresh := openTestDB(t)
	assert.ErrorIs(t, newTestMigrator(t, fresh, threeVersions()).Migrate(NilVersion), ErrNoChange)
	assertPoolReturned(t, db)
}

func TestMigrate_AVersionWithNoFileInThisDirectionRunsNothingAndStillMoves(t *testing.T) {
	// 000002 has an up and no down, which is what an intentional no-op looked like before the
	// pairing rule, and what the library did here: run nothing, move the marker.
	files := set(map[string]string{
		"000001_first.up.sql":   "CREATE TABLE t1 (id INTEGER);",
		"000001_first.down.sql": "DROP TABLE t1;",
		"000002_second.up.sql":  "CREATE TABLE t2 (id INTEGER);",
	})
	db := openTestDB(t)
	m := newTestMigrator(t, db, files)
	require.NoError(t, m.Up())
	require.True(t, tableExists(t, db, "t2"))

	require.NoError(t, m.Migrate(1))

	assert.Equal(t, []RecordedVersion{{Version: 1, Dirty: false}}, recorded(t, db))
	assert.True(t, tableExists(t, db, "t2"), "000002 has no down file, so nothing undid it")
	assertPoolReturned(t, db)
}

func TestPlan_ListsTheMigrationsThatWouldRunInBothDirections(t *testing.T) {
	db := openTestDB(t)
	m := newTestMigrator(t, db, threeVersions())

	up, err := m.Plan(5)
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2, 5}, up)
	assert.Empty(t, recorded(t, db), "Plan runs nothing")

	require.NoError(t, m.Up())

	down, err := m.Plan(1)
	require.NoError(t, err)
	// Highest first, and it names the down files that run rather than the markers they leave, so
	// an operator sees which migrations are being rolled back.
	assert.Equal(t, []int{5, 2}, down)

	toFloor, err := m.Plan(NilVersion)
	require.NoError(t, err)
	assert.Equal(t, []int{5, 2, 1}, toFloor)

	_, err = m.Plan(5)
	assert.ErrorIs(t, err, ErrNoChange)
	assertPoolReturned(t, db)
}

func TestForce_RecordsAVersionAndRunsNothing(t *testing.T) {
	db := openTestDB(t)
	m := newTestMigrator(t, db, threeVersions())

	require.NoError(t, m.Force(2))

	assert.Equal(t, []RecordedVersion{{Version: 2, Dirty: false}}, recorded(t, db))
	assert.False(t, tableExists(t, db, "t1"), "Force applies no file")
	assertPoolReturned(t, db)
}

// ---------------------------------------------------------------------------
// The version table
// ---------------------------------------------------------------------------

func TestVersion_EmptyTableIsNeverMigrated(t *testing.T) {
	db := openTestDB(t)
	m := newTestMigrator(t, db, threeVersions())

	_, _, err := m.Version()
	assert.ErrorIs(t, err, ErrNilVersion)

	require.NoError(t, m.Migrate(2))
	v, dirty, err := m.Version()
	require.NoError(t, err)
	assert.Equal(t, 2, v)
	assert.False(t, dirty)
	assertPoolReturned(t, db)
}

func TestVersion_RefusesMoreThanOneRow(t *testing.T) {
	db := openTestDB(t)
	_, err := db.Exec("INSERT INTO schema_migrations (version, dirty) VALUES (2, 0), (5, 0)")
	require.NoError(t, err)
	m := newTestMigrator(t, db, threeVersions())

	// Every entry point refuses, because every one of them starts by reading this table and none
	// of them can tell which row the schema matches.
	_, _, err = m.Version()
	var multi ErrMultipleVersions
	require.ErrorAs(t, err, &multi)
	assert.Contains(t, err.Error(), "000002")
	assert.Contains(t, err.Error(), "000005")

	assert.ErrorAs(t, m.Up(), &multi)
	assert.ErrorAs(t, m.Migrate(1), &multi)
	_, planErr := m.Plan(1)
	assert.ErrorAs(t, planErr, &multi)

	assert.False(t, tableExists(t, db, "t1"), "nothing ran")
	assertPoolReturned(t, db)
}

// TestVersionRead_FailsClosed is where decision 5 actually lives: the library's SQLite driver
// swallowed every read error and answered "never migrated", which re-runs the chain from the
// first migration against a database that already has those tables.
func TestVersionRead_FailsClosedRatherThanRerunningTheChain(t *testing.T) {
	t.Run("table missing", func(t *testing.T) {
		db := openTestDB(t)
		_, err := db.Exec("DROP TABLE schema_migrations")
		require.NoError(t, err)
		m := newTestMigrator(t, db, threeVersions())

		_, _, err = m.Version()
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrNilVersion)
		require.Error(t, m.Up())
		_, planErr := m.Plan(5)
		require.Error(t, planErr)

		assert.False(t, tableExists(t, db, "t1"), "no migration file ran")
		assertPoolReturned(t, db)
	})

	t.Run("version unscannable", func(t *testing.T) {
		db := openTestDB(t)
		_, err := db.Exec("DROP TABLE schema_migrations")
		require.NoError(t, err)
		_, err = db.Exec("CREATE TABLE schema_migrations (version TEXT NOT NULL, dirty BOOLEAN NOT NULL)")
		require.NoError(t, err)
		_, err = db.Exec("INSERT INTO schema_migrations (version, dirty) VALUES ('not-a-number', 0)")
		require.NoError(t, err)
		m := newTestMigrator(t, db, threeVersions())

		_, _, err = m.Version()
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrNilVersion)
		require.Error(t, m.Up())

		assert.False(t, tableExists(t, db, "t1"), "no migration file ran")
		assertPoolReturned(t, db)
	})
}

// TestBookkeepingWrite_IsOneTransaction holds the property that makes a failed write harmless.
// A bare DELETE followed by a failing INSERT leaves an EMPTY table, and an empty table reads as
// "never migrated", which is the worst answer available: the chain re-runs from the first
// migration against a populated database.
func TestBookkeepingWrite_IsOneTransaction(t *testing.T) {
	t.Run("the dirty write fails", func(t *testing.T) {
		db := openTestDB(t)
		m := newTestMigrator(t, db, threeVersions())
		require.NoError(t, m.Migrate(1))

		_, err := db.Exec(`CREATE TRIGGER refuse_two BEFORE INSERT ON schema_migrations
			WHEN NEW.version = 2 BEGIN SELECT RAISE(ABORT, 'refused'); END;`)
		require.NoError(t, err)

		require.Error(t, m.Migrate(2))

		assert.Equal(t, []RecordedVersion{{Version: 1, Dirty: false}}, recorded(t, db),
			"the row the database was at survives the failed write")
		assert.False(t, tableExists(t, db, "t2"), "and the schema did not move")
		assertPoolReturned(t, db)
	})

	t.Run("the final clean write fails", func(t *testing.T) {
		db := openTestDB(t)
		m := newTestMigrator(t, db, threeVersions())
		require.NoError(t, m.Migrate(1))

		_, err := db.Exec(`CREATE TRIGGER refuse_clean_two BEFORE INSERT ON schema_migrations
			WHEN NEW.version = 2 AND NEW.dirty = 0 BEGIN SELECT RAISE(ABORT, 'refused'); END;`)
		require.NoError(t, err)

		require.Error(t, m.Migrate(2))

		// The file ran, so the dirty marker is the correct record of where the schema is.
		assert.Equal(t, []RecordedVersion{{Version: 2, Dirty: true}}, recorded(t, db))
		assert.True(t, tableExists(t, db, "t2"))
		assertPoolReturned(t, db)
	})
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

func TestMigrate_AFailingFileLeavesTheDirtyMarkerAndRollsItsOwnStatementsBack(t *testing.T) {
	files := set(map[string]string{
		"000001_first.up.sql":    "CREATE TABLE t1 (id INTEGER);",
		"000001_first.down.sql":  "DROP TABLE t1;",
		"000002_broken.up.sql":   "CREATE TABLE half (id INTEGER);\nTHIS IS NOT SQL;",
		"000002_broken.down.sql": "DROP TABLE half;",
	})
	db := openTestDB(t)
	m := newTestMigrator(t, db, files)

	err := m.Up()
	require.Error(t, err)

	assert.Equal(t, []RecordedVersion{{Version: 2, Dirty: true}}, recorded(t, db))
	assert.True(t, tableExists(t, db, "t1"), "000001 committed")
	// SQLite is the engine whose files run inside a transaction the runner opens, so the
	// statements that did run before the failure are gone.
	assert.False(t, tableExists(t, db, "half"), "the failed file's earlier statements rolled back")
	assertPoolReturned(t, db)
}

func TestMigrate_RefusesADirtyDatabase(t *testing.T) {
	db := openTestDB(t)
	_, err := db.Exec("INSERT INTO schema_migrations (version, dirty) VALUES (2, 1)")
	require.NoError(t, err)
	m := newTestMigrator(t, db, threeVersions())

	var dirty ErrDirty
	require.ErrorAs(t, m.Up(), &dirty)
	assert.Equal(t, 2, dirty.Version)
	assert.ErrorAs(t, m.Migrate(1), &dirty)

	assert.False(t, tableExists(t, db, "t1"), "nothing ran")
	assertPoolReturned(t, db)
}

func TestMigrate_RefusesAVersionThisBinaryDoesNotCarry(t *testing.T) {
	t.Run("recorded by the database", func(t *testing.T) {
		// The database is at a version this binary has no file for, which is what an older
		// release opening a database a newer one migrated looks like (goal 4).
		db := openTestDB(t)
		_, err := db.Exec("INSERT INTO schema_migrations (version, dirty) VALUES (9, 0)")
		require.NoError(t, err)
		m := newTestMigrator(t, db, threeVersions())

		var unknown ErrUnknownVersion
		require.ErrorAs(t, m.Up(), &unknown)
		assert.Equal(t, 9, unknown.Version)
		assert.Equal(t, "sqlite", unknown.Engine)
		assert.Equal(t, 5, unknown.Head)
		assert.Equal(t, 5, unknown.Below)
		assert.Equal(t, NilVersion, unknown.Above, "nothing above 000009 in this set")

		assert.False(t, tableExists(t, db, "t1"), "nothing ran")
		assertPoolReturned(t, db)
	})

	t.Run("asked for as a target", func(t *testing.T) {
		db := openTestDB(t)
		m := newTestMigrator(t, db, threeVersions())
		require.NoError(t, m.Migrate(1))

		var unknown ErrUnknownVersion
		require.ErrorAs(t, m.Migrate(3), &unknown)
		assert.Equal(t, 3, unknown.Version)
		assert.Equal(t, 2, unknown.Below)
		assert.Equal(t, 5, unknown.Above)
		assert.Equal(t, 5, unknown.Head)
		assert.Contains(t, unknown.Error(), "000002")
		assert.Contains(t, unknown.Error(), "000005")

		_, planErr := m.Plan(3)
		assert.ErrorAs(t, planErr, &unknown)

		assert.Equal(t, []RecordedVersion{{Version: 1, Dirty: false}}, recorded(t, db), "nothing moved")
		assertPoolReturned(t, db)
	})
}

// TestErrDirty_NamesTheRecoveryVersionsForTheDirectionThatFailed is the case behind step 1's
// arithmetic. An up step to V marks V, so the two end states are V-1 and V. A down step from N
// marks N-1, so they are N and N-1: the "did not apply" state is the version ABOVE the marker.
// Deriving both from the marker sends an operator recovering a failed down to a version the
// schema was never at.
func TestErrDirty_NamesTheRecoveryVersionsForTheDirectionThatFailed(t *testing.T) {
	t.Run("a failed up step", func(t *testing.T) {
		files := set(map[string]string{
			"000001_first.up.sql":    "CREATE TABLE t1 (id INTEGER);",
			"000001_first.down.sql":  "DROP TABLE t1;",
			"000002_broken.up.sql":   "THIS IS NOT SQL;",
			"000002_broken.down.sql": "SELECT 1;",
		})
		db := openTestDB(t)
		m := newTestMigrator(t, db, files)

		err := m.Up()
		require.Error(t, err)
		var dirty ErrDirty
		require.ErrorAs(t, err, &dirty)
		assert.Equal(t, 2, dirty.Version, "the marker is the version being applied")
		assert.Equal(t, 2, dirty.Applied)
		// 000001 if 000002's statements did not apply, 000002 if they did.
		assert.Contains(t, dirty.Error(), "version 000001 if")
		assert.Contains(t, dirty.Error(), "version 000002 if")
	})

	t.Run("a failed down step", func(t *testing.T) {
		files := set(map[string]string{
			"000001_first.up.sql":    "CREATE TABLE t1 (id INTEGER);",
			"000001_first.down.sql":  "DROP TABLE t1;",
			"000002_second.up.sql":   "CREATE TABLE t2 (id INTEGER);",
			"000002_second.down.sql": "THIS IS NOT SQL;",
		})
		db := openTestDB(t)
		m := newTestMigrator(t, db, files)
		require.NoError(t, m.Up())

		err := m.Migrate(1)
		require.Error(t, err)
		var dirty ErrDirty
		require.ErrorAs(t, err, &dirty)
		assert.Equal(t, 1, dirty.Version, "the marker is the version being returned to")
		assert.Equal(t, 2, dirty.Applied, "the file that ran is 000002's down")
		// 000002 if its statements did not apply, 000001 if they did. Not 000000, which is what
		// arithmetic on the marker alone would name and a version this schema was never at.
		assert.Contains(t, dirty.Error(), "version 000002 if")
		assert.Contains(t, dirty.Error(), "version 000001 if")
		assert.NotContains(t, dirty.Error(), "000000")
	})

	t.Run("read back from the table, where the direction is not recorded", func(t *testing.T) {
		// schema_migrations records the version reached and nothing else, so a marker read back
		// is consistent with two interrupted steps. The message names both rather than guessing.
		e := ErrDirty{Version: 2, Applied: AppliedUnknown, Above: 5}
		assert.Contains(t, e.Error(), "000001")
		assert.Contains(t, e.Error(), "000002")
		assert.Contains(t, e.Error(), "000005")
	})
}

// ---------------------------------------------------------------------------
// The lock
// ---------------------------------------------------------------------------

// TestAdvisoryLockID_MatchesGolangMigrate pins the local copy of the formula to the values
// golang-migrate v4.19.1 produced for Goiabada's own database names, recorded by
// docs/issue-268-migration-runner/probe/lock_ids.go before the library was removed.
//
// This is the pin that cannot be re-derived once the library is gone, and it is not cosmetic.
// During an upgrade one replica runs the previous release and another runs this one; they exclude
// each other only if both compute the same resource name. A different name means both migrate the
// same database at once.
func TestAdvisoryLockID_MatchesGolangMigrate(t *testing.T) {
	cases := []struct {
		name     string
		got      string
		expected string
	}{
		// MySQL passes "<database>:schema_migrations" with no extra parts.
		{"mysql goiabada", advisoryLockID("goiabada:" + migrationsTable), "1954483659"},
		{"mysql goiabada_data", advisoryLockID("goiabada_data:" + migrationsTable), "1481710773"},
		// PostgreSQL mixes in the schema and the table name, joined with NUL bytes.
		{"postgres goiabada", advisoryLockID("goiabada", "public", migrationsTable), "2642984307"},
		{"postgres goiabada_data", advisoryLockID("goiabada_data", "public", migrationsTable), "1038419679"},
		// SQL Server mixes in the schema only.
		{"sqlserver goiabada", advisoryLockID("goiabada", "dbo"), "65607701"},
		{"sqlserver goiabada_data", advisoryLockID("goiabada_data", "dbo"), "467884027"},
	}
	for _, c := range cases {
		assert.Equalf(t, c.expected, c.got,
			"%s: the lock resource name is an inter-process contract with the previous release", c.name)
	}
}

func TestEngines_CarryTheRightPlaceholdersAndTransactionBehaviour(t *testing.T) {
	// SQLite is the one engine whose files run inside a transaction the runner opens; the other
	// three run the file bare, which their migrations are written around.
	assert.True(t, SQLite().txWrap)
	assert.False(t, MySQL("goiabada").txWrap)
	assert.False(t, Postgres("goiabada").txWrap)
	assert.False(t, SQLServer("goiabada").txWrap)

	assert.Equal(t, "?", SQLite().placeholder(1))
	assert.Equal(t, "?", MySQL("goiabada").placeholder(2))
	assert.Equal(t, "$2", Postgres("goiabada").placeholder(2))
	assert.Equal(t, "@p2", SQLServer("goiabada").placeholder(2))

	// SQLite has no cross-process lock statement, so it takes the in-process mutex instead.
	assert.Nil(t, SQLite().lock)
	assert.NotNil(t, MySQL("goiabada").lock)
	assert.NotNil(t, Postgres("goiabada").unlock)
	assert.NotNil(t, SQLServer("goiabada").unlock)
}

// TestRun_AFailedUnlockIsReportedAndTheSessionIsDiscarded covers the two things the deferred
// unlock has to settle. A lock that did not come back blocks every other migrator on the
// database, on PostgreSQL and SQL Server indefinitely, so reporting the operation as successful
// is the answer nobody investigates; and handing the connection back to the pool lends the next
// borrower a session that holds a migration lock for the rest of the process's life, which is
// exactly the leak this package exists to end.
func TestRun_AFailedUnlockIsReportedAndTheSessionIsDiscarded(t *testing.T) {
	unlockErr := errors.New("the lock did not come back")
	eng := SQLite()
	eng.lock = func(context.Context, *sql.Conn) error { return nil }
	eng.unlock = func(context.Context, *sql.Conn) error { return unlockErr }

	db := openTestDB(t)
	m, err := New(db, threeVersions(), "migrations", eng)
	require.NoError(t, err)

	// The contrast that gives the count below its meaning: an operation whose unlock succeeds
	// leaves the connection open and idle in the pool.
	ok := SQLite()
	ok.lock = func(context.Context, *sql.Conn) error { return nil }
	ok.unlock = func(context.Context, *sql.Conn) error { return nil }
	okDB := openTestDB(t)
	okM, err := New(okDB, threeVersions(), "migrations", ok)
	require.NoError(t, err)
	require.NoError(t, okM.Migrate(2))
	assert.Equal(t, 1, okDB.Stats().OpenConnections, "a released lock leaves the session in the pool")

	// The work itself succeeds, so the unlock failure is the whole of the reported error.
	err = m.Migrate(2)
	require.ErrorIs(t, err, unlockErr)

	// Read the pool BEFORE anything else touches it: with SetMaxIdleConns(1) a returned
	// connection stays open and idle, so OpenConnections would be 1, while a discarded one is
	// closed and the count is 0. Any query in between opens a replacement and the difference
	// disappears.
	stats := db.Stats()
	assert.Equal(t, 0, stats.InUse)
	assert.Equal(t, 0, stats.OpenConnections, "the session holding the lock was discarded")

	assert.Equal(t, []RecordedVersion{{Version: 2, Dirty: false}}, recorded(t, db))

	// And the operation's own error is joined rather than replaced when there is one.
	err = m.Migrate(2)
	require.ErrorIs(t, err, ErrNoChange)
	assert.ErrorIs(t, err, unlockErr)

	assertPoolReturned(t, db)
}

func TestRun_ALockedDatabaseIsRefusedAndNothingRuns(t *testing.T) {
	eng := SQLite()
	eng.lock = func(context.Context, *sql.Conn) error { return ErrLocked }
	eng.unlock = func(context.Context, *sql.Conn) error {
		return fmt.Errorf("unlock must not run when the lock was never taken")
	}

	db := openTestDB(t)
	m, err := New(db, threeVersions(), "migrations", eng)
	require.NoError(t, err)

	assert.ErrorIs(t, m.Up(), ErrLocked)
	assert.Empty(t, recorded(t, db))
	assert.False(t, tableExists(t, db, "t1"))
	assertPoolReturned(t, db)
}
