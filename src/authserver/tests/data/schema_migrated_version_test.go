package datatests

import (
	"testing"

	"github.com/leodip/goiabada/core/data/schemadump"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// migratedVersionKnownNumber is a migration every one of the four engines carries, so the
// reader can be held to a number this test chose rather than to whatever the chain happens
// to end at. 000018 is the audit_logs table, present in all four directories.
const migratedVersionKnownNumber = 18

// TestSchemaMigratedVersion_ReadsTheRecordedVersion is seam 4 of #288: the reader behind the
// golden file's migrated= header, against a real database on each engine.
//
// The version rule is worth exactly what this reader is worth. One that answered a benign 0
// when schema_migrations was missing, empty or half-applied would make the rule compare 0
// against 0 and pass on every file forever, which is why each of those three is asserted to
// be an error AND to return 0 alongside it rather than a number a caller might use.
//
// The four cases run in one isolated database and in destructive order, the way
// migration_000041_schema_migrations_test.go does it: creating four would multiply the cost
// on SQL Server, where an isolated database is the expensive part.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestSchemaMigratedVersion_ReadsTheRecordedVersion
func TestSchemaMigratedVersion_ReadsTheRecordedVersion(t *testing.T) {
	h := newIsolatedDB(t)
	d := dumpDialect(t)

	// A number this test chose, so the reader is held to reporting the version actually
	// recorded rather than to agreeing with itself about the head.
	require.NoErrorf(t, h.Migrator.Migrate(migratedVersionKnownNumber),
		"migrate to %d on %s", migratedVersionKnownNumber, dbType())
	got, err := schemadump.MigratedVersion(h.SQL, d)
	require.NoErrorf(t, err, "read the version at %d on %s", migratedVersionKnownNumber, dbType())
	assert.Equal(t, migratedVersionKnownNumber, got, "the reader answers the version recorded on %s", dbType())

	// At head, held to golang-migrate's own reader rather than to a number written here.
	// The four heads legitimately differ, so an expectation spelled out per engine would be
	// a second copy of that list to keep current, and the useful claim is that this reader
	// and the migrator agree about the database in front of them.
	require.NoErrorf(t, h.Migrator.Up(), "migrate to head on %s", dbType())
	head, dirty, err := h.Migrator.Version()
	require.NoErrorf(t, err, "golang-migrate reports the head version on %s", dbType())
	require.Falsef(t, dirty, "the chain applied cleanly on %s", dbType())
	got, err = schemadump.MigratedVersion(h.SQL, d)
	require.NoErrorf(t, err, "read the head version on %s", dbType())
	assert.Equalf(t, int(head), got, "the reader agrees with golang-migrate about the head on %s", dbType())
	require.Greaterf(t, got, migratedVersionKnownNumber,
		"the head is above %d, so the two reads above are not the same assertion twice on %s",
		migratedVersionKnownNumber, dbType())

	// Dirty: migration `head` failed part way, so the catalog is a half-applied one and is
	// not a record of any migration chain. Recording it would commit a golden file
	// describing a schema no chain produces.
	setSchemaMigrationsDirty(t, h, true)
	got, err = schemadump.MigratedVersion(h.SQL, d)
	assert.Errorf(t, err, "a dirty row is refused on %s", dbType())
	assert.Zerof(t, got, "a refusal answers 0 alongside the error and never a usable version on %s", dbType())
	setSchemaMigrationsDirty(t, h, false)

	// Empty: an unmigrated database. golang-migrate reports NilVersion for this and a reader
	// that mapped it to 0 would let a golden file be generated from a database with no
	// tables in it.
	//
	// The message is asserted, not just the refusal. An empty table and a row recording
	// version 0 are two different diagnoses, and either branch alone refuses both, so a test
	// asking only "was there an error" would leave one of them unexercised.
	_, err = h.SQL.Exec("DELETE FROM schema_migrations")
	require.NoErrorf(t, err, "empty schema_migrations on %s", dbType())
	got, err = schemadump.MigratedVersion(h.SQL, d)
	if assert.Errorf(t, err, "an empty schema_migrations is refused on %s", dbType()) {
		assert.Containsf(t, err.Error(), "holds no row",
			"the refusal names the empty table rather than a version on %s", dbType())
	}
	assert.Zerof(t, got, "a refusal answers 0 alongside the error on %s", dbType())

	// A row recording version 0, which is the table populated but naming no migration. It
	// is not a version golang-migrate writes, and it is precisely the value a lenient
	// reader would have invented, so a file encoded from it would claim migration 0.
	_, err = h.SQL.Exec("INSERT INTO schema_migrations (version, dirty) VALUES (0, " + boolLiteral(false) + ")")
	require.NoErrorf(t, err, "record version 0 on %s", dbType())
	got, err = schemadump.MigratedVersion(h.SQL, d)
	if assert.Errorf(t, err, "version 0 is refused on %s", dbType()) {
		assert.Containsf(t, err.Error(), "which is not a migration this repository has",
			"the refusal names the version rather than the empty table on %s", dbType())
	}
	assert.Zerof(t, got, "a refusal answers 0 alongside the error on %s", dbType())

	// A real failure of the query itself, which is the case the whole design rests on: the
	// reader must distinguish "could not read" from "read a zero". Forced by removing the
	// table, the same fault a wrong connection or a missing permission produces.
	_, err = h.SQL.Exec("DROP TABLE schema_migrations")
	require.NoErrorf(t, err, "drop schema_migrations on %s", dbType())
	got, err = schemadump.MigratedVersion(h.SQL, d)
	assert.Errorf(t, err, "a query failure is an error and not a version on %s", dbType())
	assert.Zerof(t, got, "a query failure answers 0 alongside the error on %s", dbType())

	_, err = schemadump.MigratedVersion(h.SQL, schemadump.Dialect("oracle"))
	assert.Error(t, err, "an unrecognised dialect is refused before any query runs")
}

// setSchemaMigrationsDirty flips the recorded row's dirty marker.
func setSchemaMigrationsDirty(t *testing.T, h *isolatedDB, dirty bool) {
	t.Helper()

	literal := boolLiteral(dirty)
	_, err := h.SQL.Exec("UPDATE schema_migrations SET dirty = " + literal)
	require.NoErrorf(t, err, "set dirty = %s on %s", literal, dbType())
}

// boolLiteral is how the configured engine spells a boolean in a statement.
//
// Spelled per engine because SQL Server has no boolean: dirty is BIT there and `dirty =
// true` is a syntax error, while the other three take the keyword. Written into the
// statement rather than passed as a parameter because the four drivers spell placeholders
// three different ways.
func boolLiteral(v bool) string {
	if dbType() == "mssql" {
		if v {
			return "1"
		}
		return "0"
	}
	if v {
		return "true"
	}
	return "false"
}
