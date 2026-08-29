package datatests

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// renamedIndexes000042 is the three foreign-key indexes MySQL named after the constraint
// and the other three engines named after the column in their own 000024. Every one of them
// covers exactly the foreign key's column and is not unique.
var renamedIndexes000042 = []struct {
	table  string
	before string // MySQL's name before 000042; no other engine ever had it
	after  string // the name all four carry afterwards
	column string
}{
	{"codes", "fk_codes_user", "idx_codes_user_id", "user_id"},
	{"refresh_tokens", "fk_refresh_tokens_code", "idx_refresh_tokens_code_id", "code_id"},
	{"user_sessions", "fk_user_sessions_user", "idx_user_sessions_user_id", "user_id"},
}

// auditDetailsType000042 is the declared type audit_logs.details carries at head on each
// engine. Written out per engine rather than compared across them, because "the four engines
// agree" is the cross-engine comparison's claim to make over the golden files and this tier
// can only ever see one engine at a time. What it pins here is that none of the other three
// gained a ceiling while MySQL was losing one.
var auditDetailsType000042 = map[string]string{
	"":         "TEXT", // sqlite, which is what an unset GOIABADA_DB_TYPE means
	"sqlite":   "TEXT",
	"mysql":    "longtext",
	"postgres": "text",
	"mssql":    "nvarchar(max)",
}

// mysqlVersionBefore000042 is 40 and not 41. 000041 is #284's own schema_migrations rebuild
// and it exists on SQLite alone, so 000040 is the last version MySQL's source carries before
// this one, and Migrate refuses a target version the engine's source does not have.
const mysqlVersionBefore000042 = 40

// TestMigration000042_MySQLIndexNamesAndDetailsWidth covers seam 5 for the two divergences
// #284's cross-engine comparison found the first time it ran over the four committed golden
// files, both of them MySQL's alone:
//
//  1. Three foreign-key indexes named fk_* where the other three engines name them idx_*.
//     A name is what a later migration says when it drops an index, so DROP INDEX
//     idx_codes_user_id written today would succeed on three engines and fail on MySQL.
//  2. audit_logs.details declared TEXT, which caps it at 65,535 bytes, where SQLite,
//     PostgreSQL and SQL Server leave it unbounded. That one is not cosmetic and the test
//     below says so in the only way that matters: it writes a 70 KiB audit record and the
//     write is refused before the migration and accepted after it.
//
// The migration file exists on MySQL alone, so this takes the two shapes migration_000036
// established: the full before/apply/down/re-apply sequence there, and the state at head on
// the other three.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000042_MySQLIndexNamesAndDetailsWidth
func TestMigration000042_MySQLIndexNamesAndDetailsWidth(t *testing.T) {
	h := newIsolatedDB(t)

	if !isMySQL000042() {
		require.NoError(t, h.Migrator.Up(), "migrate to head on %s", dbType())
		assertRenamedIndexes000042(t, h, "at head")
		assert.Equalf(t, auditDetailsType000042[dbType()],
			dumpTable(t, h, "audit_logs").column(t, "details").Type,
			"[at head] audit_logs.details is unbounded on %s and stays that way", dbType())
		return
	}

	require.NoError(t, h.Migrator.Migrate(mysqlVersionBefore000042), "migrate to 000040")

	// The before-state, asserted rather than assumed. Everything below passes trivially if
	// the indexes already carried the names this migration gives them.
	for _, ix := range renamedIndexes000042 {
		require.Truef(t, describeIndex(t, h, ix.table, ix.before).Exists,
			"%s.%s must exist at 000040: it is the inline KEY the initial migration wrote to satisfy InnoDB",
			ix.table, ix.before)
		require.Falsef(t, describeIndex(t, h, ix.table, ix.after).Exists,
			"%s.%s must not exist at 000040: its absence on MySQL alone is the divergence",
			ix.table, ix.after)
	}
	require.Equal(t, "text", dumpTable(t, h, "audit_logs").column(t, "details").Type,
		"audit_logs.details must be TEXT at 000040, which is the 64 KiB ceiling this removes")
	require.Error(t, insertAuditLog000042(t, h, 70*1024),
		"a 70 KiB audit record must be refused at 000040: that refusal is what the widening is for")

	require.NoError(t, h.Migrator.Migrate(42), "apply 000042")
	assertRenamedIndexes000042(t, h, "after apply")
	assertAuditDetailsWidened000042(t, h, "after apply")

	// The whole point of the widening, stated as behaviour rather than as a catalog
	// reading: the audit record that could not be written now can be.
	require.NoError(t, insertAuditLog000042(t, h, 70*1024),
		"a 70 KiB audit record must be accepted after 000042")

	// Removed before the roll-back because narrowing LONGTEXT back to TEXT refuses a row
	// that no longer fits, under the strict sql_mode MySQL 8 defaults to. That is what the
	// down migration's comment warns about, and leaving the row here would turn this test
	// into an assertion about the warning rather than about the shape.
	_, err := h.SQL.Exec("DELETE FROM audit_logs")
	require.NoError(t, err, "clear the oversized audit record before rolling back")

	require.NoError(t, h.Migrator.Migrate(mysqlVersionBefore000042), "roll back 000042")
	for _, ix := range renamedIndexes000042 {
		assert.Truef(t, describeIndex(t, h, ix.table, ix.before).Exists,
			"the down migration restores %s.%s", ix.table, ix.before)
		assert.Falsef(t, describeIndex(t, h, ix.table, ix.after).Exists,
			"the down migration removes %s.%s", ix.table, ix.after)
	}
	assert.Equal(t, "text", dumpTable(t, h, "audit_logs").column(t, "details").Type,
		"the down migration restores the TEXT ceiling")

	require.NoError(t, h.Migrator.Migrate(42), "re-apply 000042")
	assertRenamedIndexes000042(t, h, "after down/up round trip")
	assertAuditDetailsWidened000042(t, h, "after down/up round trip")
}

// assertRenamedIndexes000042 is the shape all four engines share at head: each foreign-key
// column indexed under the idx_* name, covering exactly that column, not unique, and with
// the foreign key it exists for still standing.
//
// The foreign key is checked because RENAME INDEX is the one operation here that could
// plausibly disturb it: InnoDB requires an index over a foreign key's columns and refuses to
// drop the last one, so a rename that was really a drop and a create would be visible as a
// missing constraint rather than as a missing index.
func assertRenamedIndexes000042(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()

	for _, ix := range renamedIndexes000042 {
		shape := describeIndex(t, h, ix.table, ix.after)
		require.Truef(t, shape.Exists, "[%s] %s.%s is missing on %s",
			phase, ix.table, ix.after, dbType())
		assert.Equalf(t, []string{ix.column}, shape.Columns,
			"[%s] %s.%s must cover exactly %s", phase, ix.table, ix.after, ix.column)
		assert.Falsef(t, shape.Unique,
			"[%s] %s.%s is a foreign-key index and must not be unique", phase, ix.table, ix.after)

		assert.Falsef(t, describeIndex(t, h, ix.table, ix.before).Exists,
			"[%s] %s.%s is MySQL's old name for the same index and must be gone",
			phase, ix.table, ix.before)

		fk := dumpTable(t, h, ix.table).foreignKey(t, ix.column)
		assert.NotEmptyf(t, fk.RefTable,
			"[%s] the foreign key on %s.%s survived the rename", phase, ix.table, ix.column)
	}
}

// assertAuditDetailsWidened000042 holds the widened column to everything the MODIFY had to
// restate. MODIFY replaces a column's whole definition, so a missing keyword there does not
// fail: it silently drops the nullability, the collation or the default.
func assertAuditDetailsWidened000042(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()

	details := dumpTable(t, h, "audit_logs").column(t, "details")
	assert.Equalf(t, "longtext", details.Type,
		"[%s] audit_logs.details is LONGTEXT, which is MySQL's unbounded string", phase)
	assert.Falsef(t, details.Nullable, "[%s] the MODIFY restated NOT NULL", phase)
	assert.Equalf(t, "utf8mb4_0900_as_cs", details.Collation,
		"[%s] the MODIFY restated the collation #283 pinned", phase)
	assert.Truef(t, details.HasDefault, "[%s] the MODIFY restated the default", phase)
	assert.Containsf(t, details.Default, "{}",
		"[%s] the default is still the empty JSON object, recorded with MySQL's charset introducer", phase)
}

// insertAuditLog000042 writes one audit record whose details payload is size bytes, and
// returns whatever the engine said about it. Written as raw SQL rather than through the data
// layer because the point is what the COLUMN accepts, and CreateAuditLog would go through a
// struct that has no way to be at 000040 in the first place.
func insertAuditLog000042(t *testing.T, h *isolatedDB, size int) error {
	t.Helper()

	_, err := h.SQL.Exec(
		"INSERT INTO audit_logs (created_at, audit_event, details) VALUES (UTC_TIMESTAMP(6), ?, ?)",
		"migration_000042_probe", strings.Repeat("x", size))
	return err
}

func isMySQL000042() bool { return dbType() == "mysql" }
