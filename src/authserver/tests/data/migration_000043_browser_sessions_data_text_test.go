package datatests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sqliteVersionBefore000043 is 41, which is the last version SQLite's own source carries
// before this one: 000042 is #284's MySQL index-name file and exists on that engine alone,
// and Migrate refuses a target version the engine's source does not have. Same reason
// migration_000041 takes 39 rather than 40.
const sqliteVersionBefore000043 = 41

// columnNamesOf000043 is the dump's column names in the order it sorted them, which is what
// makes "the rebuild kept every column" one assertion naming what is missing rather than a
// length check.
func columnNamesOf000043(s tableShape) []string {
	names := make([]string, 0, len(s.Columns))
	for _, c := range s.Columns {
		names = append(names, c.Name)
	}
	return names
}

// TestMigration000043_BrowserSessionsDataText is seam 5 for the last divergence #284's
// instrument found: browser_sessions.data was declared `longtext` on SQLite, a MySQL type
// name that reached a SQLite migration when 000035 created the table on all four engines.
//
// The migration changes no behaviour, because SQLite assigns affinity by substring and
// "longtext" contains "TEXT". What it changes is the declared type, which is what the catalog
// reports and therefore what the golden file records, so the assertions below are about the
// declared type and about the rebuild carrying everything else across unharmed.
//
// SQLite alone carries the file. On the other three the column is already each engine's own
// spelling, so this asserts the state at head and stops, the two-shape pattern
// migration_000036 established and migration_000041 follows.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000043_BrowserSessionsDataText
func TestMigration000043_BrowserSessionsDataText(t *testing.T) {
	h := newIsolatedDB(t)

	if !isSQLite000041() {
		require.NoError(t, h.Migrator.Up(), "migrate to head")
		// Each of the other three already declares the column in its own vocabulary, and
		// on MySQL that spelling IS longtext: there the name is real and it is the right
		// choice, being the engine's largest string. That is precisely why the SQLite
		// copy was wrong and why this is asserted per engine rather than as "not
		// longtext", which fails on the one engine the word belongs to.
		want := map[string]string{"mysql": "longtext", "postgres": "text", "mssql": "nvarchar(max)"}
		assert.Equalf(t, want[dbType()], dumpTable(t, h, "browser_sessions").column(t, "data").Type,
			"%s declares browser_sessions.data in its own vocabulary and needs no file", dbType())
		return
	}

	require.NoError(t, h.Migrator.Migrate(sqliteVersionBefore000043), "migrate to 000041")

	// The before-state, asserted rather than assumed. Without this the test would pass
	// whatever the migration did, on a column that had already been corrected upstream.
	before := dumpTable(t, h, "browser_sessions")
	require.Equal(t, "longtext", before.column(t, "data").Type,
		"the fixture is the MySQL spelling 000035 wrote into the SQLite chain")
	require.True(t, before.column(t, "data").Nullable, "data is nullable before the rebuild")

	// A row written through the old shape has to survive the rebuild, which is the only
	// thing about this migration that can lose anything.
	_, err := h.SQL.Exec(`INSERT INTO browser_sessions (id, owner, session_id_hash, data, last_accessed, expires_at)
		VALUES (7, 'authserver', 'hash-000043', 'payload-000043', '2026-01-01 00:00:00', '2030-01-01 00:00:00')`)
	require.NoError(t, err, "seed a row through the pre-migration shape")

	require.NoError(t, h.Migrator.Migrate(43), "apply 000043")

	after := dumpTable(t, h, "browser_sessions")
	assert.Equal(t, "TEXT", after.column(t, "data").Type,
		"the declared type is now SQLite's own, which is what the golden file records")

	// Everything the rebuild had to carry across, asserted as a whole rather than one
	// column at a time: a rebuild that drops a column, a nullability or an index is silent,
	// and that is the failure mode DumpTable exists to make visible.
	assert.Equal(t, columnNamesOf000043(before), columnNamesOf000043(after), "the rebuild kept every column")
	for _, name := range columnNamesOf000043(before) {
		if name == "data" {
			continue
		}
		assert.Equalf(t, before.column(t, name), after.column(t, name),
			"%s is untouched by the rebuild", name)
	}
	assert.Equal(t, before.Indexes, after.Indexes,
		"both indexes are recreated exactly as 000035 spelled them; DROP TABLE takes them with it")
	assert.Equal(t, before.ForeignKeys, after.ForeignKeys,
		"browser_sessions references nothing, before or after")

	// data is still nullable, and the AUTOINCREMENT declaration survived: the column is
	// still one the engine numbers.
	assert.True(t, after.column(t, "data").Nullable, "the rebuild did not tighten data to NOT NULL")
	assert.True(t, after.column(t, "id").Generated, "id is still declared AUTOINCREMENT after the rebuild")

	var owner, hash, data string
	require.NoError(t, h.SQL.QueryRow("SELECT owner, session_id_hash, data FROM browser_sessions WHERE id = 7").
		Scan(&owner, &hash, &data), "the seeded row survived the rebuild")
	assert.Equal(t, "authserver", owner)
	assert.Equal(t, "hash-000043", hash)
	assert.Equal(t, "payload-000043", data)

	// The unique index is live on the rebuilt table, which a recreated index can silently
	// fail to be if the CREATE ran against the wrong name.
	_, err = h.SQL.Exec(`INSERT INTO browser_sessions (owner, session_id_hash, last_accessed, expires_at)
		VALUES ('authserver', 'hash-000043', '2026-01-01 00:00:00', '2030-01-01 00:00:00')`)
	assert.Error(t, err, "(owner, session_id_hash) is still unique after the rebuild")

	require.NoError(t, h.Migrator.Migrate(sqliteVersionBefore000043), "roll back 000043")
	rolledBack := dumpTable(t, h, "browser_sessions")
	assert.Equal(t, "longtext", rolledBack.column(t, "data").Type,
		"the down migration restores the previous state, wrong spelling and all")
	assert.Equal(t, before.Indexes, rolledBack.Indexes, "the down migration recreates both indexes too")

	require.NoError(t, h.Migrator.Migrate(43), "re-apply 000043")
	assert.Equal(t, "TEXT", dumpTable(t, h, "browser_sessions").column(t, "data").Type,
		"the shape is the same after a down/up round trip")
}
