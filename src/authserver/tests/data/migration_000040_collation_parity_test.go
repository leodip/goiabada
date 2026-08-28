package datatests

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The collations migration 000040 moves between. MySQL and SQL Server only: SQLite compares
// BINARY and PostgreSQL's en_US.utf8 is deterministic, so both already answer `=` the way
// #283 asks for and neither has a 000040 file.
const (
	mysqlCollationBefore000040        = "utf8mb4_0900_ai_ci"
	mysqlUnicodeCollationBefore000040 = "utf8mb4_unicode_ci"
	mysqlCollationAfter000040         = "utf8mb4_0900_as_cs"

	mssqlCollationBefore000040 = "Latin1_General_100_CI_AI_SC_UTF8"
	mssqlCollationAfter000040  = "Latin1_General_100_CS_AS_KS_WS_SC_UTF8"
)

// mysqlUnicodeTables000040 are the three tables 000008, 000014 and 000018 built at
// utf8mb4_unicode_ci while the other 22 were built at utf8mb4_0900_ai_ci. They matter twice:
// the before-dump has to expect their collation rather than the majority one, and the down
// migration has to put them back at it, or down/up stops being a round trip on three tables.
var mysqlUnicodeTables000040 = map[string]bool{
	"audit_logs": true, "client_logos": true, "user_profile_pictures": true,
}

// tables000040 is every table migration 000040 converts: all 25 Goiabada tables.
// schema_migrations is deliberately absent, being golang-migrate's own bookkeeping, and its
// absence is asserted rather than assumed (see TestMigration000040_CollationParity).
var tables000040 = []string{
	"audit_logs", "browser_sessions", "client_logos", "clients", "clients_permissions",
	"codes", "group_attributes", "groups", "groups_permissions", "key_pairs", "permissions",
	"pre_registrations", "redirect_uris", "refresh_tokens", "resources", "settings",
	"user_attributes", "user_consents", "user_profile_pictures", "user_session_clients",
	"user_sessions", "users", "users_groups", "users_permissions", "web_origins",
}

// renamedDefaults000040 are the three default constraints SQL Server auto-named, because
// 000008, 000013 and 000016 added them without one. 000040 has to drop every default
// constraint on a string column before it can alter the column, and it brings these three
// back NAMED, following the convention 000024, 000026, 000029 and 000038 set. The generated
// name differs per database, so only the shape of the old name can be asserted, never the
// name itself.
var renamedDefaults000040 = map[string]string{
	"audit_logs.details":   "df_audit_logs_details",
	"clients.display_name": "df_clients_display_name",
	"clients.website_url":  "df_clients_website_url",
}

// TestMigration000040_CollationParity is #283's goal stated as a test: every string column on
// MySQL and SQL Server ends up at a case- and accent-SENSITIVE collation, so `=` and every
// UNIQUE index over a string mean here what they already mean on SQLite and PostgreSQL, which
// is what RFC 6749 section 1.9 requires of client_id, section 3.3 of scope and OpenID Connect
// Core section 2 of sub.
//
// SQLite and PostgreSQL are skipped because they have no 000040 file: neither engine moves,
// and golang-migrate refuses a target version its source does not carry.
//
// THE FIXTURE IS THE FIRST THING THIS TEST HAS TO GET RIGHT, and on SQL Server it is not
// newIsolatedDB. That helper builds the database through NewMsSQLDatabase, which this change
// makes create at the TARGET collation; no mssql migration before 000040 declares a column
// collation, so all 92 columns would inherit the target from the database default and satisfy
// the post-migration assertion before 000040 existed. Deleting the migration file would leave
// this test green. newPreCreatedMsSQLDB at the OLD collation is what makes the before-dump
// differ from the after-dump, and the before assertion is what proves it did. MySQL needs no
// equivalent: its own migrations pin a table-level collation on all 25 tables, so a table
// built before 000040 carries the old one whatever the database default is.
//
// The assertions, and why each is here:
//
//  1. EVERY string column of EVERY non-system table reports the expected collation, swept out
//     of the catalog with no column list and no allowlist. A hand-written list would go stale
//     the day a migration adds a column, which is exactly the day this needs to fail.
//  2. Before the migration they all report the OLD collation. Without this the sweep is
//     vacuous: a fixture already at the target passes both halves.
//  3. Nothing else about the 25 tables moves, computed as a difference against the before-dump
//     rather than as a hand-written list of what should have stayed. On SQL Server 23 indexes
//     are dropped and recreated and 6 default constraints come off and go back, and a lost
//     index, a flipped uniqueness, a reordered key or a dropped NOT NULL are all silent.
//  4. Seeded rows survive. A shape dump cannot tell ALTER COLUMN apart from DROP COLUMN
//     followed by ADD COLUMN, and the second would blank the column for every existing row.
//  5. The three auto-named default constraints come back named, and go back to auto-named on
//     the way down. That rename is invisible to a definition-only comparison, which is why
//     columnShape carries DefaultName.
//  6. The down migration is a real inverse, per decision 7, and the down/up round trip lands
//     where the first up did.
//
// The one thing the down migration is allowed to do instead is refuse; that is
// TestMigration000040_DownRefusesACaseVariantPair.
//
// Run via: ./run-tests.sh --type data --db mssql --run TestMigration000040
func TestMigration000040_CollationParity(t *testing.T) {
	if !engineMoves000040() {
		t.Skipf("%s already compares strings exactly, so it has no 000040 file", dbType())
	}

	h := newFixture000040(t)
	prior := priorVersion000040()

	require.NoErrorf(t, h.Migrator.Migrate(prior), "migrate to %d", prior)

	clientId := seedClient000035(t, h, "mig40-client")
	userId := seedUser000035(t, h, "mig40user")

	before := dumpTables000040(t, h)
	assertCollations000040(t, h, collationBefore000040, "at "+fmt.Sprint(prior))
	assertDefaultsAreAutoNamed000040(t, before, "at "+fmt.Sprint(prior))

	require.NoError(t, h.Migrator.Migrate(40), "apply 000040")

	after := dumpTables000040(t, h)
	assertCollations000040(t, h, collationAfter000040, "after apply")
	assertOnlyCollationMoved000040(t, before, after, "after apply")
	assertDefaultsAreNamed000040(t, after, "after apply")
	assertSeededRowsSurvive000040(t, h, clientId, userId, "after apply")

	require.NoErrorf(t, h.Migrator.Migrate(prior), "roll back 000040")

	down := dumpTables000040(t, h)
	assertCollations000040(t, h, collationBefore000040, "after roll back")
	assertOnlyCollationMoved000040(t, before, down, "after roll back")
	assertDefaultsAreAutoNamed000040(t, down, "after roll back")
	assertSeededRowsSurvive000040(t, h, clientId, userId, "after roll back")

	require.NoError(t, h.Migrator.Migrate(40), "re-apply 000040")

	reapplied := dumpTables000040(t, h)
	assertCollations000040(t, h, collationAfter000040, "after down/up round trip")
	assertOnlyCollationMoved000040(t, before, reapplied, "after down/up round trip")
	assertDefaultsAreNamed000040(t, reapplied, "after down/up round trip")
	assertSeededRowsSurvive000040(t, h, clientId, userId, "after down/up round trip")
}

// TestMigration000040_DownRefusesACaseVariantPair is decision 7's other half: the down
// migration is a real inverse and is ALLOWED TO FAIL. Once the schema is case-sensitive an
// operator can register MyApp alongside myapp, and the folding collation the down migration
// restores cannot hold both under idx_client_identifier. MySQL refuses the column conversion
// with ERROR 1062 and SQL Server the index rebuild with Msg 1505; both name the offending
// value, and both leave schema_migrations dirty, which blocks every later run until an
// operator clears it by hand.
//
// It runs on its own fixture because it deliberately ends with a dirty migration state, which
// nothing after it in the same database could survive.
func TestMigration000040_DownRefusesACaseVariantPair(t *testing.T) {
	if !engineMoves000040() {
		t.Skipf("%s already compares strings exactly, so it has no 000040 file", dbType())
	}

	h := newFixture000040(t)
	require.NoError(t, h.Migrator.Migrate(40), "apply 000040")

	// The pair that could not have existed before this migration. That it can be inserted at
	// all is the whole of what #283 fixes, so seeding it is also an assertion.
	seedClient000035(t, h, "Dupe40Client")
	seedClient000035(t, h, "dupe40client")

	err := h.Migrator.Migrate(priorVersion000040())
	require.Errorf(t, err, "the down migration must refuse a case-variant pair the new collation permitted")
	assert.Containsf(t, strings.ToLower(err.Error()), "dupe40client",
		"the engine must name the offending value, so an operator can resolve it: %v", err)
}

// engineMoves000040 is the two engines that fold case today and stop after 000040.
func engineMoves000040() bool { return dbType() == "mysql" || dbType() == "mssql" }

// priorVersion000040 is the version immediately before 000040 on this engine. It is not the
// same number on both: mssql has no 000036, 000037 or 000039, and golang-migrate refuses a
// target version its source does not carry.
func priorVersion000040() uint {
	if dbType() == "mssql" {
		return 38
	}
	return 39
}

// newFixture000040 builds the database this test migrates. See the test's comment for why
// SQL Server's is pre-created at the OLD collation rather than left to newIsolatedDB.
func newFixture000040(t *testing.T) *isolatedDB {
	t.Helper()
	if dbType() == "mssql" {
		return newPreCreatedMsSQLDB(t, mssqlCollationBefore000040)
	}
	return newIsolatedDB(t)
}

// collationBefore000040 and collationAfter000040 are what each string column of the named
// table must report, before and after. Before is per table on MySQL, because the schema was
// not uniform: see mysqlUnicodeTables000040.
func collationBefore000040(table string) string {
	if dbType() == "mssql" {
		return mssqlCollationBefore000040
	}
	if mysqlUnicodeTables000040[table] {
		return mysqlUnicodeCollationBefore000040
	}
	return mysqlCollationBefore000040
}

func collationAfter000040(table string) string {
	if dbType() == "mssql" {
		return mssqlCollationAfter000040
	}
	return mysqlCollationAfter000040
}

// assertCollations000040 sweeps every string column of every non-system table out of the
// engine's own catalog and holds each to want(table).
//
// NO COLUMN LIST AND NO ALLOWLIST, deliberately. The set is whatever the catalog reports, so
// a column a future migration adds without spelling COLLATE on SQL Server fails this on the
// day it is written rather than on the day somebody notices a lookup answering two ways.
// schema_migrations is the one table excluded, and it is excluded because 000040 deliberately
// does not convert it; that it holds no string column at all is asserted below.
func assertCollations000040(t *testing.T, h *isolatedDB, want func(string) string, phase string) {
	t.Helper()

	var q string
	switch dbType() {
	case "mysql":
		q = `SELECT TABLE_NAME, COLUMN_NAME, COLLATION_NAME
			FROM information_schema.columns
			WHERE table_schema = DATABASE() AND COLLATION_NAME IS NOT NULL
			ORDER BY TABLE_NAME, COLUMN_NAME`
	default: // mssql
		q = `SELECT t.name, c.name, c.collation_name
			FROM sys.columns c
			JOIN sys.tables t ON t.object_id = c.object_id AND t.is_ms_shipped = 0
			WHERE c.collation_name IS NOT NULL
			ORDER BY t.name, c.name`
	}

	rows, err := h.SQL.Query(q)
	require.NoErrorf(t, err, "[%s] sweep string columns", phase)
	defer func() { _ = rows.Close() }()

	seen := 0
	for rows.Next() {
		var table, column, collation string
		require.NoErrorf(t, rows.Scan(&table, &column, &collation), "[%s] scan string column", phase)

		// The one thing 000040 must not have touched. Converting the table a migration is
		// recorded in, while that migration runs, is not something to discover in production.
		if table == "schema_migrations" {
			assert.Failf(t, "schema_migrations holds a string column",
				"[%s] %s.%s: 000040 deliberately skips this table, so a string column here would go unconverted and unnoticed",
				phase, table, column)
			continue
		}

		seen++
		assert.Equalf(t, want(table), collation, "[%s] %s.%s", phase, table, column)
	}
	require.NoErrorf(t, rows.Err(), "[%s] iterate string columns", phase)

	// 92 string columns were counted on both engines when the migration was written. The
	// assertion is only that the sweep read something, because a sweep that silently matched
	// no rows would pass every collation check above it; the exact number is free to grow.
	require.NotZerof(t, seen, "[%s] the collation sweep read no string columns at all", phase)
}

func dumpTables000040(t *testing.T, h *isolatedDB) map[string]tableShape {
	t.Helper()

	shapes := map[string]tableShape{}
	for _, table := range tables000040 {
		shapes[table] = dumpTable(t, h, table)
	}
	return shapes
}

// assertOnlyCollationMoved000040 is the exhaustive half. It compares the before and after
// dumps of all 25 tables and requires that the ONLY differences anywhere are Collation, and
// DefaultName on the three constraints SQL Server auto-named: same columns, same types, same
// nullability, same default expressions, same indexes with the same uniqueness and key order,
// same foreign keys.
//
// That is what holds the SQL Server file to its 23 index drops and recreations and its 92
// restated nullability keywords. ALTER COLUMN written with neither NULL nor NOT NULL makes a
// column nullable whatever it was, which would trade one divergence for another that nothing
// else in the tree would notice.
func assertOnlyCollationMoved000040(t *testing.T, before, after map[string]tableShape, phase string) {
	t.Helper()

	for _, table := range tables000040 {
		b, a := before[table], after[table]

		require.Lenf(t, a.Columns, len(b.Columns), "[%s] %s gained or lost a column", phase, table)
		for i := range b.Columns {
			bc, ac := b.Columns[i], a.Columns[i]
			require.Equalf(t, bc.Name, ac.Name, "[%s] %s column %d", phase, table, i)

			assert.Equalf(t, bc.Type, ac.Type, "[%s] %s.%s type", phase, table, bc.Name)
			assert.Equalf(t, bc.Nullable, ac.Nullable,
				"[%s] %s.%s changed nullability: ALTER COLUMN written without an explicit NULL/NOT NULL keyword makes a column nullable",
				phase, table, bc.Name)
			assert.Equalf(t, bc.Default, ac.Default, "[%s] %s.%s default", phase, table, bc.Name)

			if _, renamed := renamedDefaults000040[table+"."+bc.Name]; !renamed {
				assert.Equalf(t, bc.DefaultName, ac.DefaultName,
					"[%s] %s.%s default constraint name", phase, table, bc.Name)
			}
		}

		assert.Equalf(t, b.Indexes, a.Indexes, "[%s] %s indexes", phase, table)
		assert.Equalf(t, b.ForeignKeys, a.ForeignKeys, "[%s] %s foreign keys", phase, table)
	}
}

// assertDefaultsAreNamed000040 and assertDefaultsAreAutoNamed000040 pin the rename in both
// directions. SQL Server generates a name like DF__clients__display__09A971A2, and the suffix
// differs per database, so the auto-named side can only be asserted by its prefix. MySQL names
// no default constraint at all, so both are no-ops there and say so rather than skipping
// silently.
func assertDefaultsAreNamed000040(t *testing.T, shapes map[string]tableShape, phase string) {
	t.Helper()
	if dbType() != "mssql" {
		return
	}

	for _, key := range sortedKeys000040(renamedDefaults000040) {
		table, column := splitQualified000040(key)
		got := shapes[table].column(t, column)
		assert.Equalf(t, renamedDefaults000040[key], got.DefaultName,
			"[%s] %s must carry the name a later migration can drop it by, without repeating the catalog lookup",
			phase, key)
	}
}

func assertDefaultsAreAutoNamed000040(t *testing.T, shapes map[string]tableShape, phase string) {
	t.Helper()
	if dbType() != "mssql" {
		return
	}

	for _, key := range sortedKeys000040(renamedDefaults000040) {
		table, column := splitQualified000040(key)
		got := shapes[table].column(t, column)
		assert.Truef(t, strings.HasPrefix(got.DefaultName, "DF__"),
			"[%s] %s must carry the auto-generated name 000008, 000013 and 000016 left; got %q",
			phase, key, got.DefaultName)
	}
}

// assertSeededRowsSurvive000040 reads back the values seeded before the migration. A shape
// dump cannot tell ALTER COLUMN apart from DROP COLUMN followed by ADD COLUMN, and on MySQL
// CONVERT TO CHARACTER SET rewrites every string column of the table in one statement, so the
// row data is the thing the shape assertions cannot see.
func assertSeededRowsSurvive000040(t *testing.T, h *isolatedDB, clientId, userId int64, phase string) {
	t.Helper()

	var identifier string
	require.NoErrorf(t, h.SQL.QueryRow(fmt.Sprintf(
		"SELECT client_identifier FROM clients WHERE id = %d", clientId)).Scan(&identifier),
		"[%s] read back the seeded client", phase)
	assert.Equalf(t, "mig40-client", identifier, "[%s] the seeded client identifier", phase)

	var username, email string
	require.NoErrorf(t, h.SQL.QueryRow(fmt.Sprintf(
		"SELECT username, email FROM users WHERE id = %d", userId)).Scan(&username, &email),
		"[%s] read back the seeded user", phase)
	assert.Equalf(t, "mig40user", username, "[%s] the seeded username", phase)
	assert.Equalf(t, "mig40user@test.local", email, "[%s] the seeded email", phase)
}

func sortedKeys000040(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func splitQualified000040(key string) (table, column string) {
	table, column, _ = strings.Cut(key, ".")
	return table, column
}
