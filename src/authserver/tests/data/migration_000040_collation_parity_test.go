package datatests

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assertDatabaseDefault000040(t, h, databaseDefaultBefore000040(), "at "+fmt.Sprint(prior))
	assertDefaultsAreAutoNamed000040(t, before, "at "+fmt.Sprint(prior))

	require.NoError(t, h.Migrator.Migrate(40), "apply 000040")

	after := dumpTables000040(t, h)
	assertCollations000040(t, h, collationAfter000040, "after apply")
	assertDatabaseDefault000040(t, h, databaseDefaultAfter000040(), "after apply")
	assertOnlyCollationMoved000040(t, before, after, "after apply")
	assertDefaultsAreNamed000040(t, after, "after apply")
	assertSeededRowsSurvive000040(t, h, clientId, userId, "after apply")

	require.NoErrorf(t, h.Migrator.Migrate(prior), "roll back 000040")

	down := dumpTables000040(t, h)
	assertCollations000040(t, h, collationBefore000040, "after roll back")
	assertDatabaseDefault000040(t, h, databaseDefaultBefore000040(), "after roll back")
	assertOnlyCollationMoved000040(t, before, down, "after roll back")
	assertDefaultsAreAutoNamed000040(t, down, "after roll back")
	assertSeededRowsSurvive000040(t, h, clientId, userId, "after roll back")

	require.NoError(t, h.Migrator.Migrate(40), "re-apply 000040")

	reapplied := dumpTables000040(t, h)
	assertCollations000040(t, h, collationAfter000040, "after down/up round trip")
	assertDatabaseDefault000040(t, h, databaseDefaultAfter000040(), "after down/up round trip")
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
	dupeId := seedClient000035(t, h, "Dupe40Client")
	seedClient000035(t, h, "dupe40client")

	// The catalog shape the refusal must leave exactly as it found it, on SQL Server. Read as
	// a DIFFERENCE rather than as a list of 23 index names, for seam 2's reason: a hand-written
	// list drifts as migrations are added and a difference cannot.
	var shapeBefore []string
	if dbType() == "mssql" {
		shapeBefore = mssqlSchemaShape000040(t, h)
		require.NotEmpty(t, shapeBefore, "the catalog sweep read no index or default at all")
	}

	err := h.Migrator.Migrate(priorVersion000040())
	require.Errorf(t, err, "the down migration must refuse a case-variant pair the new collation permitted")
	assert.Containsf(t, strings.ToLower(err.Error()), "dupe40client",
		"the engine must name the offending value, so an operator can resolve it: %v", err)

	// A refusal that dismantles the schema is not a refusal, it is a wreck. SQL Server's down
	// file drops 6 defaults and 23 indexes and alters 92 columns BEFORE it reaches the
	// CREATE UNIQUE INDEX that fails, and golang-migrate's driver submits the file as one
	// batch with no transaction of its own, so without the SET XACT_ABORT ON and explicit
	// transaction in that file every one of those statements would have autocommitted. The
	// operator would be holding a database with no UNIQUE index on client_identifier, email,
	// subject, code_hash or refresh_token_jti and no way to retry, because the first
	// DROP INDEX would then fail with Msg 3701 on an index that no longer exists.
	//
	// MySQL is deliberately not asserted here. Its refusal fires inside the per-table
	// CONVERT TO, its DDL is not transactional so the tables converted before the failing one
	// stay converted, and each statement is idempotent, so what makes MySQL survivable is the
	// retry below rather than atomicity.
	if dbType() == "mssql" {
		assert.Equalf(t, shapeBefore, mssqlSchemaShape000040(t, h),
			"the refused rollback must leave every index and default constraint exactly as it found them")
		assertCollations000040(t, h, collationAfter000040, "after the refused rollback")
	}

	// And the recovery the file tells the operator to perform actually works. Resolve the
	// duplicate, clear the dirty version by hand, run it again. This is the half that a
	// refusal test asserting only the error message cannot see, and it is the half an
	// operator is standing in.
	_, err = h.SQL.Exec(fmt.Sprintf("DELETE FROM clients WHERE id = %d", dupeId))
	require.NoError(t, err, "resolve the duplicate by hand, as the down file says to")

	// By id, not by identifier: on MySQL the clients table may or may not have been converted
	// back to the folding collation by the failed attempt, and a predicate on
	// client_identifier would mean different things in the two cases.
	require.NoError(t, h.Migrator.Force(40),
		"clear the dirty version the deliberate failure left, which is the operator's own step")
	require.NoError(t, h.Migrator.Migrate(priorVersion000040()),
		"the rollback must succeed once the duplicate is gone; if it does not, the first attempt destroyed something it cannot rebuild")

	assertCollations000040(t, h, collationBefore000040, "after the retried rollback")
}

// TestMigration000040_UpRollsBackALateFailure is the up direction's atomicity boundary. The
// down direction has one already, in TestMigration000040_DownRefusesACaseVariantPair, and the
// up direction is the one whose transaction wrapper had no test at all: every committed case
// migrates successfully, so removing SET XACT_ABORT ON and the explicit transaction from the up
// file left the whole suite green.
//
// The up direction has no failure the DATA can cause, which the file's own comment establishes:
// going from a folding collation to a non-folding one only ever relaxes uniqueness. That is
// exactly why it needs this test rather than exempting it. A lock timeout, a full transaction
// log, a dropped connection or a dependency the migration does not manage all stop it part way,
// and golang-migrate's SQL Server driver submits the file as ONE batch and opens no transaction
// of its own, so every statement before the failure would autocommit. The operator would then be
// holding a database with no UNIQUE index on client_identifier, email, subject, code_hash or
// refresh_token_jti, 90 of 92 columns converted, and no way forward: the retry dies at the first
// DROP INDEX with Msg 3701 on an index that no longer exists.
//
// SQL Server only. MySQL's DDL is not transactional, so its up file cannot be wrapped and does
// not claim to be; what makes MySQL survivable is that each of its statements is idempotent and
// the run can simply be retried. SQLite and PostgreSQL have no 000040 file.
//
// It runs on its own fixture because it deliberately ends the first attempt with a dirty
// migration state, which nothing after it in the same database could survive.
//
// Run via: ./run-tests.sh --type data --db mssql --run TestMigration000040_UpRollsBack
func TestMigration000040_UpRollsBackALateFailure(t *testing.T) {
	if dbType() != "mssql" {
		t.Skipf("%s has no transactional 000040 up file to roll back", dbType())
	}

	h := newFixture000040(t)
	prior := priorVersion000040()
	require.NoErrorf(t, h.Migrator.Migrate(prior), "migrate to %d", prior)

	// The failure, injected as a dependency the migration knows nothing about: an index of the
	// operator's own on a string column 000040 has to ALTER. SQL Server refuses that with
	// Msg 5074, which is the same refusal the migration drops its own 23 indexes to avoid.
	//
	// On users.forgot_password_code_hash deliberately, because it is the LAST column the file
	// alters on users, the second-to-last table in its conversion. The refusal therefore lands
	// after 6 default constraints and 23 indexes have been dropped and 90 of the 92 columns
	// converted. That lateness is the whole point: a failure on the first statement would pass
	// against an unwrapped file too, and prove nothing about the state this one exists to
	// prevent.
	const unmanagedIndex = "idx_operators_own_000040"
	_, err := h.SQL.Exec(fmt.Sprintf(
		"CREATE INDEX [%s] ON [users]([forgot_password_code_hash])", unmanagedIndex))
	require.NoError(t, err, "seed an index 000040 does not manage")

	before := dumpTables000040(t, h)
	shapeBefore := mssqlSchemaShape000040(t, h)
	require.NotEmpty(t, shapeBefore, "the catalog sweep read no index or default at all")

	err = h.Migrator.Migrate(40)
	require.Error(t, err, "an ALTER COLUMN under an index the migration does not manage must fail")

	// Msg 5074 names the COLUMN and not the object: "ALTER TABLE ALTER COLUMN
	// forgot_password_code_hash failed because one or more objects access this column." So the
	// column is what an operator gets, and the assertion is what they actually get rather than
	// what would be more useful. Asserted at all because the failure has to be the one this
	// test injected: any other error would prove the rollback of something else.
	assert.Containsf(t, strings.ToLower(err.Error()), "forgot_password_code_hash",
		"the failure must be the injected one, on the last column of the last-but-one table: %v", err)

	// A failure that dismantles the schema is not a failure, it is a wreck. Compared as the
	// whole dump and the whole catalog shape rather than as a list of what should have stayed,
	// for seam 2's reason: a hand-written list drifts as migrations are added and a difference
	// cannot. Equality rather than assertOnlyCollationMoved000040 because after a rollback the
	// collation must not have moved either.
	assertCollations000040(t, h, collationBefore000040, "after the failed up")
	assert.Equalf(t, shapeBefore, mssqlSchemaShape000040(t, h),
		"the failed up must leave every index and default constraint exactly as it found them")
	assert.Equal(t, before, dumpTables000040(t, h),
		"and every column of every table, including the ones it had already converted before the failure")

	// And the recovery works. Resolve the dependency, clear the dirty version by hand, run it
	// again. This is the half a test asserting only the error message cannot see, and it is the
	// half an operator is standing in: without the transaction, this retry is what dies at
	// Msg 3701.
	_, err = h.SQL.Exec(fmt.Sprintf("DROP INDEX [%s] ON [users]", unmanagedIndex))
	require.NoError(t, err, "resolve the dependency by hand")

	require.NoError(t, h.Migrator.Force(int(prior)),
		"clear the dirty version the deliberate failure left, which is the operator's own step")
	require.NoError(t, h.Migrator.Migrate(40),
		"the retry must reach 40; if it does not, the first attempt destroyed something it cannot rebuild")

	assertCollations000040(t, h, collationAfter000040, "after the retried up")
	assertDefaultsAreNamed000040(t, dumpTables000040(t, h), "after the retried up")
}

// mssqlSchemaShape000040 is every named index and every default constraint on a non-system
// table, as the engine's own catalog reports it, sorted. It exists so a refused rollback can be
// held to leaving the schema untouched without anybody maintaining a list of what "untouched"
// means: the assertion is this value before against this value after.
func mssqlSchemaShape000040(t *testing.T, h *isolatedDB) []string {
	t.Helper()

	rows, err := h.SQL.Query(`
		SELECT 'index ' + t.[name] + '.' + i.[name]
		  FROM sys.indexes i
		  JOIN sys.tables t ON t.[object_id] = i.[object_id] AND t.[is_ms_shipped] = 0
		 WHERE i.[name] IS NOT NULL
		UNION ALL
		SELECT 'default ' + t.[name] + '.' + dc.[name]
		  FROM sys.default_constraints dc
		  JOIN sys.tables t ON t.[object_id] = dc.[parent_object_id] AND t.[is_ms_shipped] = 0`)
	require.NoError(t, err, "sweep indexes and default constraints")
	defer func() { _ = rows.Close() }()

	shape := []string{}
	for rows.Next() {
		var entry string
		require.NoError(t, rows.Scan(&entry), "scan a catalog entry")
		shape = append(shape, entry)
	}
	require.NoError(t, rows.Err(), "iterate the catalog")

	sort.Strings(shape)
	return shape
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
//
// MySQL's needs the same treatment for the same reason, one statement instead of a helper.
// NewMySQLDatabase now creates at the TARGET collation, so a fixture left as the constructor
// built it already holds the value 000040's opening ALTER DATABASE is there to write, and
// deleting that statement outright would change nothing this test can see. Moved back to
// utf8mb4_0900_ai_ci, where a database created before #283 stands, the statement is load
// bearing again. ALTER DATABASE with no name applies to the connection's default database,
// which is what the migration itself relies on.
func newFixture000040(t *testing.T) *isolatedDB {
	t.Helper()
	if dbType() == "mssql" {
		return newPreCreatedMsSQLDB(t, mssqlCollationBefore000040)
	}

	h := newIsolatedDB(t)
	if dbType() == "mysql" {
		_, err := h.SQL.Exec("ALTER DATABASE CHARACTER SET utf8mb4 COLLATE " + mysqlCollationBefore000040)
		require.NoError(t, err, "put the fixture's database default back where a pre-#283 install stands")
	}
	return h
}

// databaseDefaultBefore000040 and databaseDefaultAfter000040 are what the DATABASE-level
// default collation must read either side of the migration. They are not the column
// collations asserted by collationBefore000040 and collationAfter000040: nothing already in
// the schema inherits this value, and what it decides is the collation a string column added
// by a LATER migration lands at when its DDL does not spell COLLATE.
//
// MySQL's moves, because 000040 opens with ALTER DATABASE and the down file closes with the
// inverse, and decision 12 rests entirely on that: it is why a MySQL database an operator
// pre-created at their own collation ends up indistinguishable from one Goiabada created.
//
// SQL Server's does NOT move, and asserting that it does not is the point rather than an
// omission. Measured, ALTER DATABASE ... COLLATE blocks until it times out whenever a second
// session is attached, which is what a running application and its connection pool are, so
// decision 4 accepts the operator's default there and pins all 92 columns explicitly instead.
// A future 000040 that tried to move it would hang a real upgrade and fails here first.
func databaseDefaultBefore000040() string {
	if dbType() == "mssql" {
		return mssqlCollationBefore000040
	}
	return mysqlCollationBefore000040
}

func databaseDefaultAfter000040() string {
	if dbType() == "mssql" {
		return mssqlCollationBefore000040
	}
	return mysqlCollationAfter000040
}

// assertDatabaseDefault000040 reads the database default out of the engine and names the phase
// in the failure, following assertCollations000040.
func assertDatabaseDefault000040(t *testing.T, h *isolatedDB, want string, phase string) {
	t.Helper()
	require.Equalf(t, want, readDatabaseDefaultCollation(t, h.SQL),
		"the database default collation must be %s %s: it decides what a string column added by a later migration inherits", want, phase)
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

// TestMigration000040_PreCreatedDatabaseIsFullyCollated is decision 12's guard, and what it watches
// is a deployment Goiabada did not build. NewMsSQLDatabase creates the database IF NOT EXISTS, so
// an operator who creates it themselves keeps their own collation, and on SQL Server a migration
// that omits COLLATE then lands the column at THAT collation rather than at ours. Measured before
// #283, through the repository's own constructor and migrator against a database pre-created at the
// container's server default: the collation was left untouched, every migration ran to completion,
// and all 92 string columns ended up accent-sensitive and not UTF-8.
//
// The fix is a guard rather than a warning, because there is nothing an operator could usefully do
// about a warning: ALTER DATABASE ... COLLATE blocks until it times out whenever a second session
// is attached, which is what a running application and its connection pool are (decision 4). What
// closes it instead is that EVERY migration spells COLLATE, after which the operator's database
// default never decides anything. So the property is exactly that, and the way to hold it is to
// migrate the FULL chain into a deliberately hostile database and sweep the catalog.
//
// NO ALLOWLIST AND NO COLUMN LIST, deliberately, which is the whole reason this is a test and not a
// review checklist: a future migration that adds a string column without COLLATE fails here on the
// day it is written, rather than on the day somebody notices a lookup answering two ways.
//
// SQL Server only. MySQL's own 000040 repairs the database default, the table defaults and every
// existing column, and a column and a table added afterwards both inherit the repaired default
// (executed against a database pre-created at latin1_swedish_ci). PostgreSQL's database collation
// is deterministic whatever the locale, and SQLite has no database collation at all.
//
// Run via: ./run-tests.sh --type data --db mssql --run TestMigration000040_PreCreated
func TestMigration000040_PreCreatedDatabaseIsFullyCollated(t *testing.T) {
	if dbType() != "mssql" {
		t.Skipf("%s cannot inherit a wrong collation from a pre-created database", dbType())
	}

	// Chosen for what it is not. This is the container's stock server default, and it is
	// case-insensitive, accent-SENSITIVE and not UTF-8, so it differs both from the collation
	// Goiabada pinned before #283 and from the one it pins after. A column that inherited it
	// therefore cannot be mistaken for a column 000040 converted.
	const operatorCollation = "SQL_Latin1_General_CP1_CI_AS"

	// The helper asserts on its own that NewMsSQLDatabase left this collation alone; without
	// that, every assertion below would go on passing for the wrong reason if IF NOT EXISTS
	// ever stopped being IF NOT EXISTS.
	h := newPreCreatedMsSQLDB(t, operatorCollation)

	// Up() rather than a target version: the guard is about every migration in the chain, not
	// about 000040, and the one that breaks it will be a migration nobody has written yet.
	require.NoError(t, h.Migrator.Up(), "migrate the full chain into a pre-created database")

	// The database default is still the operator's, which is what makes the sweep below mean
	// anything: every column it reads is pinned by its own COLLATE clause rather than by
	// anything it inherited. If a migration ever did repair the default, this assertion would
	// fail and the sweep would quietly become vacuous, which is the failure worth catching.
	var dbCollation string
	require.NoError(t, h.SQL.QueryRow(
		`SELECT CAST(DATABASEPROPERTYEX(DB_NAME(), 'Collation') AS NVARCHAR(128))`).Scan(&dbCollation),
		"read the database default after the full chain")
	require.Equal(t, operatorCollation, dbCollation,
		"nothing in the chain moves the database default, and the guard is that no column depends on it")

	assertCollations000040(t, h, collationAfter000040, "full chain into a pre-created database")
}
