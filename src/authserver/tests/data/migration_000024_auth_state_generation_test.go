package datatests

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration000024_AuthStateGeneration exercises the migration that introduces
// the per-user authentication generation boundary (#106). It runs against an
// ISOLATED database of the configured dialect (see migration_testdb_helper.go):
// migrate to 000023, seed a row while the column does not yet exist, apply 000024,
// and assert.
//
// Three properties, in the order they appear below:
//
//  1. A row that existed before the migration lands at generation 0. That is what
//     makes tokens issued before the deployment keep working, since the middleware
//     reads a missing generation claim as 0 (decision 15). If the backfill produced
//     anything else, every legacy access token would be rejected at once.
//  2. ALL FOUR columns are NOT NULL with a default of 0. Property 1 proves the engine
//     backfills correctly, but it proves it for one column: a DEFAULT 1 typo on
//     user_sessions, codes or refresh_tokens would invalidate existing authentication
//     state after deployment and pass every other test in the suite, because the ORM
//     always writes the column explicitly and so never exercises the default.
//  3. Every index the revocation sweep relies on exists afterwards. This is not
//     redundant with the behavioural query tests: those stay green with an index
//     accidentally omitted, so nothing else in the suite would notice.
//  4. The down migration works, and re-applying is clean.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000024_AuthStateGeneration
func TestMigration000024_AuthStateGeneration(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(23), "migrate to 000023")

	// Seeded with raw SQL rather than CreateUser: the Go model already carries
	// AuthStateGeneration, so an ORM insert at 000023 would target a column that
	// does not exist yet.
	userId := seedPreMigration000024User(t, h)

	require.NoError(t, h.Migrator.Migrate(24), "apply 000024")

	// 1. Pre-existing rows land at generation 0.
	//
	// Read with raw SQL rather than GetUserById: the seeded row leaves the nullable
	// string columns as SQL NULL, which the model scanner cannot map into Go strings.
	// Enumerating every one of them in the seed would be a lot of noise for an
	// assertion that is about a single column's value. The model mapping is covered
	// separately by the four TestUpdate*_DoesNotClobberAuthStateGeneration tests.
	assert.EqualValues(t, 0, readUserGeneration000024(t, h, userId),
		"a row that predates the migration must land at generation 0")

	// 2. Every column is NOT NULL defaulting to 0, on every engine.
	assertGenerationColumnDefaults000024(t, h, "after apply")

	// 3. Every index the sweep depends on is present.
	assertExpectedIndexes000024(t, h, "after apply")

	// 4. Down, then up again.
	//
	// This case is not in the spec's plan. It is here because nothing else in the
	// suite ever executes a down migration: Migrate() only calls Up(), and the one
	// other migrator test starts from an empty database, so its Migrate(20) goes
	// UP to 20 rather than down to it. That left every down migration in the repo
	// unverified, and this one has an engine-specific hazard worth covering: SQL
	// Server refuses to drop a column while a default constraint depends on it, so
	// 000024 names its default constraints and drops them by name first.
	require.NoError(t, h.Migrator.Migrate(23), "roll back 000024")
	require.NoError(t, h.Migrator.Migrate(24), "re-apply 000024")

	assert.EqualValues(t, 0, readUserGeneration000024(t, h, userId),
		"generation after the down/up round trip")
	assertGenerationColumnDefaults000024(t, h, "after down/up round trip")
	assertExpectedIndexes000024(t, h, "after down/up round trip")
}

// seedPreMigration000024User inserts a minimal users row with literal SQL, covering
// exactly the NOT NULL columns of the 000023 schema. Literals rather than
// placeholders because the four dialects disagree on placeholder syntax, and the
// values here are all test-controlled.
func seedPreMigration000024User(t *testing.T, h *isolatedDB) int64 {
	t.Helper()

	// boolean columns are `boolean` on PostgreSQL and integer-like everywhere else.
	falseLit := "0"
	if dbType() == "postgres" {
		falseLit = "false"
	}

	subject := uuid.NewString()
	username := "premig24"
	q := fmt.Sprintf(`INSERT INTO users
		(enabled, subject, username, email_verified, phone_number_verified,
		 password_hash, otp_enabled)
		VALUES (%s, '%s', '%s', %s, %s, 'x', %s)`,
		falseLit, subject, username, falseLit, falseLit, falseLit)
	_, err := h.SQL.Exec(q)
	require.NoError(t, err, "seed pre-migration user")

	var id int64
	err = h.SQL.QueryRow(fmt.Sprintf("SELECT id FROM users WHERE subject = '%s'", subject)).Scan(&id)
	require.NoError(t, err, "read back seeded user id")
	return id
}

func readUserGeneration000024(t *testing.T, h *isolatedDB, userId int64) int64 {
	t.Helper()
	var gen int64
	q := fmt.Sprintf("SELECT auth_state_generation FROM users WHERE id = %d", userId)
	require.NoError(t, h.SQL.QueryRow(q).Scan(&gen), "read auth_state_generation")
	return gen
}

// generationTables000024 is every table the migration adds the column to.
var generationTables000024 = []string{"users", "user_sessions", "codes", "refresh_tokens"}

// assertGenerationColumnDefaults000024 checks each column's declared shape rather than
// seeding a row per table. The reasoning: the ALTER ... NOT NULL DEFAULT 0 backfill is a
// property of the engine, and the seeded users row above already proves this engine
// applies it. What remains to catch is a per-column DDL typo, which is exactly what the
// declared default and nullability report, and it costs four one-statement queries
// instead of a raw-SQL fixture for clients, sessions, codes and refresh tokens with
// their forty-odd NOT NULL columns and per-dialect datetime and boolean literals.
func assertGenerationColumnDefaults000024(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	for _, table := range generationTables000024 {
		notNull, def := generationColumnShape000024(t, h, table)
		assert.Truef(t, notNull, "[%s] %s.auth_state_generation must be NOT NULL", phase, table)
		assert.Equalf(t, "0", def,
			"[%s] %s.auth_state_generation must default to 0, got %q", phase, table, def)
	}
}

// generationColumnShape000024 returns whether the column is NOT NULL and its default
// expression normalised to a bare literal. Each engine reports both differently, and
// the nullability flag even inverts: SQLite's pragma sets notnull=1 for NOT NULL while
// SQL Server's sys.columns sets is_nullable=0, so the polarity is resolved per dialect
// here rather than by the caller.
func generationColumnShape000024(t *testing.T, h *isolatedDB, table string) (bool, string) {
	t.Helper()

	const col = "auth_state_generation"
	var q string
	switch dbType() {
	case "mysql":
		q = fmt.Sprintf(`SELECT IS_NULLABLE, COLUMN_DEFAULT FROM information_schema.columns
			WHERE table_schema = DATABASE() AND table_name = '%s' AND column_name = '%s'`, table, col)
	case "postgres":
		q = fmt.Sprintf(`SELECT is_nullable, column_default FROM information_schema.columns
			WHERE table_name = '%s' AND column_name = '%s'`, table, col)
	case "mssql":
		q = fmt.Sprintf(`SELECT CAST(c.is_nullable AS VARCHAR(1)), dc.definition
			FROM sys.columns c
			LEFT JOIN sys.default_constraints dc
			  ON dc.parent_object_id = c.object_id AND dc.parent_column_id = c.column_id
			WHERE c.object_id = OBJECT_ID('dbo.%s') AND c.name = '%s'`, table, col)
	default: // sqlite
		q = fmt.Sprintf(`SELECT CAST("notnull" AS TEXT), dflt_value
			FROM pragma_table_info('%s') WHERE name = '%s'`, table, col)
	}

	var nullFlag, def sql.NullString
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&nullFlag, &def),
		"column metadata: %s.%s", table, col)

	notNull := false
	switch dbType() {
	case "mysql", "postgres":
		notNull = strings.EqualFold(nullFlag.String, "NO")
	case "mssql":
		notNull = nullFlag.String == "0"
	default: // sqlite
		notNull = nullFlag.String == "1"
	}

	// Defaults come back variously as `0`, `'0'` and `((0))`.
	normalised := strings.Trim(strings.TrimSpace(def.String), "()' ")
	return notNull, normalised
}

type expectedIndex000024 struct {
	table string
	index string
}

// expectedIndexes000024 lists, per dialect, the indexes that must cover the columns
// the user-scoped revocation sweep queries. The sets differ because the engines
// arrive at the same coverage by different routes: MySQL's initial migration declares
// inline KEYs for its foreign keys, so 000024 only has to add the one column that has
// no foreign key, while the other three engines index nothing automatically.
//
// Mirrors decision 10's table in the spec. If that table and this list disagree, the
// spec is wrong, not this test.
func expectedIndexes000024() []expectedIndex000024 {
	if dbType() == "mysql" {
		return []expectedIndex000024{
			{"codes", "idx_codes_session_identifier"}, // added by 000024
			{"codes", "fk_codes_user"},                // inline KEY, initial migration
			{"refresh_tokens", "fk_refresh_tokens_code"},
			{"refresh_tokens", "idx_refresh_tokens_user_id"}, // added by 000011
			{"user_sessions", "fk_user_sessions_user"},
		}
	}
	// sqlite, postgres and mssql share the same names. On sqlite all five come from
	// 000024; on postgres and mssql idx_refresh_tokens_user_id came from 000011.
	return []expectedIndex000024{
		{"codes", "idx_codes_user_id"},
		{"codes", "idx_codes_session_identifier"},
		{"refresh_tokens", "idx_refresh_tokens_code_id"},
		{"refresh_tokens", "idx_refresh_tokens_user_id"},
		{"user_sessions", "idx_user_sessions_user_id"},
	}
}

func assertExpectedIndexes000024(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	for _, want := range expectedIndexes000024() {
		assert.Truef(t, index000024Exists(t, h, want.table, want.index),
			"[%s] index %s on %s is missing", phase, want.index, want.table)
	}
}

func index000024Exists(t *testing.T, h *isolatedDB, table, index string) bool {
	t.Helper()

	var q string
	switch dbType() {
	case "mysql":
		q = fmt.Sprintf(`SELECT COUNT(*) FROM information_schema.statistics
			WHERE table_schema = DATABASE() AND table_name = '%s' AND index_name = '%s'`, table, index)
	case "postgres":
		q = fmt.Sprintf(`SELECT COUNT(*) FROM pg_indexes
			WHERE tablename = '%s' AND indexname = '%s'`, table, index)
	case "mssql":
		q = fmt.Sprintf(`SELECT COUNT(*) FROM sys.indexes
			WHERE name = '%s' AND object_id = OBJECT_ID('dbo.%s')`, index, table)
	default: // sqlite
		q = fmt.Sprintf(`SELECT COUNT(*) FROM sqlite_master
			WHERE type = 'index' AND name = '%s' AND tbl_name = '%s'`, index, table)
	}

	var n int
	require.NoError(t, h.SQL.QueryRow(q).Scan(&n), "index lookup: %s on %s", index, table)
	return n > 0
}
