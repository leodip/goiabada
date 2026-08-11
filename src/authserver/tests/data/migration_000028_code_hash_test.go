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

// TestMigration000028_CodeHashColumns exercises the migration that lets a reset or
// activation link be found by an unsalted SHA-256 of its code, so the link no longer
// carries an email address (#112). It runs against an ISOLATED database of the configured
// dialect (see migration_testdb_helper.go).
//
// The properties, in the order they appear below:
//
//  1. Both columns absent at 000027, so what is found afterwards is what 000028 added.
//  2. Declared NOT NULL defaulting to the empty string. Nullable is not an option:
//     database/sql cannot scan NULL into a Go string, so every read of a pre-existing
//     row would fail.
//  3. Rows that do not mention the column land at the empty string, which is the
//     dormant value the lookups refuse to match. Proved on the engine, not in the DDL.
//  4. Both indexes exist with the shapes §4 chose: plain on the users column, which is
//     empty on most rows, and UNIQUE on the pre-registrations one.
//  5. The pre-existing pre_registrations rows are gone, and the migration itself
//     succeeds. This is the case decision 9 turns on, and the only one that observes the
//     deployment the migration will actually meet: with the rows left in place they would
//     all take the empty default and CREATE UNIQUE INDEX would abort the migration at
//     startup on any deployment holding two or more.
//  6. The down migration works and re-applying is clean. SQL Server's hazard lives here:
//     it refuses to drop a column while an index or a default constraint depends on it,
//     so the down migration drops both first and 000028 names its constraints.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000028_CodeHashColumns
func TestMigration000028_CodeHashColumns(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(27), "migrate to 000027")

	// 1. Absent before the migration.
	exists, _, _ := columnShape000028(t, h, "users", "forgot_password_code_hash")
	assert.False(t, exists, "users.forgot_password_code_hash must not exist at 000027")
	exists, _, _ = columnShape000028(t, h, "pre_registrations", "verification_code_hash")
	assert.False(t, exists, "pre_registrations.verification_code_hash must not exist at 000027")

	// Seeded with raw SQL rather than through the models: both Go structs already carry
	// the new fields, so an ORM insert at 000027 would target columns that do not exist
	// yet.
	userId := seedPreMigration000028User(t, h)

	// TWO pre-registration rows, not one. One '' value satisfies a UNIQUE index on every
	// engine, so a single row would let this whole case pass with the DELETE removed.
	seedPreMigration000028PreRegistration(t, h)
	seedPreMigration000028PreRegistration(t, h)
	require.EqualValues(t, 2, countPreRegistrations000028(t, h), "two rows seeded at 000027")

	// 5a. The migration succeeds. Without the DELETE, CREATE UNIQUE INDEX refuses the two
	// '' values and this line is where the case fails.
	require.NoError(t, h.Migrator.Migrate(28), "apply 000028")

	// 2 and 4.
	assertShape000028(t, h, "after apply")

	// 3a. A users row that predates the column lands at '', meaning no code outstanding.
	//
	// Read with raw SQL rather than GetUserById, as the 000027 test does: the seeded row
	// leaves the nullable string columns as SQL NULL, which the model scanner cannot map
	// into Go strings. The model mapping is covered by the seam 2 cases in user_test.go.
	assert.Equal(t, "", readString000028(t, h,
		fmt.Sprintf("SELECT forgot_password_code_hash FROM users WHERE id = %d", userId)),
		"a users row that predates the column must land at the dormant ''")

	// 5b. The pre-existing pre-registrations are gone.
	assert.EqualValues(t, 0, countPreRegistrations000028(t, h),
		"the up migration must empty pre_registrations, or the UNIQUE index cannot be created")

	// 3b. A pre-registration written without the column lands at '' too. Written after
	// the migration, since the up migration deletes everything written before it.
	preRegId := seedPreMigration000028PreRegistration(t, h)
	assert.Equal(t, "", readString000028(t, h,
		fmt.Sprintf("SELECT verification_code_hash FROM pre_registrations WHERE id = %d", preRegId)),
		"a pre_registrations row written without the column must land at the dormant ''")

	// 6. Down, then up again. The down migration is not a true inverse (the deleted rows
	// are gone for good), but it must run, and on SQL Server it is where the index and
	// named-constraint drops are exercised.
	require.NoError(t, h.Migrator.Migrate(27), "roll back 000028")
	exists, _, _ = columnShape000028(t, h, "users", "forgot_password_code_hash")
	assert.False(t, exists, "users.forgot_password_code_hash must be gone after the down migration")
	exists, _, _ = columnShape000028(t, h, "pre_registrations", "verification_code_hash")
	assert.False(t, exists, "pre_registrations.verification_code_hash must be gone after the down migration")

	require.NoError(t, h.Migrator.Migrate(28), "re-apply 000028")
	assertShape000028(t, h, "after down/up round trip")
}

// assertShape000028 checks both columns and both indexes: NOT NULL defaulting to the
// empty string, a plain index on the users column and a UNIQUE one on the
// pre-registrations column.
func assertShape000028(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()

	for _, c := range []struct{ table, column string }{
		{"users", "forgot_password_code_hash"},
		{"pre_registrations", "verification_code_hash"},
	} {
		exists, notNull, def := columnShape000028(t, h, c.table, c.column)
		require.Truef(t, exists, "[%s] %s.%s must exist", phase, c.table, c.column)
		assert.Truef(t, notNull, "[%s] %s.%s must be NOT NULL: database/sql cannot scan NULL into a Go string",
			phase, c.table, c.column)
		assert.Equalf(t, "", def, "[%s] %s.%s must default to the empty string, got %q",
			phase, c.table, c.column, def)
	}

	exists, unique := indexShape000028(t, h, "users", "idx_users_forgot_password_code_hash")
	require.Truef(t, exists, "[%s] idx_users_forgot_password_code_hash must exist", phase)
	assert.Falsef(t, unique, "[%s] the users index must NOT be unique: the column is '' on most rows, "+
		"and two '' values are refused under a UNIQUE index on all four engines", phase)

	exists, unique = indexShape000028(t, h, "pre_registrations", "idx_pre_reg_verification_code_hash")
	require.Truef(t, exists, "[%s] idx_pre_reg_verification_code_hash must exist", phase)
	assert.Truef(t, unique, "[%s] the pre-registrations index must be UNIQUE, matching the codes.code_hash precedent", phase)
}

// seedPreMigration000028User inserts a minimal users row with literal SQL, covering
// exactly the NOT NULL columns of the 000027 schema. Literals rather than placeholders
// because the four dialects disagree on placeholder syntax, and the values here are all
// test-controlled. Follows seedPreMigration000027User.
func seedPreMigration000028User(t *testing.T, h *isolatedDB) int64 {
	t.Helper()

	// boolean columns are `boolean` on PostgreSQL and integer-like everywhere else.
	falseLit, trueLit := "0", "1"
	if dbType() == "postgres" {
		falseLit, trueLit = "false", "true"
	}

	subject := uuid.NewString()
	q := fmt.Sprintf(`INSERT INTO users
		(enabled, subject, username, email_verified, phone_number_verified,
		 password_hash, otp_enabled)
		VALUES (%s, '%s', '%s', %s, %s, 'x', %s)`,
		trueLit, subject, "premig28", falseLit, falseLit, falseLit)
	_, err := h.SQL.Exec(q)
	require.NoError(t, err, "seed pre-migration user")

	var id int64
	err = h.SQL.QueryRow(fmt.Sprintf("SELECT id FROM users WHERE subject = '%s'", subject)).Scan(&id)
	require.NoError(t, err, "read back seeded user id")
	return id
}

// seedPreMigration000028PreRegistration inserts a pre_registrations row naming only the
// columns the 000027 schema requires, so the row carries no code hash. Returns its id.
func seedPreMigration000028PreRegistration(t *testing.T, h *isolatedDB) int64 {
	t.Helper()

	email := uuid.NewString() + "@example.com"
	q := fmt.Sprintf(`INSERT INTO pre_registrations (email, password_hash) VALUES ('%s', 'x')`, email)
	_, err := h.SQL.Exec(q)
	require.NoError(t, err, "seed pre-registration")

	var id int64
	err = h.SQL.QueryRow(fmt.Sprintf("SELECT id FROM pre_registrations WHERE email = '%s'", email)).Scan(&id)
	require.NoError(t, err, "read back seeded pre-registration id")
	return id
}

func countPreRegistrations000028(t *testing.T, h *isolatedDB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, h.SQL.QueryRow("SELECT COUNT(*) FROM pre_registrations").Scan(&n),
		"count pre_registrations")
	return n
}

func readString000028(t *testing.T, h *isolatedDB, query string) string {
	t.Helper()
	var s string
	require.NoErrorf(t, h.SQL.QueryRow(query).Scan(&s), "read: %s", query)
	return s
}

// columnShape000028 reports whether a column exists, whether it is NOT NULL, and its
// default expression normalised to a bare literal. It follows lastOTPStepShape000027,
// which likewise needs absence to be a result rather than a scan error, since this test
// asserts absence at 000027 and again after the down migration. The polarity of the
// nullability flag inverts between engines, so it is resolved per dialect here.
func columnShape000028(t *testing.T, h *isolatedDB, table, col string) (bool, bool, string) {
	t.Helper()

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
	err := h.SQL.QueryRow(q).Scan(&nullFlag, &def)
	if err == sql.ErrNoRows {
		return false, false, ""
	}
	require.NoErrorf(t, err, "column metadata: %s.%s", table, col)

	notNull := false
	switch dbType() {
	case "mysql", "postgres":
		notNull = strings.EqualFold(nullFlag.String, "NO")
	case "mssql":
		notNull = nullFlag.String == "0"
	default: // sqlite
		notNull = nullFlag.String == "1"
	}

	// An empty-string default comes back variously as ``, `''`, `('')` and
	// `''::character varying`. The cast suffix goes first, then the wrapping.
	normalised := strings.TrimSpace(def.String)
	if i := strings.Index(normalised, "::"); i >= 0 {
		normalised = normalised[:i]
	}
	normalised = strings.Trim(normalised, "()' ")
	return true, notNull, normalised
}

// indexShape000028 reports whether an index exists and whether it is UNIQUE. Both halves
// matter: §4 chose different shapes for the two columns for a reason the data tier is the
// only place to check, since the four engines disagree about what a UNIQUE index does
// with repeated empty values.
func indexShape000028(t *testing.T, h *isolatedDB, table, index string) (bool, bool) {
	t.Helper()

	var q string
	switch dbType() {
	case "mysql":
		// NON_UNIQUE is 1 for a plain index and 0 for a unique one, inverted below. One
		// row per indexed column, so a single-column index yields exactly one.
		q = fmt.Sprintf(`SELECT NON_UNIQUE FROM information_schema.statistics
			WHERE table_schema = DATABASE() AND table_name = '%s' AND index_name = '%s'`, table, index)
	case "postgres":
		q = fmt.Sprintf(`SELECT CASE WHEN i.indisunique THEN 1 ELSE 0 END
			FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
			WHERE c.relname = '%s'`, index)
	case "mssql":
		q = fmt.Sprintf(`SELECT CAST(is_unique AS INT) FROM sys.indexes
			WHERE object_id = OBJECT_ID('dbo.%s') AND name = '%s'`, table, index)
	default: // sqlite
		q = fmt.Sprintf(`SELECT "unique" FROM pragma_index_list('%s') WHERE name = '%s'`, table, index)
	}

	var flag int
	err := h.SQL.QueryRow(q).Scan(&flag)
	if err == sql.ErrNoRows {
		return false, false
	}
	require.NoErrorf(t, err, "index metadata: %s on %s", index, table)

	if dbType() == "mysql" {
		return true, flag == 0
	}
	return true, flag == 1
}
