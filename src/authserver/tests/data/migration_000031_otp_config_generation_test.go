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

// TestMigration000031_OTPConfigGeneration exercises the migration that replaces the per-session
// boolean level2_auth_config_has_changed with the per-user counter otp_config_generation and its
// per-session snapshot (#242). It runs against an ISOLATED database of the configured dialect
// (see migration_testdb_helper.go).
//
// §5 seam 4 of the agreement said this seed could not be covered by any tier, on the premise that
// migrations run before any test row exists. That premise is false in this tree: migrations 000024
// through 000030 each seed a pre-migration fixture through newIsolatedDB and then apply the
// migration under test.
//
// The properties, in the order they appear below:
//
//  1. Both columns are absent at 000030, so what is found afterwards is what 000031 added, and
//     level2_auth_config_has_changed is present, so the seed below has something to read.
//  2. **The four combinations of the old flag against the user's otp_enabled.** Decision 9 makes
//     the seed a union of two clauses, and three of these four rows are covered by it:
//     - flag set, otp_enabled set        -> -1, both clauses
//     - flag set, otp_enabled clear      -> -1, decision 8's clause alone. This is the DISABLE
//     case: a user who removed their authenticator has otp_enabled false, so decision 9's
//     clause taken alone would discharge exactly the obligations decision 8 exists to hand over.
//     - flag clear, otp_enabled set      -> -1, decision 9's clause alone. This is the bypass the
//     old writer left open: it flagged only the caller's own sid, so a session that
//     authenticated at level2_optional with amr ["pwd"] while the user had no authenticator was
//     never flagged when the user later enabled OTP elsewhere.
//     - flag clear, otp_enabled clear    -> 0, neither clause.
//     **That fourth row is what tells option C apart from option B**, which seeds every session,
//     and no other case can: under B it would also be -1. The two -1-by-one-clause rows are what
//     make dropping either clause a failure rather than a silent narrowing.
//  3. Both new columns are NOT NULL with a default of 0. A wrong default would pass every
//     behavioural test in the suite, because the ORM always writes both columns explicitly and so
//     never exercises the default.
//  4. A users row that predates the column reads 0, which is property 3 proved on the engine.
//  5. level2_auth_config_has_changed is gone. Its drop and models.UserSession losing the field are
//     one commit: with the field kept and the column gone every session query names a column that
//     is not there, and with the field gone and the column kept every insert omits a NOT NULL
//     column with no default on three engines.
//  6. Down, then up again. That is where SQL Server's default constraints bite in both directions:
//     the down has to drop the two new columns' named constraints before their columns, and the
//     second up has to drop the default constraint the down gave the restored boolean, which the
//     original schema never had.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000031_OTPConfigGeneration
func TestMigration000031_OTPConfigGeneration(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(30), "migrate to 000030")

	// 1. Absent before the migration, and the old column present.
	exists, _, _ := columnShape000031(t, h, "users", "otp_config_generation")
	assert.False(t, exists, "users.otp_config_generation must not exist at 000030")
	exists, _, _ = columnShape000031(t, h, "user_sessions", "otp_config_generation")
	assert.False(t, exists, "user_sessions.otp_config_generation must not exist at 000030")
	exists, _, _ = columnShape000031(t, h, "user_sessions", "level2_auth_config_has_changed")
	require.True(t, exists, "user_sessions.level2_auth_config_has_changed must exist at 000030, "+
		"or the seed under test has nothing to read")

	// Seeded with raw SQL rather than CreateUserSession: the Go model already carries
	// OtpConfigGeneration and no longer carries Level2AuthConfigHasChanged, so an ORM insert at
	// 000030 would name one column that does not exist yet and omit one that does.
	enrolled := seedPreMigration000031User(t, h, true)
	notEnrolled := seedPreMigration000031User(t, h, false)

	flaggedEnrolled := seedPreMigration000031Session(t, h, enrolled, true)
	unflaggedEnrolled := seedPreMigration000031Session(t, h, enrolled, false)
	flaggedNotEnrolled := seedPreMigration000031Session(t, h, notEnrolled, true)
	unflaggedNotEnrolled := seedPreMigration000031Session(t, h, notEnrolled, false)

	require.NoError(t, h.Migrator.Migrate(31), "apply 000031")

	// 2. The four combinations. The three the union covers land at -1 and the fourth at 0.
	assert.EqualValues(t, -1, readSessionGeneration000031(t, h, flaggedEnrolled),
		"flag set and otp_enabled set: both clauses of the seed cover this row")
	assert.EqualValues(t, -1, readSessionGeneration000031(t, h, flaggedNotEnrolled),
		"flag set and otp_enabled clear is the disable case, which decision 8 preserves: dropping "+
			"the level2_auth_config_has_changed clause discharges exactly what it exists to hand over")
	assert.EqualValues(t, -1, readSessionGeneration000031(t, h, unflaggedEnrolled),
		"flag clear and otp_enabled set is the bypass the old per-sid writer left open: dropping "+
			"the otp_enabled clause regresses the seed to option A and leaves it alive for a "+
			"session lifetime after the upgrade")
	assert.EqualValues(t, 0, readSessionGeneration000031(t, h, unflaggedNotEnrolled),
		"flag clear and otp_enabled clear is covered by neither clause: no false level 2 assertion "+
			"is possible for a user with no authenticator, and this row is the only thing that "+
			"tells decision 9's option C apart from option B, which seeds every session")

	// -1 rather than any non-negative value, because the counter starts at 0 and only rises and
	// the readers compare with != rather than <, so -1 never matches and each seeded session is
	// re-prompted exactly once and then promoted like any other. A seed of 0 would discharge
	// every obligation the moment the migration ran.
	assert.EqualValues(t, 0, readUserGeneration000031(t, h, enrolled),
		"the user's counter is untouched by the seed: only sessions are seeded behind it")

	// 3 and 4.
	assertShape000031(t, h, "after apply")
	assert.EqualValues(t, 0, readUserGeneration000031(t, h, notEnrolled),
		"a users row that predates the column must land at generation 0")

	// 5. The old column is gone.
	exists, _, _ = columnShape000031(t, h, "user_sessions", "level2_auth_config_has_changed")
	assert.False(t, exists, "user_sessions.level2_auth_config_has_changed must be gone after 000031")

	// 6. Down, then up again.
	require.NoError(t, h.Migrator.Migrate(30), "roll back 000031")

	exists, notNull, def := columnShape000031(t, h, "user_sessions", "level2_auth_config_has_changed")
	require.True(t, exists, "the down migration must restore level2_auth_config_has_changed")
	assert.True(t, notNull, "the restored column must be NOT NULL, as it was")
	// The literal the engine reports back, not "0" everywhere: postgres declares the column
	// boolean and reports its default as `false`, where the other three declare it numeric,
	// tinyint(1) and BIT and report `0`. Same reason the migration itself is four files.
	restoredDefault, _ := boolLiterals000031()
	assert.Equal(t, restoredDefault, def,
		"the restored column needs a default the original did not have, because existing rows need a value")

	require.NoError(t, h.Migrator.Migrate(31), "re-apply 000031")

	assertShape000031(t, h, "after down/up round trip")
	exists, _, _ = columnShape000031(t, h, "user_sessions", "level2_auth_config_has_changed")
	assert.False(t, exists, "the re-applied migration must drop the restored column, which on SQL "+
		"Server means dropping the default constraint the down migration gave it first")
}

// seedPreMigration000031User inserts a minimal users row with literal SQL, covering exactly the
// NOT NULL columns of the 000030 schema. Literals rather than placeholders because the four
// dialects disagree on placeholder syntax, and the values here are all test-controlled. Follows
// seedPreMigration000027User.
func seedPreMigration000031User(t *testing.T, h *isolatedDB, otpEnabled bool) int64 {
	t.Helper()

	falseLit, trueLit := boolLiterals000031()
	otpLit := falseLit
	if otpEnabled {
		otpLit = trueLit
	}

	// A distinct email per row rather than leaving it NULL, which every other migration test
	// here can do because they seed one user. SQL Server's unique indexes treat two NULLs as
	// equal, so a second NULL-email row is a duplicate key there and nowhere else, and this
	// test needs two users: one with an authenticator and one without.
	subject := uuid.NewString()
	q := fmt.Sprintf(`INSERT INTO users
		(enabled, subject, username, email, email_verified, phone_number_verified,
		 password_hash, otp_enabled)
		VALUES (%s, '%s', '%s', '%s', %s, %s, 'x', %s)`,
		trueLit, subject, "premig31-"+subject[:8], "premig31-"+subject[:8]+"@test.local",
		falseLit, falseLit, otpLit)
	_, err := h.SQL.Exec(q)
	require.NoError(t, err, "seed pre-migration user")

	var id int64
	err = h.SQL.QueryRow(fmt.Sprintf("SELECT id FROM users WHERE subject = '%s'", subject)).Scan(&id)
	require.NoError(t, err, "read back seeded user id")
	return id
}

// seedPreMigration000031Session inserts a user_sessions row at the 000030 schema, which still has
// level2_auth_config_has_changed and does not yet have otp_config_generation.
//
// The datetime literal is one string for all four engines. '2026-01-01 00:00:00' is accepted by
// SQLite's DATETIME, MySQL's datetime(6), PostgreSQL's timestamp(6) without time zone and SQL
// Server's DATETIME2(6) alike, which is why the 000024 test's reason for not seeding this table
// does not apply here: it avoided the fixture rather than the literal.
func seedPreMigration000031Session(t *testing.T, h *isolatedDB, userId int64, flagged bool) string {
	t.Helper()

	falseLit, trueLit := boolLiterals000031()
	flagLit := falseLit
	if flagged {
		flagLit = trueLit
	}

	const ts = "'2026-01-01 00:00:00'"
	identifier := uuid.NewString()
	q := fmt.Sprintf(`INSERT INTO user_sessions
		(session_identifier, started, last_accessed, auth_methods, acr_level, auth_time,
		 ip_address, device_name, device_type, device_os, level2_auth_config_has_changed, user_id)
		VALUES ('%s', %s, %s, 'pwd', 'urn:goiabada:level2_optional', %s,
		 '127.0.0.1', 'device', 'desktop', 'linux', %s, %d)`,
		identifier, ts, ts, ts, flagLit, userId)
	_, err := h.SQL.Exec(q)
	require.NoError(t, err, "seed pre-migration user session")
	return identifier
}

// boolLiterals000031 gives the false and true literals for this dialect's boolean columns.
// PostgreSQL declares otp_enabled and level2_auth_config_has_changed boolean and takes true/false;
// SQLite, MySQL and SQL Server declare them numeric, tinyint(1) and BIT and take 1/0. Each
// spelling is a type error on the other side, which is why migration 000031 is not one file the
// four engines could share.
func boolLiterals000031() (string, string) {
	if dbType() == "postgres" {
		return "false", "true"
	}
	return "0", "1"
}

func readSessionGeneration000031(t *testing.T, h *isolatedDB, sessionIdentifier string) int64 {
	t.Helper()
	var generation int64
	q := fmt.Sprintf("SELECT otp_config_generation FROM user_sessions WHERE session_identifier = '%s'",
		sessionIdentifier)
	require.NoError(t, h.SQL.QueryRow(q).Scan(&generation), "read user_sessions.otp_config_generation")
	return generation
}

func readUserGeneration000031(t *testing.T, h *isolatedDB, userId int64) int64 {
	t.Helper()
	var generation int64
	q := fmt.Sprintf("SELECT otp_config_generation FROM users WHERE id = %d", userId)
	require.NoError(t, h.SQL.QueryRow(q).Scan(&generation), "read users.otp_config_generation")
	return generation
}

func assertShape000031(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	for _, table := range []string{"users", "user_sessions"} {
		exists, notNull, def := columnShape000031(t, h, table, "otp_config_generation")
		require.Truef(t, exists, "[%s] %s.otp_config_generation must exist", phase, table)
		assert.Truef(t, notNull, "[%s] %s.otp_config_generation must be NOT NULL", phase, table)
		assert.Equalf(t, "0", def,
			"[%s] %s.otp_config_generation must default to 0, got %q", phase, table, def)
	}
}

// columnShape000031 reports whether a column exists, whether it is NOT NULL, and its default
// expression normalised to a bare literal. It follows lastOTPStepShape000027, generalised over the
// table and column because this migration touches two tables and has to assert one column's
// absence as well as two columns' presence. The polarity of the nullability flag inverts between
// engines, so it is resolved per dialect here.
func columnShape000031(t *testing.T, h *isolatedDB, table, col string) (bool, bool, string) {
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

	// Defaults come back variously as `0`, `'0'` and `((0))`.
	normalised := strings.Trim(strings.TrimSpace(def.String), "()' ")
	return true, notNull, normalised
}
