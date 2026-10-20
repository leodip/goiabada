package datatests

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration000065_OtpConsecutiveFailures exercises the migration that introduces the
// count of consecutive failed attempts against the enrolled authenticator, which NIST SP
// 800-63B section 3.2.2 bases its disable on (#489). It runs against an ISOLATED database
// of the configured dialect (see migration_testdb_helper_test.go).
//
// The properties, in the order they appear below, following TestMigration000027:
//
//  1. Absent at 000064, so the column found afterwards is the one 000065 added.
//  2. Declared NOT NULL with a default of 0. A default of anything else would be a count
//     of failures for every existing user, and since the verification claim holds the
//     count under record.OtpConsecutiveFailureLimit, it would disable every enrolled
//     authenticator at the deployment.
//  3. A users row that predates the column reads 0 afterwards, which is property 2 proved
//     on the engine rather than in the DDL.
//  4. The down migration works and re-applying is clean. This is where SQL Server's hazard
//     lives: it refuses to drop a column while a default constraint depends on it, so
//     000065 names its constraint and the down migration drops it by name.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000065_OtpConsecutiveFailures
func TestMigration000065_OtpConsecutiveFailures(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(context.Background(), 64), "migrate to 000064")

	// 1. Absent before the migration.
	exists, _, _ := otpConsecutiveFailuresShape000065(t, h)
	assert.False(t, exists, "users.otp_consecutive_failures must not exist at 000064")

	// Seeded with raw SQL rather than CreateUser: the Go model already carries
	// OtpConsecutiveFailures, so an ORM insert at 000064 would target a column that does
	// not exist yet.
	userId := seedPreMigration000065User(t, h)

	require.NoError(t, h.Migrator.Migrate(context.Background(), 65), "apply 000065")

	// 2. NOT NULL, defaulting to 0.
	assertOtpConsecutiveFailuresShape000065(t, h, "after apply")

	// 3. A row that predates the column lands at 0, meaning no failed attempt counted.
	assert.EqualValues(t, 0, readUserOtpConsecutiveFailures000065(t, h, userId),
		"a users row that predates the column must land at 0")

	// 4. Down, then up again. Nothing else in the suite executes a down migration for
	// this number, and this one carries mssql's named-constraint drop.
	require.NoError(t, h.Migrator.Migrate(context.Background(), 64), "roll back 000065")
	require.NoError(t, h.Migrator.Migrate(context.Background(), 65), "re-apply 000065")

	assert.EqualValues(t, 0, readUserOtpConsecutiveFailures000065(t, h, userId),
		"count after the down/up round trip")
	assertOtpConsecutiveFailuresShape000065(t, h, "after down/up round trip")
}

// seedPreMigration000065User inserts a minimal users row with literal SQL, covering
// exactly the NOT NULL columns of the 000064 schema, following
// seedPreMigration000027User, with otp_enabled true so the row is one the verification
// claim's otp_enabled term would accept.
func seedPreMigration000065User(t *testing.T, h *isolatedDB) int64 {
	t.Helper()

	// boolean columns are `boolean` on PostgreSQL and integer-like everywhere else.
	falseLit, trueLit := "0", "1"
	if dbType() == data.Postgres {
		falseLit, trueLit = "false", "true"
	}

	subject := fake.UUID()
	q := fmt.Sprintf(`INSERT INTO users
		(enabled, subject, username, email_verified, phone_number_verified,
		 password_hash, otp_enabled)
		VALUES (%s, '%s', '%s', %s, %s, 'x', %s)`,
		trueLit, subject, "premig65", falseLit, falseLit, trueLit)
	_, err := h.SQL.Exec(q)
	require.NoError(t, err, "seed pre-migration user")

	var id int64
	err = h.SQL.QueryRow(fmt.Sprintf("SELECT id FROM users WHERE subject = '%s'", subject)).Scan(&id)
	require.NoError(t, err, "read back seeded user id")
	return id
}

func readUserOtpConsecutiveFailures000065(t *testing.T, h *isolatedDB, userId int64) int64 {
	t.Helper()
	var count int64
	q := fmt.Sprintf("SELECT otp_consecutive_failures FROM users WHERE id = %d", userId)
	require.NoError(t, h.SQL.QueryRow(q).Scan(&count), "read otp_consecutive_failures")
	return count
}

func assertOtpConsecutiveFailuresShape000065(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	exists, notNull, def := otpConsecutiveFailuresShape000065(t, h)
	require.Truef(t, exists, "[%s] users.otp_consecutive_failures must exist", phase)
	assert.Truef(t, notNull, "[%s] users.otp_consecutive_failures must be NOT NULL", phase)
	assert.Equalf(t, "0", def,
		"[%s] users.otp_consecutive_failures must default to 0, got %q", phase, def)
}

// otpConsecutiveFailuresShape000065 reports whether users.otp_consecutive_failures
// exists, whether it is NOT NULL, and its default expression normalised to a bare
// literal. It follows lastOTPStepShape000027, which likewise needs absence to be a
// result rather than a scan error, since this test asserts absence at 000064. The
// polarity of the nullability flag inverts between engines, so it is resolved per
// dialect here.
func otpConsecutiveFailuresShape000065(t *testing.T, h *isolatedDB) (bool, bool, string) {
	t.Helper()

	const table, col = "users", "otp_consecutive_failures"
	var q string
	switch dbType() {
	case data.MySQL:
		q = fmt.Sprintf(`SELECT IS_NULLABLE, COLUMN_DEFAULT FROM information_schema.columns
			WHERE table_schema = DATABASE() AND table_name = '%s' AND column_name = '%s'`, table, col)
	case data.Postgres:
		q = fmt.Sprintf(`SELECT is_nullable, column_default FROM information_schema.columns
			WHERE table_name = '%s' AND column_name = '%s'`, table, col)
	case data.MSSQL:
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

	var notNull bool
	switch dbType() {
	case data.MySQL, data.Postgres:
		notNull = strings.EqualFold(nullFlag.String, "NO")
	case data.MSSQL:
		notNull = nullFlag.String == "0"
	default: // sqlite
		notNull = nullFlag.String == "1"
	}

	// Defaults come back variously as `0`, `'0'` and `((0))`.
	normalised := strings.Trim(strings.TrimSpace(def.String), "()' ")
	return true, notNull, normalised
}
