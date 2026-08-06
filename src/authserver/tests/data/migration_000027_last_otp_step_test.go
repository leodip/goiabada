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

// TestMigration000027_LastOTPStep exercises the migration that introduces the
// consumed-step marker that makes TOTP codes one-time-use (#111, RFC 6238 5.2). It
// runs against an ISOLATED database of the configured dialect (see
// migration_testdb_helper.go).
//
// The properties, in the order they appear below:
//
//  1. Absent at 000026, so the column found afterwards is the one 000027 added.
//  2. Declared NOT NULL with a default of 0. A default of anything else would be a
//     marker in the future for every existing user, refusing every code until wall
//     time caught up, and it would pass every behavioural test in the suite because
//     the claim always writes the column explicitly and so never exercises the
//     default.
//  3. A users row that predates the column reads 0 afterwards. This is property 2
//     proved on the engine rather than in the DDL, and it is what keeps every
//     enrolled user able to authenticate across the deployment.
//  4. The down migration works and re-applying is clean. This is where SQL Server's
//     hazard lives: it refuses to drop a column while a default constraint depends on
//     it, so 000027 names its constraint and the down migration drops it by name.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000027_LastOTPStep
func TestMigration000027_LastOTPStep(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(26), "migrate to 000026")

	// 1. Absent before the migration.
	exists, _, _ := lastOTPStepShape000027(t, h)
	assert.False(t, exists, "users.last_otp_step must not exist at 000026")

	// Seeded with raw SQL rather than CreateUser: the Go model already carries
	// LastOTPStep, so an ORM insert at 000026 would target a column that does not
	// exist yet.
	userId := seedPreMigration000027User(t, h)

	require.NoError(t, h.Migrator.Migrate(27), "apply 000027")

	// 2. NOT NULL, defaulting to 0.
	assertLastOTPStepShape000027(t, h, "after apply")

	// 3. A row that predates the column lands at 0, meaning no code consumed.
	//
	// Read with raw SQL rather than GetUserById, as the 000024 test does: the seeded
	// row leaves the nullable string columns as SQL NULL, which the model scanner
	// cannot map into Go strings. The model mapping is covered by the seam 2 tests in
	// user_test.go.
	assert.EqualValues(t, 0, readUserLastOTPStep000027(t, h, userId),
		"a users row that predates the column must land at step 0")

	// 4. Down, then up again. Nothing else in the suite executes a down migration
	// except the 000024, 000025 and 000026 tests, and this one carries mssql's
	// named-constraint drop.
	require.NoError(t, h.Migrator.Migrate(26), "roll back 000027")
	require.NoError(t, h.Migrator.Migrate(27), "re-apply 000027")

	assert.EqualValues(t, 0, readUserLastOTPStep000027(t, h, userId),
		"step after the down/up round trip")
	assertLastOTPStepShape000027(t, h, "after down/up round trip")
}

// seedPreMigration000027User inserts a minimal users row with literal SQL, covering
// exactly the NOT NULL columns of the 000026 schema. Literals rather than
// placeholders because the four dialects disagree on placeholder syntax, and the
// values here are all test-controlled. Follows seedPreMigration000024User, with
// otp_enabled true so the row is one the claim's otp_enabled term would accept.
func seedPreMigration000027User(t *testing.T, h *isolatedDB) int64 {
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
		trueLit, subject, "premig27", falseLit, falseLit, trueLit)
	_, err := h.SQL.Exec(q)
	require.NoError(t, err, "seed pre-migration user")

	var id int64
	err = h.SQL.QueryRow(fmt.Sprintf("SELECT id FROM users WHERE subject = '%s'", subject)).Scan(&id)
	require.NoError(t, err, "read back seeded user id")
	return id
}

func readUserLastOTPStep000027(t *testing.T, h *isolatedDB, userId int64) int64 {
	t.Helper()
	var step int64
	q := fmt.Sprintf("SELECT last_otp_step FROM users WHERE id = %d", userId)
	require.NoError(t, h.SQL.QueryRow(q).Scan(&step), "read last_otp_step")
	return step
}

func assertLastOTPStepShape000027(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	exists, notNull, def := lastOTPStepShape000027(t, h)
	require.Truef(t, exists, "[%s] users.last_otp_step must exist", phase)
	assert.Truef(t, notNull, "[%s] users.last_otp_step must be NOT NULL", phase)
	assert.Equalf(t, "0", def,
		"[%s] users.last_otp_step must default to 0, got %q", phase, def)
}

// lastOTPStepShape000027 reports whether users.last_otp_step exists, whether it is
// NOT NULL, and its default expression normalised to a bare literal. It follows
// codeRevokedShape000026, which likewise needs absence to be a result rather than a
// scan error, since this test asserts absence at 000026. The polarity of the
// nullability flag inverts between engines, so it is resolved per dialect here.
func lastOTPStepShape000027(t *testing.T, h *isolatedDB) (bool, bool, string) {
	t.Helper()

	const table, col = "users", "last_otp_step"
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
