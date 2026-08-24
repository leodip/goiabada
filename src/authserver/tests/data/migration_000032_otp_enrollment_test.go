package datatests

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration000032_OTPEnrollment exercises the migration that adds the pending TOTP enrolment
// pair to users (#247). It runs against an ISOLATED database of the configured dialect (see
// migration_testdb_helper.go).
//
// The properties, in the order they appear below:
//
//  1. Both columns are absent at 000031, so what is found afterwards is what 000032 added.
//  2. Both are present and NULLABLE afterwards. Nullable is the whole contract of the pair: NULL
//     is the dormant "nothing pending" state of every user who is not part way through an
//     enrolment, and it is what ClearPendingOTPEnrollment writes back. A NOT NULL column would
//     also have needed a default, which on SQL Server is a named constraint the down migration
//     would have to drop first, so this assertion is what keeps all four files as simple as they
//     are.
//  3. A users row seeded BEFORE the migration reads NULL in both, which is property 2 proved on
//     the engine rather than inferred from its catalogue.
//  4. The down drops both, and a down-then-up round trip lands back at 2 and 3. That is where
//     SQLite's refusal to DROP COLUMN under an index or constraint would bite, and where a named
//     default constraint on SQL Server would too if either file had grown one.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000032_OTPEnrollment
func TestMigration000032_OTPEnrollment(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(31), "migrate to 000031")

	// 1. Absent before the migration.
	for _, col := range otpEnrollmentColumns000032 {
		exists, _, _ := columnShape000031(t, h, "users", col)
		assert.Falsef(t, exists, "users.%s must not exist at 000031", col)
	}

	// Seeded with raw SQL rather than CreateUser: the Go model already carries both fields, so an
	// ORM insert at 000031 would name two columns that do not exist yet. Follows
	// seedPreMigration000031User.
	userId := seedPreMigration000032User(t, h)

	require.NoError(t, h.Migrator.Migrate(32), "apply 000032")

	// 2 and 3.
	assertPendingEnrollmentShape000032(t, h, "after apply")
	assertPendingEnrollmentIsNull000032(t, h, userId, "after apply")

	// 4. Down, then up again.
	require.NoError(t, h.Migrator.Migrate(31), "roll back 000032")
	for _, col := range otpEnrollmentColumns000032 {
		exists, _, _ := columnShape000031(t, h, "users", col)
		assert.Falsef(t, exists, "the down migration must drop users.%s", col)
	}

	require.NoError(t, h.Migrator.Migrate(32), "re-apply 000032")
	assertPendingEnrollmentShape000032(t, h, "after down/up round trip")
	assertPendingEnrollmentIsNull000032(t, h, userId, "after down/up round trip")
}

var otpEnrollmentColumns000032 = []string{
	"otp_enrollment_secret_encrypted",
	"otp_enrollment_issued_at",
}

// seedPreMigration000032User inserts a minimal users row with literal SQL, covering exactly the
// NOT NULL columns of the 000031 schema. Literals rather than placeholders because the four
// dialects disagree on placeholder syntax, and the values here are all test-controlled.
func seedPreMigration000032User(t *testing.T, h *isolatedDB) int64 {
	t.Helper()

	falseLit, trueLit := boolLiterals000031()

	subject := uuid.NewString()
	q := fmt.Sprintf(`INSERT INTO users
		(enabled, subject, username, email, email_verified, phone_number_verified,
		 password_hash, otp_enabled)
		VALUES (%s, '%s', '%s', '%s', %s, %s, 'x', %s)`,
		trueLit, subject, "premig32-"+subject[:8], "premig32-"+subject[:8]+"@test.local",
		falseLit, falseLit, falseLit)
	_, err := h.SQL.Exec(q)
	require.NoError(t, err, "seed pre-migration user")

	var id int64
	err = h.SQL.QueryRow(fmt.Sprintf("SELECT id FROM users WHERE subject = '%s'", subject)).Scan(&id)
	require.NoError(t, err, "read back seeded user id")
	return id
}

// columnShape000031 is reused rather than copied: it is already generalised over the table and the
// column, and it returns exactly what this migration has to assert. Duplicating its forty lines of
// four-dialect catalogue SQL to change a number in the name would be the worse trade.
func assertPendingEnrollmentShape000032(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	for _, col := range otpEnrollmentColumns000032 {
		exists, notNull, _ := columnShape000031(t, h, "users", col)
		require.Truef(t, exists, "[%s] users.%s must exist", phase, col)
		assert.Falsef(t, notNull, "[%s] users.%s must be nullable: NULL is the dormant "+
			"'no enrolment pending' state, and it is what the clear writes back", phase, col)
	}
}

func assertPendingEnrollmentIsNull000032(t *testing.T, h *isolatedDB, userId int64, phase string) {
	t.Helper()
	for _, col := range otpEnrollmentColumns000032 {
		var isNull bool
		q := fmt.Sprintf("SELECT CASE WHEN %s IS NULL THEN 1 ELSE 0 END FROM users WHERE id = %d",
			col, userId)
		require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&isNull), "[%s] read users.%s", phase, col)
		assert.Truef(t, isNull, "[%s] a users row that predates the column must read NULL in %s",
			phase, col)
	}
}
