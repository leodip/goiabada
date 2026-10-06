package datatests

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000059 sits between. Literals, as for 000048 and 000056: nothing in
// production code names this number.
const (
	beforeDropPhoneVerificationCode000059 = 58
	dropPhoneVerificationCode000059       = 59
)

// The two columns 000059 drops, left over from the SMS phone verification v0.7 removed (#471
// decision 8).
var phoneVerificationCodeColumns000059 = []string{
	"phone_number_verification_code_encrypted",
	"phone_number_verification_code_issued_at",
}

// TestMigration000059_DropPhoneVerificationCode exercises the migration that removes
// users.phone_number_verification_code_encrypted and users.phone_number_verification_code_issued_at
// (#471 decisions 8 and 9), against a REAL engine of the configured dialect (see
// migration_testdb_helper_test.go). Nothing has read or written either column since v0.7.
//
// The properties, in order:
//
//  1. Both columns are gone from the catalog once 000059 has run, and they are the only thing
//     about the table that moved. Read from the engine's own catalog rather than from a query
//     failing.
//
//  2. A user written BEFORE the drop, holding a stale ciphertext and issued-at in both columns,
//     reads back afterwards through the data layer with the rest of its row intact: its password
//     hash and its encrypted TOTP seed, which shares the _encrypted suffix with the column dropped.
//
//  3. The down migration restores the table to exactly the shape 000058 built, both columns'
//     type, nullability, collation and the absence of a default included, so the previous
//     release, whose user statements still name both columns, can read a rolled-back database.
//     The shape comes back, never the values: the row reads NULL in both. Compared against the
//     shape read before the drop on this same engine rather than against a per-engine literal, as
//     000048's and 000056's tests do.
//
//  4. 000059 applies again after a round trip.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000059_DropPhoneVerificationCode
func TestMigration000059_DropPhoneVerificationCode(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	// FORWARD to 000058 from an empty database, never down to it, so that `before` is what the
	// chain built and not what 000059's own down wrote (see 000048's test for the measured case).
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeDropPhoneVerificationCode000059),
		"migrate an empty database up to 000058 on %s", dbType())

	before := dumpTable(t, h, "users")
	for _, col := range phoneVerificationCodeColumns000059 {
		_, ok := schemadump.TableShape(before).Column(col)
		require.Truef(t, ok,
			"users.%s must exist at 000058 on %s, or this migration has nothing to drop and every assertion below is vacuous",
			col, dbType())
	}

	// Seeded through the data layer, which names neither column any more, and then the two
	// columns filled with SQL, the way a row from before v0.7 can still hold them.
	const seed = "JBSWY3DPEHPK3PXP"
	encryptedSeed, err := dataCipher.Encrypt(seed)
	require.NoError(t, err, "the process cipher is initialized in TestMain")
	user := &record.User{
		Enabled:            true,
		Subject:            fake.UUID(),
		Username:           "mig59user",
		Email:              "mig59-" + fake.UUID() + "@example.com",
		PasswordHash:       "a-stored-password-hash",
		OTPEnabled:         true,
		OTPSecretEncrypted: encryptedSeed,
	}
	require.NoErrorf(t, h.DB.CreateUser(ctx, nil, user), "seed a user at 000058 on %s", dbType())

	_, err = h.SQL.Exec(fmt.Sprintf(
		`UPDATE users SET phone_number_verification_code_encrypted = %s, phone_number_verification_code_issued_at = %s WHERE id = %d`,
		placeholder000059(1), placeholder000059(2), user.Id),
		[]byte("a-stale-phone-code-ciphertext"), time.Now().UTC().Truncate(time.Second))
	require.NoErrorf(t, err, "fill the two phone verification columns at 000058 on %s", dbType())
	for _, col := range phoneVerificationCodeColumns000059 {
		require.Falsef(t, columnIsNull000059(t, h, col, user.Id),
			"the seed must leave users.%s holding a value on %s, or the roll back's NULL proves nothing", col, dbType())
	}

	require.NoErrorf(t, h.Migrator.Migrate(ctx, dropPhoneVerificationCode000059), "apply 000059 on %s", dbType())

	// 1. Gone, and nothing else moved.
	afterDrop := schemadump.TableShape(dumpTable(t, h, "users"))
	for _, col := range phoneVerificationCodeColumns000059 {
		_, stillThere := afterDrop.Column(col)
		assert.Falsef(t, stillThere, "users.%s is still in the catalog on %s after 000059", col, dbType())
	}

	wantAfterDrop := schemadump.TableShape(before)
	wantAfterDrop.Columns = slices.DeleteFunc(slices.Clone(wantAfterDrop.Columns),
		func(c schemadump.ColumnShape) bool {
			return slices.Contains(phoneVerificationCodeColumns000059, c.Name)
		})
	assert.Equalf(t, wantAfterDrop, afterDrop,
		"000059 must drop the two phone verification columns and touch nothing else of users on %s", dbType())

	// 2. The user survives, its seed included.
	got, err := h.DB.GetUserById(ctx, nil, user.Id)
	require.NoErrorf(t, err, "read users.id=%d back after the drop on %s", user.Id, dbType())
	require.NotNilf(t, got, "users.id=%d is gone on %s; this migration deletes no rows", user.Id, dbType())
	assert.Equal(t, user.Email, got.Email)
	assert.Equal(t, "a-stored-password-hash", got.PasswordHash)
	assert.True(t, got.OTPEnabled)
	decrypted, err := dataCipher.Decrypt(got.OTPSecretEncrypted)
	require.NoErrorf(t, err, "the encrypted TOTP seed must still decrypt after the drop on %s", dbType())
	assert.Equalf(t, seed, decrypted,
		"000059 must leave users.otp_secret_encrypted alone on %s: it shares the suffix with the column dropped", dbType())

	// 3. Roll back: the table 000058 built, and the row reads NULL in both restored columns.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeDropPhoneVerificationCode000059),
		"roll back 000059 on %s", dbType())

	assert.Equalf(t, before, dumpTable(t, h, "users"),
		"000059's down must restore users to the shape 000058 built on %s: both columns' type, "+
			"nullability and collation, no default, and every index", dbType())
	for _, col := range phoneVerificationCodeColumns000059 {
		assert.Truef(t, columnIsNull000059(t, h, col, user.Id),
			"000059's down restores the shape, never the values: users.%s reads NULL on %s", col, dbType())
	}

	rolledBack, err := h.DB.GetUserById(ctx, nil, user.Id)
	require.NoErrorf(t, err, "read users.id=%d back after the roll back on %s", user.Id, dbType())
	require.NotNilf(t, rolledBack, "the roll back must keep users.id=%d on %s", user.Id, dbType())
	assert.Equal(t, user.Email, rolledBack.Email)

	// 4. Forward again, which is what an operator who rolled back and retried does.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, dropPhoneVerificationCode000059),
		"re-apply 000059 on %s after a down/up round trip", dbType())
	thereAgain := schemadump.TableShape(dumpTable(t, h, "users"))
	for _, col := range phoneVerificationCodeColumns000059 {
		_, ok := thereAgain.Column(col)
		assert.Falsef(t, ok, "000059 must drop users.%s again after a round trip on %s", col, dbType())
	}
}

// placeholder000059 is the n-th bind parameter in the configured engine's spelling. Bound rather
// than inlined because one of the two values is binary, and the four engines spell a binary
// literal four ways.
func placeholder000059(n int) string {
	switch dbType() {
	case data.Postgres:
		return fmt.Sprintf("$%d", n)
	case data.MSSQL:
		return fmt.Sprintf("@p%d", n)
	default:
		return "?"
	}
}

func columnIsNull000059(t *testing.T, h *isolatedDB, col string, userId int64) bool {
	t.Helper()
	var isNull int
	q := fmt.Sprintf("SELECT CASE WHEN %s IS NULL THEN 1 ELSE 0 END FROM users WHERE id = %d", col, userId)
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&isNull), "read users.%s on %s", col, dbType())
	return isNull == 1
}
