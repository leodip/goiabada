package datatests

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000048 sits between. Literals rather than a datafactory constant,
// because unlike 000047 nothing in production code names this number: the drop has no pre-flight
// and no Go-side gate, which is decision 8 of #359 and is the whole of what ships with it.
const (
	beforeDropOtpSecret000048 = 47
	dropOtpSecret000048       = 48
)

// TestMigration000048_DropOtpSecret exercises the migration that removes users.otp_secret, the
// plaintext TOTP seed column (#98, #262), against a REAL engine of the configured dialect (see
// migration_testdb_helper.go).
//
// Four engines matter here rather than one. The column's declared type differs on every one of
// them -- TEXT, varchar(64), character varying(64), nvarchar(64) -- so the up statement is written
// four times and the down statement restores four different shapes, including a collation on two
// of them. Nothing but the data tier runs mysql, postgres and mssql at all.
//
// The properties, in order:
//
//  1. The column is gone from the catalog once the chain reaches head. Read from the engine's own
//     catalog rather than from a query failing, because a failing SELECT is also what a typo in
//     the test looks like.
//
//  2. A user row written BEFORE the drop, carrying an encrypted seed, reads back afterwards with
//     otp_secret_encrypted intact and the stored seed still decrypting. That is the claim the
//     release rests on: 1.6.x moved every seed to the encrypted column, so dropping the plaintext
//     one costs a database that has booted 1.6.x nothing.
//
//  3. The down migration restores the column with its original type and nullability, so a roll
//     back lands on the shape 000047 left rather than an approximation of it. Compared against the
//     shape read before the drop, on this same engine, rather than against a per-engine literal:
//     a table of four spellings in a test is a table that can disagree with four .down.sql files
//     and still be green.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000048_DropOtpSecret
func TestMigration000048_DropOtpSecret(t *testing.T) {
	h := newIsolatedDB(t)

	// FORWARD to 000047 from an empty database, never down to it. 000047's own test reaches its
	// version by migrating to head and stepping back, which is safe there because 000047's down is
	// a no-op; here it would not be. Stepping back through 000048's down is what CREATES the column
	// this test then compares the down against, so `before` would be the down's own output and
	// property 3 would compare the statement with itself. Measured: the comparison passed with the
	// down declaring BLOB instead of TEXT.
	//
	// Migrating up is also enough to seed through the ORM. models.User carries no OTPSecret field
	// since #98, and every column it does carry exists at 000047.
	require.NoErrorf(t, h.Migrator.Migrate(context.Background(), beforeDropOtpSecret000048),
		"migrate an empty database up to 000047 on %s", dbType())

	// 3, first half: the shape 000047 leaves the column in, which is what a roll back has to
	// land back on.
	before, ok := schemadump.TableShape(dumpTable(t, h, "users")).Column("otp_secret")
	require.Truef(t, ok,
		"users.otp_secret must exist at 000047 on %s, or this migration has nothing to drop and every assertion below is vacuous",
		dbType())

	const seed = "JBSWY3DPEHPK3PXP"
	encrypted, err := encryption.EncryptData(seed)
	require.NoError(t, err, "the process cipher is initialized in TestMain")

	user := &models.User{
		Enabled:            true,
		Subject:            "00000000-0000-0000-0000-000000048001",
		Username:           "mig48user",
		Email:              "mig48@example.com",
		PasswordHash:       "not-a-real-hash",
		OTPEnabled:         true,
		OTPSecretEncrypted: encrypted,
	}
	require.NoErrorf(t, h.DB.CreateUser(context.Background(), nil, user), "seed a user at 000047 on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(context.Background(), dropOtpSecret000048), "apply 000048 on %s", dbType())

	// 1. Gone from the catalog.
	afterDrop := schemadump.TableShape(dumpTable(t, h, "users"))
	_, stillThere := afterDrop.Column("otp_secret")
	assert.Falsef(t, stillThere,
		"users.otp_secret is still in the catalog on %s after 000048: the column the migration names is the one it must drop",
		dbType())

	// And the migration dropped only that column. otp_secret_encrypted shares a prefix with it,
	// which is the plausible way a hand-written four-engine statement takes the wrong one.
	_, encryptedSurvives := afterDrop.Column("otp_secret_encrypted")
	require.Truef(t, encryptedSurvives,
		"users.otp_secret_encrypted is gone on %s: 000048 dropped the column carrying every seed rather than the empty one beside it",
		dbType())

	// 2. The row survives with its seed readable. Through the ORM, which is what every production
	// read of a seed goes through.
	got, err := h.DB.GetUserById(context.Background(), nil, user.Id)
	require.NoErrorf(t, err, "read users.id=%d back after the drop on %s", user.Id, dbType())
	require.NotNilf(t, got, "users.id=%d is gone; this migration deletes no rows", user.Id)
	assert.Truef(t, got.OTPEnabled, "the drop must not disturb otp_enabled on %s", dbType())

	decrypted, err := encryption.DecryptData(got.OTPSecretEncrypted)
	require.NoErrorf(t, err, "the encrypted seed must still decrypt after the drop on %s", dbType())
	assert.Equalf(t, seed, decrypted,
		"the seed has to survive the drop: a user whose authenticator stops working is what dropping the wrong column looks like on %s",
		dbType())

	// 3, second half. The down statement restores the shape, verbatim, and nothing else about the
	// table moves.
	require.NoErrorf(t, h.Migrator.Migrate(context.Background(), beforeDropOtpSecret000048), "roll back 000048 on %s", dbType())

	restored, ok := schemadump.TableShape(dumpTable(t, h, "users")).Column("otp_secret")
	require.Truef(t, ok, "000048's down must re-add users.otp_secret on %s", dbType())
	assert.Equalf(t, before.Type, restored.Type,
		"000048's down must restore the original type on %s, or a rolled-back database diverges from one that never migrated",
		dbType())
	assert.Equalf(t, before.Nullable, restored.Nullable,
		"000048's down must restore the original nullability on %s; SQL Server in particular makes a column nullable whenever the keyword is left off",
		dbType())
	assert.Equalf(t, before.Collation, restored.Collation,
		"000048's down must restore the original collation on %s, which MySQL and SQL Server pin per column (#283)",
		dbType())
	assert.Equalf(t, before.HasDefault, restored.HasDefault,
		"000048's down must not invent a default on %s", dbType())

	// The shape only. The values are not restored and the file says so: the plaintext seeds are
	// recorded nowhere else, so the re-added column reads NULL or empty for every row.
	rolledBack, err := h.DB.GetUserById(context.Background(), nil, user.Id)
	require.NoError(t, err)
	require.NotNil(t, rolledBack)
	stillDecrypts, err := encryption.DecryptData(rolledBack.OTPSecretEncrypted)
	require.NoErrorf(t, err, "the encrypted seed is untouched by the roll back on %s", dbType())
	assert.Equal(t, seed, stillDecrypts,
		"a down migration that restores a shape must not disturb the column that actually carries the seed")

	// And forward again, which is what an operator who rolled back and retried does.
	require.NoErrorf(t, h.Migrator.Migrate(context.Background(), dropOtpSecret000048), "re-apply 000048 on %s", dbType())
	_, thereAgain := schemadump.TableShape(dumpTable(t, h, "users")).Column("otp_secret")
	assert.Falsef(t, thereAgain, "000048 must be re-appliable after a down/up round trip on %s", dbType())
}
