package datatests

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/datafactory"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/data/sqlitedb"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedThrowawayDatabase migrates a fresh sqlite file, hands it to seed, then closes the handle
// and returns the configuration that reopens the same file through datafactory.NewDatabase.
//
// Closing matters: the sqlite handle is pinned to one connection, and the point of these tests is
// that the second open is a real startup rather than a continuation of the seeding one.
func seedThrowawayDatabase(t *testing.T, name string, seed func(db data.Database)) *config.DatabaseConfig {
	t.Helper()

	dsn := filepath.Join(t.TempDir(), name)
	db, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{Type: "sqlite", DSN: dsn}, false)
	require.NoError(t, err, "the seeding handle has to open before anything can be seeded")
	require.NoError(t, db.Migrate(), "seeding writes rows, so the schema has to be at head first")

	seed(db)

	require.NoError(t, db.DB.Close(), "the seeding handle is released so the startup open is a fresh one")
	return &config.DatabaseConfig{Type: "sqlite", DSN: dsn}
}

// TestNewDatabase_RunsTheStartupDataTasksOnTheDatabaseItOpened pins the one edge of the startup
// pipeline that the helper's own table cannot reach: that NewDatabase actually calls
// runStartupDataTasks on the database it just opened, with the key it was handed.
//
// runStartupDataTasks is tested in datafactory against a mock, one case per fail-closed branch,
// and those cases pass whether or not anything calls the function. So does every other test in
// this tier, because a fresh database has no legacy plaintext for the tasks to convert. Deleting
// the call in NewDatabase therefore left all 598 sqlite data tests green, which is a move that
// can silently drop the legacy key migration, the env-to-env rotation and this OTP backfill
// while the suite reports success (#353).
//
// The observable effect is the backfill of #82: a row holding a plaintext TOTP secret comes back
// with the plaintext blanked and a ciphertext that decrypts to it. Nothing but the startup pass
// touches that row between the two opens.
//
// sqlite only, for the reason TestNewDatabase_RefusesAnAESKeyOfTheWrongLength gives: a DSN to a
// throwaway file is the one way to reach NewDatabase without running the startup pass over the
// shared database this tier runs against. The edge under test is engine-independent, being a call
// in datafactory that happens before any engine-specific code runs.
func TestNewDatabase_RunsTheStartupDataTasksOnTheDatabaseItOpened(t *testing.T) {
	if engine := dbType(); engine != "sqlite" && engine != "" {
		t.Skip("needs a DSN to a throwaway database, which only sqlite has; the call under test is engine-independent")
	}

	// The key the process cipher was initialized with in TestMain, so the model's GetOTPSecret
	// can read back whatever the startup pass wrote.
	key := config.GetAESEncryptionKey()

	const legacySeed = "STARTUPTASKSEED1"
	var legacy *models.User

	cfg := seedThrowawayDatabase(t, "startup_tasks.db", func(db data.Database) {
		legacy = &models.User{
			Subject:      fake.UUID(),
			Username:     fake.UUID(),
			Email:        fake.UUID() + "@example.com",
			PasswordHash: "x",
			OTPSecret:    legacySeed,
			OTPEnabled:   true,
		}
		require.NoError(t, db.CreateUser(nil, legacy), "the legacy row is the whole fixture")
	})

	opened, err := datafactory.NewDatabase(cfg, key, nil, false)
	require.NoError(t, err, "a migrated database and a 32-byte key is a startup that must succeed")
	require.NotNil(t, opened)

	got, err := opened.GetUserById(nil, legacy.Id)
	require.NoError(t, err)
	require.NotNil(t, got, "the seeded row survives the second open")

	assert.Empty(t, got.OTPSecret,
		"the backfill blanks the plaintext column, and an untouched plaintext secret is what a dropped startup pass looks like")

	decrypted, err := got.GetOTPSecret()
	require.NoError(t, err, "the ciphertext the startup pass wrote must be readable with the key it was given")
	assert.Equal(t, legacySeed, decrypted, "the secret has to survive the conversion, not merely be replaced")
}

// TestNewDatabase_HandsTheStartupTasksThePreviousKey pins the second half of the same edge: the
// previous key NewDatabase is given reaches runStartupDataTasks, rather than being dropped on the
// way. Dropped, the env-to-env rotation of #83 is skipped in silence -- the startup succeeds, and
// the server then serves requests against data it cannot decrypt.
//
// The detection canary is the one RotateEncryptionKeyIfNeeded uses: an encrypted RSA private key
// PEM. Seeded under the previous key, a startup carrying that key rewrites it under the current
// one; a startup that lost it leaves the row as it was (#353).
func TestNewDatabase_HandsTheStartupTasksThePreviousKey(t *testing.T) {
	if engine := dbType(); engine != "sqlite" && engine != "" {
		t.Skip("needs a DSN to a throwaway database, which only sqlite has; the call under test is engine-independent")
	}

	currentKey := config.GetAESEncryptionKey()
	previousKey := bytes.Repeat([]byte{0x5a}, 32)
	require.NotEqual(t, currentKey, previousKey,
		"rotation is a no-op when the two keys match, so the fixture would prove nothing")

	const canaryPEM = "-----BEGIN RSA PRIVATE KEY-----\nnot a real key, only a canary\n-----END RSA PRIVATE KEY-----"
	underPreviousKey, err := encryption.EncryptText(canaryPEM, previousKey)
	require.NoError(t, err)

	cfg := seedThrowawayDatabase(t, "startup_rotation.db", func(db data.Database) {
		require.NoError(t, db.CreateKeyPair(nil, &models.KeyPair{
			State:         enums.KeyStateCurrent.String(),
			KeyIdentifier: fake.UUID(),
			Type:          "RSA",
			Algorithm:     "RS256",
			PrivateKeyPEM: underPreviousKey,
		}), "the canary is the whole fixture")
	})

	opened, err := datafactory.NewDatabase(cfg, currentKey, previousKey, false)
	require.NoError(t, err, "data under the previous key is exactly the configuration rotation exists to accept")
	require.NotNil(t, opened)

	keys, err := opened.GetAllSigningKeys(nil)
	require.NoError(t, err)
	require.Len(t, keys, 1, "the second open must not have added or dropped a key pair")

	rotated, err := encryption.DecryptText(keys[0].PrivateKeyPEM, currentKey)
	require.NoError(t, err,
		"after a startup carrying the previous key the canary reads under the current one; a failure here is the previous key never arriving")
	assert.Equal(t, canaryPEM, rotated, "rotation re-encrypts the same plaintext, it does not replace it")

	_, err = encryption.DecryptText(keys[0].PrivateKeyPEM, previousKey)
	assert.Error(t, err, "the old key must no longer open the row, which is what makes this a rotation rather than a copy")
}
