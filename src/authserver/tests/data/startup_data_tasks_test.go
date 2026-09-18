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

// TestNewDatabase_RefusesAStartupWhoseDataTasksFailed pins the last property of the same edge:
// runStartupDataTasks collapses every one of its fail-closed branches into one returned error,
// and NewDatabase has to turn that error into a refused startup rather than a usable handle.
//
// The two cases above prove the call happens and that both keys reach it, and the helper's own
// mock table in datafactory proves each internal branch fails closed. None of them reaches this
// arm: changing it from `return nil, err` to `return database, nil` left all 600 sqlite data
// tests green. That is a server reporting a successful startup after the legacy key migration,
// the env-to-env rotation or the plaintext OTP backfill has failed, then serving requests over
// data it could not convert -- which is precisely the outcome every one of those branches is
// fail-closed to prevent (#353).
//
// The forcing fixture is the rotation canary seeded under a THIRD key. RotateEncryptionKeyIfNeeded
// treats a canary that decrypts under the current key as "already rotated" and one that decrypts
// under the previous key as "rotate now"; a canary that opens under neither is the one
// misconfiguration it refuses outright rather than guessing at, so it is the cheapest real task
// failure this tier can construct.
//
// sqlite only, for the reason the two cases above give: a DSN to a throwaway file is the one way
// to reach NewDatabase without running the startup pass over the shared database this tier runs
// against. The arm under test is engine-independent, being a return in datafactory.
func TestNewDatabase_RefusesAStartupWhoseDataTasksFailed(t *testing.T) {
	if engine := dbType(); engine != "sqlite" && engine != "" {
		t.Skip("needs a DSN to a throwaway database, which only sqlite has; the arm under test is engine-independent")
	}

	currentKey := config.GetAESEncryptionKey()
	previousKey := bytes.Repeat([]byte{0x5a}, 32)
	unknownKey := bytes.Repeat([]byte{0x77}, 32)
	require.NotEqual(t, currentKey, unknownKey,
		"the canary has to open under neither supplied key, or the task succeeds and proves nothing")
	require.NotEqual(t, previousKey, unknownKey,
		"the canary has to open under neither supplied key, or the task rotates and proves nothing")

	const canaryPEM = "-----BEGIN RSA PRIVATE KEY-----\nnot a real key, only a canary\n-----END RSA PRIVATE KEY-----"
	underUnknownKey, err := encryption.EncryptText(canaryPEM, unknownKey)
	require.NoError(t, err)

	cfg := seedThrowawayDatabase(t, "startup_tasks_failed.db", func(db data.Database) {
		require.NoError(t, db.CreateKeyPair(nil, &models.KeyPair{
			State:         enums.KeyStateCurrent.String(),
			KeyIdentifier: fake.UUID(),
			Type:          "RSA",
			Algorithm:     "RS256",
			PrivateKeyPEM: underUnknownKey,
		}), "the unreadable canary is the whole fixture")
	})

	opened, err := datafactory.NewDatabase(cfg, currentKey, previousKey, false)

	require.Error(t, err,
		"a startup data task that failed must not be reported as a successful startup")
	assert.Nil(t, opened,
		"a refused startup must hand back no database, or the caller serves requests over data the tasks could not convert")
	assert.Contains(t, err.Error(), "AES data key rotation failed",
		"the failing task's own message has to survive the arm, since it is all the operator gets")
	assert.Contains(t, err.Error(), "GOIABADA_AES_ENCRYPTION_KEY",
		"and it has to keep naming the variables the operator would have to fix")
}

// TestNewDatabase_RefusesAStartupWhoseOpenFailed pins the first arm of the same pipeline: when
// OpenDatabase refuses, NewDatabase stops there rather than carrying a nil database on into the
// pre-flight, the migration and the startup tasks.
//
// Stage 2's unit table pins OpenDatabase's own refusal, and nothing pinned that NewDatabase
// honours it: neutralizing this arm survived the whole sqlite data tier. The arm below it
// dereferences the database it was handed, so what a lost return actually ships is a nil
// dereference at startup in place of the configuration error the operator has to read (#353).
//
// An unsupported engine name is the cheapest refusal OpenDatabase has and the only one needing no
// filesystem, which is what lets this case run on every engine rather than sqlite alone.
func TestNewDatabase_RefusesAStartupWhoseOpenFailed(t *testing.T) {
	cfg := &config.DatabaseConfig{Type: "wat"}

	opened, err := datafactory.NewDatabase(cfg, make([]byte, 32), nil, false)

	require.Error(t, err,
		"an engine name nothing can open must not be reported as a successful startup")
	assert.Nil(t, opened, "a refused open must hand back no database")
	assert.Contains(t, err.Error(), "unsupported database type: wat",
		"OpenDatabase's refusal has to reach the caller unchanged, since it quotes back what the operator set")
}

// TestNewDatabase_RefusesADirtyDatabase pins the third arm: a migration that will not run must
// stop startup, rather than leaving the startup tasks to convert data over a schema nobody knows
// the shape of.
//
// Dirty is the real state this arm exists for. The runner writes the marker before a file runs
// and clears it after, so a migration cut short by a crash or a dropped connection leaves it set,
// and Goiabada then refuses to migrate because it cannot tell how much of that file applied.
// preflightEmailCase reads a dirty database's version without complaint -- it says so in as many
// words -- so this arm is the only thing standing between that marker and a startup that runs the
// data tasks anyway. Neutralizing it survived the whole sqlite data tier (#353).
//
// sqlite only, for the reason the cases above give: a DSN to a throwaway file is the one way to
// reach NewDatabase without touching the shared database this tier runs against. The arm under
// test is engine-independent, being a return in datafactory.
func TestNewDatabase_RefusesADirtyDatabase(t *testing.T) {
	if engine := dbType(); engine != "sqlite" && engine != "" {
		t.Skip("needs a DSN to a throwaway database, which only sqlite has; the arm under test is engine-independent")
	}

	cfg := seedThrowawayDatabase(t, "startup_dirty.db", func(db data.Database) {})

	// The marker an interrupted migration leaves behind, written through a handle of its own
	// because the dirty flag is a raw schema_migrations column and not anything data.Database
	// exposes. The file is already at head, so the pre-flight reads the version, skips, and this
	// arm is the first one with anything to refuse.
	marker, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{Type: "sqlite", DSN: cfg.DSN}, false)
	require.NoError(t, err, "the marker handle has to open before the fixture can be written")
	res, err := marker.DB.Exec("UPDATE schema_migrations SET dirty = 1")
	require.NoError(t, err, "the dirty marker is the whole fixture")
	affected, err := res.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), affected,
		"the runner writes exactly one row and refuses a table holding two, so the fixture has to be that row")
	require.NoError(t, marker.DB.Close(), "released so the startup open is a fresh one")

	opened, err := datafactory.NewDatabase(cfg, config.GetAESEncryptionKey(), nil, false)

	require.Error(t, err,
		"a database whose migration did not finish must not be reported as a successful startup")
	assert.Nil(t, opened, "a refused migration must hand back no database")
	assert.Contains(t, err.Error(), "dirty",
		"the runner's own refusal has to survive the arm, since it is what tells the operator to repair by hand")
}
