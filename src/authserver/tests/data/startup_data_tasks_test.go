package datatests

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/datafactory"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
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
	m, err := db.NewMigrator(context.Background())
	require.NoError(t, err)
	require.NoError(t, m.Up(context.Background()), "seeding writes rows, so the schema has to be at head first")

	seed(db)

	require.NoError(t, db.DB.Close(), "the seeding handle is released so the startup open is a fresh one")
	return &config.DatabaseConfig{Type: "sqlite", DSN: dsn}
}

// TestNewDatabase_HandsTheStartupTasksThePreviousKey pins that the previous key NewDatabase is
// given reaches runStartupDataTasks, rather than being dropped on the way. Dropped, the env-to-env
// rotation of #83 is skipped in silence -- the startup succeeds, and the server then serves
// requests against data it cannot decrypt.
//
// IT IS ALSO THE SOLE PIN ON THE CALL ITSELF. A sibling case used to hold that edge with a
// plaintext TOTP seed the startup backfill converted; #359 deleted that conversion (#262, #98), so
// the canary below is what is left. It only rewrites if NewDatabase calls runStartupDataTasks at
// all, which is worth stating because deleting that call left all 598 sqlite data tests green
// (#353): every other test in this tier passes whether or not the startup pass runs.
//
// The detection canary is the one the startup task reads: an encrypted RSA private key PEM. Seeded under the previous key, a startup carrying that key rewrites it under the current
// one; a startup that lost it leaves the row as it was (#353).
func TestNewDatabase_HandsTheStartupTasksThePreviousKey(t *testing.T) {
	if engine := dbType(); engine != data.SQLite {
		t.Skip("needs a DSN to a throwaway database, which only sqlite has; the call under test is engine-independent")
	}

	currentKey := dataKey
	previousKey := bytes.Repeat([]byte{0x5a}, 32)
	require.NotEqual(t, currentKey, previousKey,
		"rotation is a no-op when the two keys match, so the fixture would prove nothing")

	const canaryPEM = "-----BEGIN RSA PRIVATE KEY-----\nnot a real key, only a canary\n-----END RSA PRIVATE KEY-----"
	underPreviousKey, err := encryption.EncryptText(canaryPEM, previousKey)
	require.NoError(t, err)

	cfg := seedThrowawayDatabase(t, "startup_rotation.db", func(db data.Database) {
		require.NoError(t, db.CreateKeyPair(context.Background(), nil, &models.KeyPair{
			State:         models.KeyStateCurrent.String(),
			KeyIdentifier: fake.UUID(),
			Type:          "RSA",
			Algorithm:     "RS256",
			PrivateKeyPEM: underPreviousKey,
		}), "the canary is the whole fixture")
	})

	opened, err := datafactory.NewDatabase(context.Background(), cfg, currentKey, previousKey, false)
	require.NoError(t, err, "data under the previous key is exactly the configuration rotation exists to accept")
	require.NotNil(t, opened)

	keys, err := opened.GetAllSigningKeys(context.Background(), nil)
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
// The case above proves the call happens and that both keys reach it, and the helper's own mock
// table in datafactory proves the surviving branch fails closed. Neither reaches this arm:
// changing it from `return nil, err` to `return database, nil` left all 600 sqlite data tests
// green. That is a server reporting a successful startup after the env-to-env key rotation has
// failed, then serving requests over data it could not re-key -- which is precisely the outcome
// that branch is fail-closed to prevent (#353).
//
// The forcing fixture is the rotation canary seeded under a THIRD key. The startup task treats a canary that decrypts under the current key as "already rotated" and one that decrypts
// under the previous key as "rotate now"; a canary that opens under neither is the one
// misconfiguration it refuses outright rather than guessing at, so it is the cheapest real task
// failure this tier can construct.
//
// sqlite only, for the reason the case above gives: a DSN to a throwaway file is the one way to
// reach NewDatabase without running the startup pass over the shared database this tier runs
// against. The arm under test is engine-independent, being a return in datafactory.
func TestNewDatabase_RefusesAStartupWhoseDataTasksFailed(t *testing.T) {
	if engine := dbType(); engine != data.SQLite {
		t.Skip("needs a DSN to a throwaway database, which only sqlite has; the arm under test is engine-independent")
	}

	currentKey := dataKey
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
		require.NoError(t, db.CreateKeyPair(context.Background(), nil, &models.KeyPair{
			State:         models.KeyStateCurrent.String(),
			KeyIdentifier: fake.UUID(),
			Type:          "RSA",
			Algorithm:     "RS256",
			PrivateKeyPEM: underUnknownKey,
		}), "the unreadable canary is the whole fixture")
	})

	opened, err := datafactory.NewDatabase(context.Background(), cfg, currentKey, previousKey, false)

	require.Error(t, err,
		"a startup data task that failed must not be reported as a successful startup")
	assert.Nil(t, opened,
		"a refused startup must hand back no database, or the caller serves requests over data the tasks could not convert")
	assert.Contains(t, err.Error(), "AES data key rotation failed",
		"the failing task's own message has to survive the arm, since it is all the operator gets")
	assert.Contains(t, err.Error(), "GOIABADA_AES_ENCRYPTION_KEY",
		"and it has to keep naming the variables the operator would have to fix")
}

// TestNewDatabase_RefusesAPlaintextPEMCanaryAndRekeysNothing is the one statement this tree can
// make about a database that never booted 1.6.x. #359 deleted the startup conversion that
// encrypted a plaintext RSA PEM (#262) and ships no pre-flight to refuse such a database, so what
// is left to establish is that a startup carrying a previous key does not quietly half-convert
// one: the canary is the first non-empty PrivateKeyPEM, a plaintext PEM decrypts under neither key,
// and the startup task refuses before ReencryptToKey runs.
//
// That is why commondb.reencryptPrivateKeys keeps its plaintext-PEM branch as unreachable code
// rather than deleting it: nothing in production can reach it, and this test is the reason that
// claim holds. It used to call the data layer's own rotation method; #438 decision 8 moved the
// canary to datafactory, so it goes through the startup that reads it.
//
// sqlite only, for the reason the cases above give.
func TestNewDatabase_RefusesAPlaintextPEMCanaryAndRekeysNothing(t *testing.T) {
	if engine := dbType(); engine != data.SQLite {
		t.Skip("needs a DSN to a throwaway database, which only sqlite has; the refusal under test is engine-independent")
	}

	currentKey := dataKey
	previousKey := bytes.Repeat([]byte{0x5a}, 32)
	require.NotEqual(t, currentKey, previousKey,
		"the canary is not even read when the two keys match, so the fixture would prove nothing")

	const (
		pemPlain  = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc123fakepemcontent\n-----END RSA PRIVATE KEY-----\n"
		clientSec = "client-secret"
	)
	secretUnderPrevious, err := encryption.EncryptText(clientSec, previousKey)
	require.NoError(t, err)
	clientIdentifier := "c-" + fake.UUID()

	cfg := seedThrowawayDatabase(t, "startup_plaintext_pem.db", func(db data.Database) {
		require.NoError(t, db.CreateKeyPair(context.Background(), nil, &models.KeyPair{
			State:         models.KeyStateCurrent.String(),
			KeyIdentifier: fake.UUID(),
			Type:          "RSA",
			Algorithm:     "RS256",
			PrivateKeyPEM: []byte(pemPlain), // the pre-1.6.0 state: never encrypted
		}), "the plaintext canary is the fixture")
		require.NoError(t, db.CreateClient(context.Background(), nil, &models.Client{
			ClientIdentifier:      clientIdentifier,
			ClientSecretEncrypted: secretUnderPrevious,
		}), "and a secret under the previous key, which a re-key would have moved")
	})

	opened, err := datafactory.NewDatabase(context.Background(), cfg, currentKey, previousKey, false)

	require.Error(t, err, "a plaintext PEM decrypts under neither key, so the startup is refused")
	assert.Nil(t, opened)
	assert.Contains(t, err.Error(), "decrypts under neither GOIABADA_AES_ENCRYPTION_KEY nor GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS")

	// Nothing was re-keyed: the PEM is the plaintext it was, and the client secret still reads
	// under the previous key, because the refusal comes before ReencryptToKey opens its transaction.
	reopened, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{Type: "sqlite", DSN: cfg.DSN}, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.DB.Close() })

	keys, err := reopened.GetAllSigningKeys(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, []byte(pemPlain), keys[0].PrivateKeyPEM,
		"the plaintext PEM was rewritten by a startup that reported failure")

	client, err := reopened.GetClientByClientIdentifier(context.Background(), nil, clientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, client)
	plaintext, err := encryption.DecryptText(client.ClientSecretEncrypted, previousKey)
	require.NoError(t, err, "the client secret was re-keyed by a startup that refused to rotate")
	assert.Equal(t, clientSec, plaintext)
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

	opened, err := datafactory.NewDatabase(context.Background(), cfg, make([]byte, 32), nil, false)

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
	if engine := dbType(); engine != data.SQLite {
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

	opened, err := datafactory.NewDatabase(context.Background(), cfg, dataKey, nil, false)

	require.Error(t, err,
		"a database whose migration did not finish must not be reported as a successful startup")
	assert.Nil(t, opened, "a refused migration must hand back no database")
	assert.Contains(t, err.Error(), "dirty",
		"the runner's own refusal has to survive the arm, since it is what tells the operator to repair by hand")
}
