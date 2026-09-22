package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The seed over a real SQLite file database, migrated to head, opened the way the migrate
// command's tests open one. The Database mock can show that a transaction was handed over; only an
// engine can show the writes used it and that a rollback left nothing, and on SQLite's single
// connection a write made outside the transaction waits for the connection the transaction holds,
// so it hangs this tier rather than passing it. The same proof on the three server engines is the
// data tier's (tests/data/database_seeder_test.go).

// seededTables are the tables the seed's 19 writes land in.
var seededTables = []string{
	"clients", "redirect_uris", "users", "resources", "permissions",
	"clients_permissions", "users_permissions", "key_pairs", "settings",
}

// seedWrites is how many writes a seed makes, each through one of the port's nine creates.
const seedWrites = 19

type seedDB struct {
	*sqlitedb.SQLiteDatabase
}

func newSeedDB(t *testing.T) *seedDB {
	t.Helper()
	db, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{
		Type: "sqlite",
		DSN:  "file:" + filepath.Join(t.TempDir(), "bootstrap_test.db"),
	}, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.DB.Close() })

	m, err := db.NewMigrator(context.Background())
	require.NoError(t, err)
	if err := m.Up(context.Background()); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding")
	}
	return &seedDB{db}
}

// counts answers the row count of every seeded table, which a failed seed must leave where it
// found them.
func (d *seedDB) counts(t *testing.T) map[string]int {
	t.Helper()
	counts := make(map[string]int, len(seededTables))
	for _, table := range seededTables {
		var n int
		require.NoError(t, d.DB.QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n))
		counts[table] = n
	}
	return counts
}

// testRunner is newRunner at the key size the rotator's tests use: 4096-bit keys cost about 300ms
// each, and nothing here depends on the size.
func testRunner(db runDatabase, cfg Config) *runner {
	r := newRunner(db, cfg)
	r.keySizeBits = 1024
	return r
}

func twoStepConfig(t *testing.T) Config {
	return Config{
		AdminEmail:          "Admin@Example.com",
		AdminPassword:       "SeedTest_p4ssword!",
		AppName:             "Goiabada",
		AuthServerBaseURL:   "https://auth.example.com",
		AdminConsoleBaseURL: "https://admin.example.com",
		BootstrapEnvOutFile: filepath.Join(t.TempDir(), "bootstrap", "bootstrap.env"),
	}
}

func singleStepConfig() Config {
	return Config{
		AdminEmail:          "Admin@Example.com",
		AdminPassword:       "SeedTest_p4ssword!",
		AppName:             "Goiabada",
		AuthServerBaseURL:   "https://auth.example.com",
		AdminConsoleBaseURL: "https://admin.example.com",
		OAuthClientSecret:   "the-configured-client-secret",
	}
}

// assertSeeded checks what a seed leaves, and answers the stored client secret, decrypted.
func assertSeeded(t *testing.T, db *seedDB, cfg Config) string {
	t.Helper()
	ctx := context.Background()

	isEmpty, err := db.IsEmpty(ctx)
	require.NoError(t, err)
	assert.False(t, isEmpty, "the database reads as seeded")

	settings, err := db.GetSettingsById(ctx, nil, 1)
	require.NoError(t, err)
	require.NotNil(t, settings, "the settings row is at id 1, the id every reader asks for")
	assert.Equal(t, cfg.AppName, settings.AppName)
	assert.Equal(t, cfg.AuthServerBaseURL, settings.Issuer)

	user, err := db.GetUserByEmail(ctx, nil, strings.ToLower(cfg.AdminEmail))
	require.NoError(t, err)
	require.NotNil(t, user, "the admin is found by the lowercased address")
	assert.True(t, passwordhash.Verify(user.PasswordHash, cfg.AdminPassword), "and the configured password verifies")

	keys, err := db.GetAllSigningKeys(ctx, nil)
	require.NoError(t, err)
	states := []string{}
	for _, key := range keys {
		states = append(states, key.State)
	}
	assert.ElementsMatch(t, []string{models.KeyStateCurrent.String(), models.KeyStateNext.String()}, states,
		"one current key and one next key")

	client, err := db.GetClientByClientIdentifier(ctx, nil, constants.AdminConsoleClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, client)
	secret, err := encryption.DecryptData(client.ClientSecretEncrypted)
	require.NoError(t, err)

	counts := db.counts(t)
	assert.Equal(t, map[string]int{
		"clients": 1, "redirect_uris": 2, "users": 1, "resources": 1, "permissions": 8,
		"clients_permissions": 1, "users_permissions": 2, "key_pairs": 2, "settings": 1,
	}, counts, "nineteen rows, one per write")
	return secret
}

// envFileValue reads one variable out of the bootstrap file's content.
func envFileValue(t *testing.T, content, name string) string {
	t.Helper()
	for _, line := range strings.Split(content, "\n") {
		if value, ok := strings.CutPrefix(line, name+"="); ok {
			return value
		}
	}
	t.Fatalf("%s is not in the bootstrap file", name)
	return ""
}

func TestRun_SingleStep_SeedsAndContinues(t *testing.T) {
	db := newSeedDB(t)
	cfg := singleStepConfig()

	outcome, err := testRunner(db, cfg).run(context.Background())

	require.NoError(t, err)
	assert.Equal(t, Continue, outcome)
	secret := assertSeeded(t, db, cfg)
	assert.Equal(t, cfg.OAuthClientSecret, secret, "the configured secret is the one stored")
}

func TestRun_TwoStep_PublishesTheFileAndExits(t *testing.T) {
	db := newSeedDB(t)
	cfg := twoStepConfig(t)
	logs := testutil.CaptureSlog(t)

	outcome, err := testRunner(db, cfg).run(context.Background())

	require.NoError(t, err)
	assert.Equal(t, Exit, outcome)
	secret := assertSeeded(t, db, cfg)

	info, err := os.Stat(cfg.BootstrapEnvOutFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	dirInfo, err := os.Stat(filepath.Dir(cfg.BootstrapEnvOutFile))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm(), "the directory is created owner-only")

	content, err := os.ReadFile(cfg.BootstrapEnvOutFile)
	require.NoError(t, err)
	assert.Equal(t, secret, envFileValue(t, string(content), "GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET"),
		"the file carries the secret the committed client was written with")

	entries, err := os.ReadDir(filepath.Dir(cfg.BootstrapEnvOutFile))
	require.NoError(t, err)
	require.Len(t, entries, 1, "the staged file became the target; nothing else is left beside it")

	messages := recordMessages(logs)
	assert.Contains(t, messages, "bootstrap credentials generated: open the file and copy the OAuth client secret and the session keys into the deployment configuration")
	assert.Contains(t, messages, "bootstrap complete, so the auth server is exiting: copy every credential from the bootstrap file into the two services' configuration, then restart them")
}

// Both configured: the secret selects single-step, as it did in main, and no file is generated for
// credentials the operator already has.
func TestRun_BothModesConfigured_SingleStepWins(t *testing.T) {
	db := newSeedDB(t)
	cfg := twoStepConfig(t)
	cfg.OAuthClientSecret = "the-configured-client-secret"

	outcome, err := testRunner(db, cfg).run(context.Background())

	require.NoError(t, err)
	assert.Equal(t, Continue, outcome)
	assertSeeded(t, db, cfg)
	assert.NoDirExists(t, filepath.Dir(cfg.BootstrapEnvOutFile))
}

func TestRun_NeitherModeConfigured_LeavesTheDatabaseEmpty(t *testing.T) {
	db := newSeedDB(t)
	before := db.counts(t)

	outcome, err := testRunner(db, Config{AdminEmail: "admin@example.com"}).run(context.Background())

	require.NoError(t, err)
	assert.Equal(t, Refused, outcome)
	assert.Equal(t, before, db.counts(t))
}

// The seed's bound on both sides, through a real database: 72 bytes seeds and verifies, 73 leaves
// the database empty, so the next start with the variable fixed seeds it (#409).
func TestRun_AdminPasswordAtAndPastTheBound(t *testing.T) {
	t.Run("72 bytes seeds", func(t *testing.T) {
		db := newSeedDB(t)
		cfg := singleStepConfig()
		cfg.AdminPassword = strings.Repeat("a", passwordhash.MaxPasswordBytes)

		outcome, err := testRunner(db, cfg).run(context.Background())

		require.NoError(t, err)
		assert.Equal(t, Continue, outcome)
		assertSeeded(t, db, cfg)
	})

	t.Run("73 bytes leaves the database empty", func(t *testing.T) {
		db := newSeedDB(t)
		cfg := singleStepConfig()
		cfg.AdminPassword = strings.Repeat("a", passwordhash.MaxPasswordBytes+1)
		before := db.counts(t)

		outcome, err := testRunner(db, cfg).run(context.Background())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "GOIABADA_ADMIN_PASSWORD")
		assert.Equal(t, Refused, outcome)
		isEmpty, err := db.IsEmpty(context.Background())
		require.NoError(t, err)
		assert.True(t, isEmpty)
		assert.Equal(t, before, db.counts(t))
	})
}

var errInjected = errors.New("injected failure")

// faultDB wraps the real database and fails one of the seed's writes, counted across the nine
// creates, either before the write reaches the engine or after the engine has executed it, or
// lets every write through and fails the commit. onWrite, when set, runs as each write begins,
// inside the transaction.
type faultDB struct {
	runDatabase
	failAt     int
	afterWrite bool
	failCommit bool
	onWrite    func()
	writes     int
}

func (f *faultDB) write(create func() error) error {
	f.writes++
	if f.onWrite != nil {
		f.onWrite()
	}
	if f.writes == f.failAt && !f.afterWrite {
		return errInjected
	}
	if err := create(); err != nil {
		return err
	}
	if f.writes == f.failAt {
		return errInjected
	}
	return nil
}

// RunInTransaction fails the commit, when asked, by cancelling the transaction's context once the
// body has returned: database/sql rolls the transaction back and the commit reports it, which is
// the one way to make an engine refuse a commit whose every statement succeeded.
func (f *faultDB) RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error {
	if !f.failCommit {
		return f.runDatabase.RunInTransaction(ctx, fn)
	}
	txCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	return f.runDatabase.RunInTransaction(txCtx, func(tx *sql.Tx) error {
		err := fn(tx)
		cancel()
		return err
	})
}

func (f *faultDB) CreateClient(ctx context.Context, tx *sql.Tx, client *models.Client) error {
	return f.write(func() error { return f.runDatabase.CreateClient(ctx, tx, client) })
}

func (f *faultDB) CreateRedirectURI(ctx context.Context, tx *sql.Tx, redirectURI *models.RedirectURI) error {
	return f.write(func() error { return f.runDatabase.CreateRedirectURI(ctx, tx, redirectURI) })
}

func (f *faultDB) CreateUser(ctx context.Context, tx *sql.Tx, user *models.User) error {
	return f.write(func() error { return f.runDatabase.CreateUser(ctx, tx, user) })
}

func (f *faultDB) CreateResource(ctx context.Context, tx *sql.Tx, resource *models.Resource) error {
	return f.write(func() error { return f.runDatabase.CreateResource(ctx, tx, resource) })
}

func (f *faultDB) CreatePermission(ctx context.Context, tx *sql.Tx, permission *models.Permission) error {
	return f.write(func() error { return f.runDatabase.CreatePermission(ctx, tx, permission) })
}

func (f *faultDB) CreateClientPermission(ctx context.Context, tx *sql.Tx, clientPermission *models.ClientPermission) error {
	return f.write(func() error { return f.runDatabase.CreateClientPermission(ctx, tx, clientPermission) })
}

func (f *faultDB) CreateUserPermission(ctx context.Context, tx *sql.Tx, userPermission *models.UserPermission) error {
	return f.write(func() error { return f.runDatabase.CreateUserPermission(ctx, tx, userPermission) })
}

func (f *faultDB) CreateKeyPair(ctx context.Context, tx *sql.Tx, keyPair *models.KeyPair) error {
	return f.write(func() error { return f.runDatabase.CreateKeyPair(ctx, tx, keyPair) })
}

func (f *faultDB) CreateInitialSettings(ctx context.Context, tx *sql.Tx, settings *models.Settings) error {
	return f.write(func() error { return f.runDatabase.CreateInitialSettings(ctx, tx, settings) })
}

// Every write goes through the port's nine creates, and there are nineteen of them: the count the
// failure table below is written against.
func TestRun_MakesNineteenWrites(t *testing.T) {
	db := newSeedDB(t)
	faults := &faultDB{runDatabase: db}

	_, err := testRunner(faults, singleStepConfig()).run(context.Background())

	require.NoError(t, err)
	assert.Equal(t, seedWrites, faults.writes)
}

// A failure at any write, before or after the engine executed it, or at the commit, leaves the
// database as it was and no bootstrap file, staged or published; and the next start, with the
// fault gone, seeds cleanly. Before #424 the first write was committed on its own and the next
// start failed on it forever.
func TestRun_AFailureAnywhereLeavesNothingAndTheNextStartSeeds(t *testing.T) {
	cases := []struct {
		name  string
		fault faultDB
	}{
		{"first write, before it runs", faultDB{failAt: 1}},
		{"first write, after it ran", faultDB{failAt: 1, afterWrite: true}},
		{"a middle write, before it runs", faultDB{failAt: 10}},
		{"a middle write, after it ran", faultDB{failAt: 10, afterWrite: true}},
		{"the settings row, before it runs", faultDB{failAt: seedWrites}},
		{"the settings row, after it ran", faultDB{failAt: seedWrites, afterWrite: true}},
		{"the commit", faultDB{failCommit: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newSeedDB(t)
			cfg := twoStepConfig(t)
			before := db.counts(t)
			faults := tc.fault
			faults.runDatabase = db

			outcome, err := testRunner(&faults, cfg).run(context.Background())

			require.Error(t, err)
			assert.Equal(t, Refused, outcome)
			if tc.fault.failCommit {
				assert.Equal(t, seedWrites, faults.writes, "every write ran before the commit failed")
			} else {
				assert.ErrorIs(t, err, errInjected)
			}

			isEmpty, err := db.IsEmpty(context.Background())
			require.NoError(t, err)
			assert.True(t, isEmpty, "the next start sees an empty database")
			assert.Equal(t, before, db.counts(t), "and nothing the failed seed wrote survived it")
			entries, err := os.ReadDir(filepath.Dir(cfg.BootstrapEnvOutFile))
			require.NoError(t, err)
			assert.Empty(t, entries, "the staged file is removed, and none was published")

			outcome, err = testRunner(db, cfg).run(context.Background())

			require.NoError(t, err, "the next start seeds")
			assert.Equal(t, Exit, outcome)
			assertSeeded(t, db, cfg)
			assert.FileExists(t, cfg.BootstrapEnvOutFile)
		})
	}
}

// The file appears under its name only after the commit: inside the transaction, at every write,
// the target does not exist and the one file beside it is the staged copy, already owner-only.
func TestRun_BootstrapFileIsPublishedOnlyAfterTheCommit(t *testing.T) {
	db := newSeedDB(t)
	cfg := twoStepConfig(t)
	dir := filepath.Dir(cfg.BootstrapEnvOutFile)
	checked := 0
	faults := &faultDB{runDatabase: db, onWrite: func() {
		checked++
		assert.NoFileExists(t, cfg.BootstrapEnvOutFile, "not published while the transaction is open")
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1, "the staged file, and only it")
		assert.True(t, strings.HasPrefix(entries[0].Name(), ".bootstrap.env."), entries[0].Name())
		info, err := entries[0].Info()
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}}

	outcome, err := testRunner(faults, cfg).run(context.Background())

	require.NoError(t, err)
	assert.Equal(t, Exit, outcome)
	assert.Equal(t, seedWrites, checked)
	assert.FileExists(t, cfg.BootstrapEnvOutFile)
}

// A directory that cannot be created is refused before any row is written, so fixing the volume
// and restarting seeds cleanly (#424 decision 4).
func TestRun_UncreatableBootstrapDirectory_RefusedBeforeAnyWrite(t *testing.T) {
	db := newSeedDB(t)
	cfg := twoStepConfig(t)
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	cfg.BootstrapEnvOutFile = filepath.Join(blocker, "bootstrap", "bootstrap.env")
	faults := &faultDB{runDatabase: db}

	outcome, err := testRunner(faults, cfg).run(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to create the bootstrap file's directory")
	assert.Equal(t, Refused, outcome)
	assert.Zero(t, faults.writes, "no write was attempted")
	isEmpty, err := db.IsEmpty(context.Background())
	require.NoError(t, err)
	assert.True(t, isEmpty)
}

// A rename that fails after the commit keeps the staged file, because it is the only copy of the
// credentials the committed rows were written with, and the error names it so the operator can
// move it by hand (#424 decision 4).
func TestRun_RenameFailsAfterTheCommit_KeepsAndNamesTheStagedFile(t *testing.T) {
	db := newSeedDB(t)
	cfg := twoStepConfig(t)
	r := testRunner(db, cfg)
	r.rename = func(string, string) error { return errInjected }

	outcome, err := r.run(context.Background())

	require.Error(t, err)
	assert.ErrorIs(t, err, errInjected)
	assert.Equal(t, Refused, outcome)
	assert.NoFileExists(t, cfg.BootstrapEnvOutFile)

	entries, readErr := os.ReadDir(filepath.Dir(cfg.BootstrapEnvOutFile))
	require.NoError(t, readErr)
	require.Len(t, entries, 1, "the staged file survives")
	staged := filepath.Join(filepath.Dir(cfg.BootstrapEnvOutFile), entries[0].Name())
	assert.Contains(t, err.Error(), staged, "the error names the file holding the credentials")
	assert.Contains(t, err.Error(), cfg.BootstrapEnvOutFile, "and where it belongs")
	info, statErr := os.Stat(staged)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	secret := assertSeeded(t, db, cfg)
	content, readErr := os.ReadFile(staged)
	require.NoError(t, readErr)
	assert.Equal(t, secret, envFileValue(t, string(content), "GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET"),
		"its secret is the one the committed client carries")
	for _, name := range bootstrapCredentialVars[1:] {
		assert.NotEmpty(t, envFileValue(t, string(content), name))
	}
}

// One record for the whole seed, after the commit, where there was one per row; the default
// warnings and the client secret's source stay.
func TestRun_WritesOneSeededRecord(t *testing.T) {
	db := newSeedDB(t)
	cfg := singleStepConfig()
	cfg.AppName = ""
	logs := testutil.CaptureSlog(t)

	_, err := testRunner(db, cfg).run(context.Background())
	require.NoError(t, err)

	var seeded []testutil.CapturedRecord
	for _, record := range logs.Records() {
		assert.False(t, strings.HasSuffix(record.Message, " created"), "no per-row record: %s", record.Message)
		if record.Message == "database seeded" {
			seeded = append(seeded, record)
		}
	}
	require.Len(t, seeded, 1)

	keys, err := db.GetAllSigningKeys(context.Background(), nil)
	require.NoError(t, err)
	byState := map[string]string{}
	for _, key := range keys {
		byState[key.State] = key.KeyIdentifier
	}
	assert.Equal(t, constants.AdminConsoleClientIdentifier, seeded[0].Attrs["client_identifier"])
	assert.Equal(t, "admin@example.com", seeded[0].Attrs["email"])
	assert.Equal(t, byState[models.KeyStateCurrent.String()], seeded[0].Attrs["current_key_identifier"])
	assert.Equal(t, byState[models.KeyStateNext.String()], seeded[0].Attrs["next_key_identifier"])

	messages := recordMessages(logs)
	assert.Contains(t, messages, "app name is not set, defaulting it")
	assert.Contains(t, messages, "using pre-generated OAuth client secret from environment")
}
