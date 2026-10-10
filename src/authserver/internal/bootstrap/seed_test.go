package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The seed over a real SQLite file database, migrated to head, opened the way the migrate
// command's tests open one. The Database mock can show that a transaction was handed over; only an
// engine can show the writes used it and that a rollback left nothing, and on SQLite's single
// connection a write made outside the transaction waits for the connection the transaction holds,
// so it hangs this tier rather than passing it. The same proof on the three server engines is the
// data tier's (tests/data/database_seeder_test.go).

// seededTables are the tables the seed's 18 writes land in.
var seededTables = []string{
	"clients", "redirect_uris", "users", "resources", "permissions",
	"clients_permissions", "users_permissions", "key_pairs", "settings",
}

// seedWrites is how many writes a seed makes, each through one of the port's nine creates.
const seedWrites = 18

type seedDB struct {
	*sqlitedb.Database
}

func newSeedDB(t *testing.T) *seedDB {
	t.Helper()
	db, err := sqlitedb.New(context.Background(), "file:"+filepath.Join(t.TempDir(), "bootstrap_test.db"), false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.DB.Close() })

	m, err := db.NewMigrator(context.Background(), nil)
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
	r := newRunner(db, testDataCipher, cfg)
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
		// Sealed under the cipher Run was given, so that cipher opens it (#434).
		_, parseErr := signingkeys.ParsePrivateKey(testDataCipher, &key)
		require.NoError(t, parseErr, "the %s key does not open under the seed's cipher", key.State)
	}
	assert.ElementsMatch(t, []string{record.KeyStateCurrent.String(), record.KeyStateNext.String()}, states,
		"one current key and one next key")

	client, err := db.GetClientByClientIdentifier(ctx, nil, builtin.AdminConsoleClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.True(t, client.AdministrativeScopesAllowed,
		"the admin console's client is seeded allowed to request the administrative scopes, so what the API answers agrees with what the server does (#499)")
	secret, err := testDataCipher.Decrypt(client.ClientSecretEncrypted)
	require.NoError(t, err)

	counts := db.counts(t)
	assert.Equal(t, map[string]int{
		"clients": 1, "redirect_uris": 2, "users": 1, "resources": 1, "permissions": 7,
		"clients_permissions": 1, "users_permissions": 2, "key_pairs": 2, "settings": 1,
	}, counts, "eighteen rows, one per write")
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
	logs := logtest.CaptureSlog(t)

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

// A first run refuses an admin password that is empty, the published changeme, or under 15
// characters, in both bootstrap modes alike: before any write and before the bootstrap file is
// staged, naming the variable, with the database left empty; and the next start, with the
// variable fixed, seeds that same database (#500 decisions 1 and 2). Unset reaches the seed as
// empty, since the configuration no longer supplies a default.
func TestRun_RefusesAnUnusableAdminPasswordInBothModes(t *testing.T) {
	passwords := []struct {
		name     string
		password string
		reason   string
	}{
		{"unset or empty", "", "empty"},
		{"the published changeme", "changeme", "published"},
		{"14 characters", strings.Repeat("a", 14), "at least 15 characters"},
		{"14 two-byte characters, 28 bytes", strings.Repeat("é", 14), "at least 15 characters"},
	}
	modes := []struct {
		name    string
		config  func(t *testing.T) Config
		outcome Outcome
	}{
		{"single-step", func(*testing.T) Config { return singleStepConfig() }, Continue},
		{"two-step", twoStepConfig, Exit},
	}
	for _, mode := range modes {
		for _, pw := range passwords {
			t.Run(mode.name+", "+pw.name, func(t *testing.T) {
				db := newSeedDB(t)
				cfg := mode.config(t)
				cfg.AdminPassword = pw.password
				before := db.counts(t)
				faults := &faultDB{runDatabase: db}
				logs := logtest.CaptureSlog(t)

				outcome, err := testRunner(faults, cfg).run(context.Background())

				require.Error(t, err)
				assert.Equal(t, Refused, outcome)
				assert.Contains(t, err.Error(), "GOIABADA_ADMIN_PASSWORD")
				assert.Contains(t, err.Error(), pw.reason)
				assert.Zero(t, faults.writes, "no write was attempted")
				isEmpty, err := db.IsEmpty(context.Background())
				require.NoError(t, err)
				assert.True(t, isEmpty, "the next start sees an empty database")
				assert.Equal(t, before, db.counts(t))
				if cfg.BootstrapEnvOutFile != "" {
					assert.NoDirExists(t, filepath.Dir(cfg.BootstrapEnvOutFile),
						"refused before the bootstrap file is staged, so not even its directory exists")
				}
				for _, logRecord := range logs.Records() {
					assert.NotContains(t, logRecord.Message, "defaulting it",
						"no password is supplied in place of the operator's")
					for _, value := range logRecord.Attrs {
						assert.NotEqual(t, "changeme", value, "%s carries changeme", logRecord.Message)
					}
				}

				cfg.AdminPassword = "a-valid-password-at-last"
				outcome, err = testRunner(db, cfg).run(context.Background())

				require.NoError(t, err, "the next start, with the variable fixed, seeds")
				assert.Equal(t, mode.outcome, outcome)
				assertSeeded(t, db, cfg)
			})
		}
	}
}

// 15 characters is the floor, counted in characters: 15 two-byte characters seed, as 15 ASCII ones
// do, though 14 of either do not (above).
func TestRun_AdminPasswordOfFifteenCharactersSeeds(t *testing.T) {
	for name, password := range map[string]string{
		"15 ASCII characters":              strings.Repeat("a", 15),
		"15 two-byte characters, 30 bytes": strings.Repeat("é", 15),
	} {
		t.Run(name, func(t *testing.T) {
			db := newSeedDB(t)
			cfg := singleStepConfig()
			cfg.AdminPassword = password

			outcome, err := testRunner(db, cfg).run(context.Background())

			require.NoError(t, err)
			assert.Equal(t, Continue, outcome)
			assertSeeded(t, db, cfg)
		})
	}
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
	// failWith is the error the failing write answers, errInjected when nil.
	failWith error
	onWrite  func()
	writes   int
}

func (f *faultDB) write(create func() error) error {
	f.writes++
	if f.onWrite != nil {
		f.onWrite()
	}
	injected := errInjected
	if f.failWith != nil {
		injected = f.failWith
	}
	if f.writes == f.failAt && !f.afterWrite {
		return injected
	}
	if err := create(); err != nil {
		return err
	}
	if f.writes == f.failAt {
		return injected
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

func (f *faultDB) CreateClient(ctx context.Context, tx *sql.Tx, client *record.Client) error {
	return f.write(func() error { return f.runDatabase.CreateClient(ctx, tx, client) })
}

func (f *faultDB) CreateRedirectURI(ctx context.Context, tx *sql.Tx, redirectURI *record.RedirectURI) error {
	return f.write(func() error { return f.runDatabase.CreateRedirectURI(ctx, tx, redirectURI) })
}

func (f *faultDB) CreateUser(ctx context.Context, tx *sql.Tx, user *record.User) error {
	return f.write(func() error { return f.runDatabase.CreateUser(ctx, tx, user) })
}

func (f *faultDB) CreateResource(ctx context.Context, tx *sql.Tx, resource *record.Resource) error {
	return f.write(func() error { return f.runDatabase.CreateResource(ctx, tx, resource) })
}

func (f *faultDB) CreatePermission(ctx context.Context, tx *sql.Tx, permission *record.Permission) error {
	return f.write(func() error { return f.runDatabase.CreatePermission(ctx, tx, permission) })
}

func (f *faultDB) CreateClientPermission(ctx context.Context, tx *sql.Tx, clientPermission *record.ClientPermission) error {
	return f.write(func() error { return f.runDatabase.CreateClientPermission(ctx, tx, clientPermission) })
}

func (f *faultDB) CreateUserPermission(ctx context.Context, tx *sql.Tx, userPermission *record.UserPermission) error {
	return f.write(func() error { return f.runDatabase.CreateUserPermission(ctx, tx, userPermission) })
}

func (f *faultDB) CreateKeyPair(ctx context.Context, tx *sql.Tx, keyPair *record.KeyPair) error {
	return f.write(func() error { return f.runDatabase.CreateKeyPair(ctx, tx, keyPair) })
}

func (f *faultDB) CreateInitialSettings(ctx context.Context, tx *sql.Tx, settings *record.Settings) error {
	return f.write(func() error { return f.runDatabase.CreateInitialSettings(ctx, tx, settings) })
}

// Every write goes through the port's nine creates, and there are eighteen of them: the count the
// failure table below is written against.
func TestRun_MakesEighteenWrites(t *testing.T) {
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
				require.ErrorIs(t, err, errInjected)
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
	require.ErrorIs(t, err, errInjected)
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
	logs := logtest.CaptureSlog(t)

	_, err := testRunner(db, cfg).run(context.Background())
	require.NoError(t, err)

	var seeded []logtest.CapturedRecord
	for _, logRecord := range logs.Records() {
		assert.False(t, strings.HasSuffix(logRecord.Message, " created"), "no per-row record: %s", logRecord.Message)
		if logRecord.Message == "database seeded" {
			seeded = append(seeded, logRecord)
		}
	}
	require.Len(t, seeded, 1)

	keys, err := db.GetAllSigningKeys(context.Background(), nil)
	require.NoError(t, err)
	byState := map[string]string{}
	for _, key := range keys {
		byState[key.State] = key.KeyIdentifier
	}
	assert.Equal(t, builtin.AdminConsoleClientIdentifier, seeded[0].Attrs["client_identifier"])
	assert.Equal(t, "admin@example.com", seeded[0].Attrs["email"])
	assert.Equal(t, byState[record.KeyStateCurrent.String()], seeded[0].Attrs["current_key_identifier"])
	assert.Equal(t, byState[record.KeyStateNext.String()], seeded[0].Attrs["next_key_identifier"])

	messages := recordMessages(logs)
	assert.Contains(t, messages, "app name is not set, defaulting it")
	assert.Contains(t, messages, "using pre-generated OAuth client secret from environment")
}

// TestRun_AStopDuringTheSeedLetsItFinish and the case after it are #390 decision 9 for the seed: a
// shutdown signal arriving while the seed writes lets it commit, since it is one transaction and
// stopping it would only leave the next start to seed again, and one arriving before it begins
// keeps it from beginning.
func TestRun_AStopDuringTheSeedLetsItFinish(t *testing.T) {
	db := newSeedDB(t)
	cfg := singleStepConfig()
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	faults := &faultDB{runDatabase: db, onWrite: stop}

	outcome, err := testRunner(faults, cfg).run(ctx)

	require.NoError(t, err, "the seed under way when the stop arrived committed")
	assert.Equal(t, Continue, outcome)
	assert.Equal(t, seedWrites, faults.writes)
	assertSeeded(t, db, cfg)
}

func TestRun_AStopBeforeTheSeedLeavesTheDatabaseEmpty(t *testing.T) {
	db := newSeedDB(t)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	stopping := &stopAfterTheEmptinessCheck{runDatabase: db, stop: stop}
	faults := &faultDB{runDatabase: stopping}

	outcome, err := testRunner(faults, singleStepConfig()).run(ctx)

	require.ErrorIs(t, err, context.Canceled, "the start was asked to stop, and answers in a way main can match")
	assert.Equal(t, Refused, outcome)
	assert.Zero(t, faults.writes, "the seed did not begin")
	isEmpty, err := db.IsEmpty(context.Background())
	require.NoError(t, err)
	assert.True(t, isEmpty, "the next start seeds")
}

// stopAfterTheEmptinessCheck answers the emptiness check and then stops the start, which is the
// last moment before the seed begins.
type stopAfterTheEmptinessCheck struct {
	runDatabase
	stop func()
}

func (s *stopAfterTheEmptinessCheck) IsEmpty(ctx context.Context) (bool, error) {
	isEmpty, err := s.runDatabase.IsEmpty(ctx)
	s.stop()
	return isEmpty, err
}

// TestRun_ASeedThatLosesTheRaceCarriesOn is several replicas starting at once on an empty database
// (#542 decision 2): this start and another both find it empty, the other's seed commits first, and
// this one's first insert loses on the admin console client's unique key. Its transaction rolls back
// whole, the database reads as seeded, and it carries on as a start a moment later would, where it
// used to exit 1 on the duplicate key and be restarted to find the database seeded.
func TestRun_ASeedThatLosesTheRaceCarriesOn(t *testing.T) {
	for name, loserConfig := range map[string]func(t *testing.T) Config{
		"single-step": func(*testing.T) Config { return singleStepConfig() },
		"two-step":    twoStepConfig,
	} {
		t.Run(name, func(t *testing.T) {
			db := newSeedDB(t)
			winner := singleStepConfig()
			racing := &seedAfterTheEmptinessCheck{runDatabase: db, other: func() {
				outcome, err := testRunner(db, winner).run(context.Background())
				require.NoError(t, err, "the other instance seeds")
				require.Equal(t, Continue, outcome)
			}}
			faults := &faultDB{runDatabase: racing}
			cfg := loserConfig(t)
			logs := logtest.CaptureSlog(t)

			outcome, err := testRunner(faults, cfg).run(context.Background())

			require.NoError(t, err, "a seed lost to another instance is not a failed start")
			assert.Equal(t, Continue, outcome, "it carries on with the database the other instance seeded")
			assert.Equal(t, 1, faults.writes, "it lost at its first write")
			assertSeeded(t, db, winner)
			assert.Contains(t, recordMessages(logs),
				"another instance seeded the database while this one was seeding it, proceeding with normal startup")
			if cfg.BootstrapEnvOutFile != "" {
				entries, err := os.ReadDir(filepath.Dir(cfg.BootstrapEnvOutFile))
				require.NoError(t, err)
				assert.Empty(t, entries, "the loser publishes no file and leaves no staged one")
			}
		})
	}
}

// A unique violation is a lost race only when the database now reads as seeded. On one that still
// reads as empty it is a fault, refused with the seed's own error, as is a re-check that fails.
func TestRun_AUniqueViolationOnADatabaseStillEmptyIsRefused(t *testing.T) {
	db := newSeedDB(t)
	faults := &faultDB{runDatabase: db, failAt: 1,
		failWith: errs.Wrap(data.ErrUniqueViolation, "a unique key nobody else holds")}

	outcome, err := testRunner(faults, singleStepConfig()).run(context.Background())

	require.ErrorIs(t, err, data.ErrUniqueViolation)
	assert.Contains(t, err.Error(), "unable to seed the database")
	assert.Equal(t, Refused, outcome)
	isEmpty, err := db.IsEmpty(context.Background())
	require.NoError(t, err)
	assert.True(t, isEmpty)
}

// seedAfterTheEmptinessCheck answers the first emptiness check and then has another instance seed
// the database, which is the moment two starts racing on an empty database both pass: the other
// commits while this one is about to begin its own seed.
type seedAfterTheEmptinessCheck struct {
	runDatabase
	other   func()
	checked bool
}

func (s *seedAfterTheEmptinessCheck) IsEmpty(ctx context.Context) (bool, error) {
	isEmpty, err := s.runDatabase.IsEmpty(ctx)
	if !s.checked {
		s.checked = true
		s.other()
	}
	return isEmpty, err
}
