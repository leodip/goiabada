package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data/datafactory"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb/sqlitedbtest"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// The reencrypt command (#492 decisions 3, 5 and 8), in the style of recover's tests: each case
// runs the command against a SQLite file database of its own, at the head of the real migration
// set, and reads what it printed, its exit status, what the stored secrets are under afterwards and
// the audit rows it left.
//
// What a value is under is asserted with a cipher built here from one key alone, never from what
// the command reports: a value is under the new key when a cipher holding the new key alone opens
// it.

// The keys of the rotation as an operator sets them: the old key, the new one, and a third that is
// neither, under which nothing the command is given opens.
var (
	reencryptOldKey   = []byte("reencrypt-test-old-data-key-0123")
	reencryptNewKey   = []byte("reencrypt-test-new-data-key-0123")
	reencryptOtherKey = []byte("reencrypt-test-other-data-key-01")
)

// reencryptStopAcknowledgement is the line the command answers its first stop signal with, and
// reencryptStopReminder the one it answers every further one with, once the stop is made.
const (
	reencryptStopAcknowledgement = "stopping: no further stored secret will be re-encrypted"
	reencryptStopReminder        = "still stopping: a further Ctrl-C changes nothing"
)

// The plaintexts of the stored secrets each test database holds.
const (
	reencryptSMTPPassword = "the-smtp-password"
	reencryptClientSecret = "the-client-secret"
)

// sealUnder seals plaintext under key alone.
func sealUnder(t *testing.T, key []byte, plaintext string) []byte {
	t.Helper()
	sealed, err := encryption.EncryptText(plaintext, key)
	require.NoError(t, err)
	return sealed
}

// opensUnder reports whether key alone opens value.
func opensUnder(key, value []byte) bool {
	_, err := encryption.DecryptText(value, key)
	return err == nil
}

// reencryptSeal says which key each stored secret of a test database is sealed under.
type reencryptSeal struct {
	smtp       []byte
	clients    [][]byte // one client per key, in id order
	signingKey []byte
}

// allUnder seals the SMTP password, one client secret and the signing key under key.
func allUnder(key []byte) reencryptSeal {
	return reencryptSeal{smtp: key, clients: [][]byte{key}, signingKey: key}
}

// newReencryptDatabaseAt writes a SQLite file database at path, at the head of the real migration
// set, holding the settings row, with the SMTP password and audit events stored in the database,
// the clients and the current signing key, each secret sealed under the key seal names for it.
func newReencryptDatabaseAt(t *testing.T, path string, seal reencryptSeal) *sqlitedb.Database {
	t.Helper()

	sqlitedbtest.WriteMigrated(t, path)
	db, err := sqlitedb.New(context.Background(), "file:"+path, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.DB.Close() })

	// The shared signing key, sealed under recover's test key, opened and sealed again under the
	// key this database holds it under.
	keyPair := recoverTestKeyPair(t)
	pem, err := recoverTestCipher.Decrypt(keyPair.PrivateKeyPEM)
	require.NoError(t, err)
	keyPair.PrivateKeyPEM = sealUnder(t, seal.signingKey, pem)

	ctx := context.Background()
	require.NoError(t, db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		if err := db.CreateInitialSettings(ctx, tx, &record.Settings{
			AppName:                         "reencrypt test",
			Issuer:                          "https://localhost:8080",
			PasswordPolicy:                  record.PasswordPolicyLow,
			AESEncryptionKeyLegacy:          []byte{},
			UserSessionIdleTimeoutInSeconds: 7200,
			UserSessionMaxLifetimeInSeconds: 86400,
			SMTPPasswordEncrypted:           sealUnder(t, seal.smtp, reencryptSMTPPassword),
			AuditLogsInDatabaseEnabled:      true,
		}); err != nil {
			return err
		}
		for i, key := range seal.clients {
			if err := db.CreateClient(ctx, tx, &record.Client{
				ClientIdentifier:      "client-" + strconv.Itoa(i+1),
				Enabled:               true,
				ClientSecretEncrypted: sealUnder(t, key, reencryptClientSecret),
			}); err != nil {
				return err
			}
		}
		return db.CreateKeyPair(ctx, tx, keyPair)
	}))
	return db
}

// newReencryptDatabase is newReencryptDatabaseAt in a directory of the test's own.
func newReencryptDatabase(t *testing.T, seal reencryptSeal) *sqlitedb.Database {
	t.Helper()
	return newReencryptDatabaseAt(t, filepath.Join(t.TempDir(), "reencrypt_test.db"), seal)
}

// storedSecrets answers every stored secret of the test database, by where it is held.
func storedSecrets(t *testing.T, db *sqlitedb.Database) map[string][]byte {
	t.Helper()
	ctx := context.Background()
	secrets := map[string][]byte{}

	settings, err := db.GetSettingsByID(ctx, nil, 1)
	require.NoError(t, err)
	secrets["settings.smtp_password_encrypted"] = settings.SMTPPasswordEncrypted

	clients, err := db.GetAllClients(ctx, nil)
	require.NoError(t, err)
	for _, client := range clients {
		secrets["clients."+client.ClientIdentifier] = client.ClientSecretEncrypted
	}

	key, err := db.GetCurrentSigningKey(ctx, nil)
	require.NoError(t, err)
	secrets["key_pairs.current"] = key.PrivateKeyPEM
	return secrets
}

// reencryptAuditRows answers the audit rows the test database holds, oldest first.
func reencryptAuditRows(t *testing.T, db *sqlitedb.Database) []record.AuditLog {
	t.Helper()
	rows, _, err := db.GetAuditLogsPaginated(context.Background(), nil, 1, 100, record.AuditLogFilter{})
	require.NoError(t, err)
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	return rows
}

// reencryptDetails answers an audit row's details.
func reencryptDetails(t *testing.T, row record.AuditLog) map[string]interface{} {
	t.Helper()
	var details map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(row.Details), &details))
	return details
}

// runReencryptOn runs the command against the database with the keys given, through the audit
// logger the command builds, and answers its exit status with what it printed on each stream.
func runReencryptOn(t *testing.T, db *sqlitedb.Database, current, previous []byte) (int, string, string) {
	t.Helper()
	return runReencryptUnder(t, context.Background(), db, current, previous)
}

// runReencryptUnder is runReencryptOn under ctx.
func runReencryptUnder(t *testing.T, ctx context.Context, db *sqlitedb.Database, current, previous []byte) (int, string, string) {
	t.Helper()
	m, err := db.NewMigrator(context.Background(), nil)
	require.NoError(t, err)
	var out, errOut bytes.Buffer
	code := runReencrypt(ctx, db, m,
		audit.NewLogger(db, middleware.NewAuditSwitches(db), middleware.ActingUser{}),
		reencryptDataKeys{current: current, previous: previous}, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestParseReencryptArgs(t *testing.T) {
	t.Run("reads the database flags", func(t *testing.T) {
		inv, err := parseReencryptArgs([]string{"--db-dsn=file:b.db", "--db-type", "sqlite"}, migrateArgsBase())
		require.NoError(t, err)
		assert.Equal(t, "file:b.db", inv.database.DSN)
		assert.False(t, inv.help)
	})

	t.Run("no flag at all", func(t *testing.T) {
		inv, err := parseReencryptArgs(nil, migrateArgsBase())
		require.NoError(t, err)
		assert.Equal(t, migrateArgsBase(), inv.database)
	})

	t.Run("help", func(t *testing.T) {
		for _, args := range [][]string{{"-h"}, {"--help"}, {"--db-dsn=file:b.db", "-help"}} {
			inv, err := parseReencryptArgs(args, migrateArgsBase())
			require.NoError(t, err, "%#v", args)
			assert.True(t, inv.help, "%#v", args)
		}
	})

	t.Run("a positional argument is refused", func(t *testing.T) {
		_, err := parseReencryptArgs([]string{"all"}, migrateArgsBase())
		require.Error(t, err)
		assert.Equal(t, `"all" is not an argument reencrypt takes: it takes only the --db-* flags`, err.Error())
	})

	t.Run("a flag that is not a database flag is refused", func(t *testing.T) {
		_, err := parseReencryptArgs([]string{"--email", "a@example.com"}, migrateArgsBase())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--email is not a flag reencrypt accepts")
		assert.Contains(t, err.Error(), "only the --db-* flags can follow reencrypt")
	})
}

// TestReencryptUsage_NamesEveryDatabaseFlag: every flag config.RegisterDatabaseFlags registers can
// follow reencrypt, so the usage, the only place they are spelled out, names each one.
func TestReencryptUsage_NamesEveryDatabaseFlag(t *testing.T) {
	fs := flag.NewFlagSet("reencrypt", flag.ContinueOnError)
	config.RegisterDatabaseFlags(fs, &config.DatabaseConfig{})
	var names []string
	fs.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	require.NotEmpty(t, names)
	for _, name := range names {
		named := regexp.MustCompile(`--` + regexp.QuoteMeta(name) + `([^-a-z]|$)`)
		assert.Truef(t, named.MatchString(reencryptUsage), "the reencrypt usage does not name --%s", name)
	}
	for _, want := range []string{"GOIABADA_AES_ENCRYPTION_KEY", "GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS",
		"exits 0", "1 when", "2 for"} {
		assert.Contains(t, reencryptUsage, want)
	}
}

func TestReencryptCommand_HelpPrintsTheUsageAndOpensNothing(t *testing.T) {
	a := filepath.Join(t.TempDir(), "a.db")

	var stdout, stderr bytes.Buffer
	inv, ok := readReencryptCommand([]string{"--help"}, sqliteBase(a), &stderr)
	require.True(t, ok, "stderr: %s", stderr.String())
	code := runReencryptCommand(inv, datafactory.OpenDatabase, reencryptDataKeys{}, &stdout, &stderr)

	require.Equal(t, migrateExitOK, code)
	assert.Equal(t, reencryptUsage+"\n", stdout.String())
	assert.Empty(t, stderr.String(), "help needs no key, and refuses nothing")
	assert.NoFileExists(t, a)
}

// TestReencryptCommand_RefusesAUsageMistakeBeforeOpeningAnything: a malformed invocation is refused
// with the usage, for an exit with status 2, and the database named is never created.
func TestReencryptCommand_RefusesAUsageMistakeBeforeOpeningAnything(t *testing.T) {
	for _, args := range [][]string{{"now"}, {"--password", "x"}, {"--db-port=abc"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			a := filepath.Join(t.TempDir(), "a.db")

			var stderr bytes.Buffer
			_, ok := readReencryptCommand(args, sqliteBase(a), &stderr)

			require.False(t, ok)
			assert.Contains(t, stderr.String(), "\n\n"+reencryptUsage+"\n")
			assert.NoFileExists(t, a)
		})
	}
}

// TestReencryptCommand_RefusesADataKeyItCannotUseBeforeOpeningAnything: a current key that is
// missing, malformed or the published sample key, or a previous key that is malformed, refuses the
// run with exit status 1 before the database is opened, as it refuses a start.
func TestReencryptCommand_RefusesADataKeyItCannotUseBeforeOpeningAnything(t *testing.T) {
	sample := publishedSampleDataKey
	for _, tc := range []struct {
		name, current, previous, want string
	}{
		{"no current key", "", "", "GOIABADA_AES_ENCRYPTION_KEY is required"},
		{"a current key not hex", strings.Repeat("zz", 32), "", "GOIABADA_AES_ENCRYPTION_KEY must be hex-encoded"},
		{"a current key too short", strings.Repeat("ab", 16), "", "GOIABADA_AES_ENCRYPTION_KEY must be 32 bytes"},
		{"the published sample key as the current key", sample, "",
			"GOIABADA_AES_ENCRYPTION_KEY is the sample key this repository published"},
		{"a previous key too short", strings.Repeat("ab", 32), strings.Repeat("cd", 16),
			"GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS must be 32 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := filepath.Join(t.TempDir(), "a.db")
			keys := readReencryptDataKeys(&config.Config{AESEncryptionKey: tc.current,
				AESEncryptionKeyPrevious: tc.previous})

			var stdout, stderr bytes.Buffer
			inv, ok := readReencryptCommand(nil, sqliteBase(a), &stderr)
			require.True(t, ok, "stderr: %s", stderr.String())
			code := runReencryptCommand(inv, datafactory.OpenDatabase, keys, &stdout, &stderr)

			require.Equal(t, migrateExitError, code)
			assert.True(t, strings.HasPrefix(stderr.String(), "refusing to re-encrypt: "), stderr.String())
			assert.Contains(t, stderr.String(), tc.want)
			assert.Empty(t, stdout.String())
			assert.NoFileExists(t, a, "the database was never opened")
		})
	}

	// The sample key is refused as the current key only: a rotation off it holds it as the
	// previous key.
	t.Run("the published sample key as the previous key", func(t *testing.T) {
		keys := readReencryptDataKeys(&config.Config{AESEncryptionKey: strings.Repeat("ab", 32),
			AESEncryptionKeyPrevious: sample})
		require.NoError(t, keys.err)
	})
}

// TestReencryptCommand_NeverCreatesTheDatabase: on every server engine the opener is handed a
// configuration that does not create the database, whatever the base or a --db-create after
// reencrypt asks, so a mistyped name is refused as missing, as recover refuses it.
func TestReencryptCommand_NeverCreatesTheDatabase(t *testing.T) {
	for _, engine := range []string{"mysql", "postgres", "mssql"} {
		t.Run(engine, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			base := config.DatabaseConfig{Type: engine, Host: "localhost", Port: 5432,
				Name: "goiabada_typo", Create: true}

			var stdout, stderr bytes.Buffer
			inv, ok := readReencryptCommand([]string{"--db-create=true"}, base, &stderr)
			require.True(t, ok, "stderr: %s", stderr.String())

			var opened []config.DatabaseConfig
			open := func(_ context.Context, c *config.DatabaseConfig, _ bool) (datafactory.Migratable, error) {
				opened = append(opened, *c)
				return nil, errors.New(`database "goiabada_typo" does not exist`)
			}
			code := runReencryptCommand(inv, open, reencryptDataKeys{current: reencryptNewKey}, &stdout, &stderr)

			require.Equal(t, migrateExitError, code)
			require.Len(t, opened, 1)
			assert.False(t, opened[0].Create, "reencrypt asked the opener to create the database")
			assert.Contains(t, stderr.String(), `unable to open the database: database "goiabada_typo" does not exist`)

			records := logs.Records()
			require.Len(t, records, 1, "logs: %s", logs.Text())
			assert.Equal(t, "reencrypt never creates a server database, so it must already exist", records[0].Message)
			assert.Equal(t, "GOIABADA_DB_CREATE", records[0].Attrs["setting"])
			assert.Equal(t, true, records[0].Attrs["configured"])
		})
	}
}

// TestReencryptCommand_AFlagAfterReencryptChoosesTheDatabaseOpened: the base names file A, the flag
// after `reencrypt` names file B, and B is the database re-encrypted. A is never created.
func TestReencryptCommand_AFlagAfterReencryptChoosesTheDatabaseOpened(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.db"), filepath.Join(dir, "b.db")
	db := newReencryptDatabaseAt(t, b, allUnder(reencryptOldKey))

	var stdout, stderr bytes.Buffer
	inv, ok := readReencryptCommand([]string{"--db-dsn=file:" + b}, sqliteBase(a), &stderr)
	require.True(t, ok, "stderr: %s", stderr.String())
	code := runReencryptCommand(inv, datafactory.OpenDatabase,
		reencryptDataKeys{current: reencryptNewKey, previous: reencryptOldKey}, &stdout, &stderr)

	require.Equal(t, migrateExitOK, code, "stderr: %s", stderr.String())
	assert.NoFileExists(t, a)
	for where, value := range storedSecrets(t, db) {
		assert.Truef(t, opensUnder(reencryptNewKey, value), "%s is under the new key", where)
	}
}

func TestReencrypt_RefusesASchemaThisBinaryDoesNotCarry(t *testing.T) {
	for _, tc := range []struct {
		name  string
		place func(t *testing.T, sqlDB *sql.DB, head int)
		want  string
	}{
		{"a newer schema", func(t *testing.T, sqlDB *sql.DB, head int) {
			_, err := sqlDB.Exec("UPDATE schema_migrations SET version = ?", head+1)
			require.NoError(t, err)
		}, "a newer release migrated it. Run the reencrypt command of that release"},
		{"a dirty schema", func(t *testing.T, sqlDB *sql.DB, _ int) {
			_, err := sqlDB.Exec("UPDATE schema_migrations SET dirty = 1")
			require.NoError(t, err)
		}, "DIRTY: a migration did not finish. Repair the schema by hand as " +
			"https://goiabada.dev/troubleshooting/waiting-for-the-migration-lock-or-marked-dirty/ " +
			"describes, then run reencrypt again"},
		{"an older schema", func(t *testing.T, sqlDB *sql.DB, head int) {
			_, err := sqlDB.Exec("UPDATE schema_migrations SET version = ?", head-1)
			require.NoError(t, err)
		}, "it is behind this release. Run `goiabada-authserver migrate to %d`, or start this " +
			"release's auth server once, then run reencrypt again"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newReencryptDatabase(t, allUnder(reencryptOldKey))
			before := storedSecrets(t, db)
			m, err := db.NewMigrator(context.Background(), nil)
			require.NoError(t, err)
			tc.place(t, db.DB, m.Head())

			code, stdout, stderr := runReencryptOn(t, db, reencryptNewKey, reencryptOldKey)

			assert.Equal(t, migrateExitError, code)
			assert.Contains(t, stderr, "refusing to re-encrypt: the database records schema version")
			want := tc.want
			if strings.Contains(want, "%d") {
				want = fmt.Sprintf(want, m.Head())
			}
			assert.Contains(t, stderr, want)
			assert.Empty(t, stdout)
			assert.Equal(t, before, storedSecrets(t, db), "nothing was re-encrypted")
			assert.Empty(t, reencryptAuditRows(t, db), "and nothing recorded")
		})
	}

	t.Run("a database never migrated", func(t *testing.T) {
		db, err := sqlitedb.New(context.Background(), "file:"+filepath.Join(t.TempDir(), "empty.db"), false)
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.DB.Close() })

		code, _, stderr := runReencryptOn(t, db, reencryptNewKey, reencryptOldKey)

		assert.Equal(t, migrateExitError, code)
		assert.Contains(t, stderr, "refusing to re-encrypt: the database records no schema version: it has "+
			"never been migrated")
	})
}

// TestReencrypt_MovesEveryStoredSecretToTheCurrentKey is the rotation's step: with the new key
// current and the old one previous, every stored secret ends under the new key, one summary says
// so, the run exits 0 and writes one reencrypted_stored_secrets event naming the command.
func TestReencrypt_MovesEveryStoredSecretToTheCurrentKey(t *testing.T) {
	db := newReencryptDatabase(t, reencryptSeal{
		smtp:       reencryptOldKey,
		clients:    [][]byte{reencryptOldKey, reencryptNewKey},
		signingKey: reencryptOldKey,
	})

	code, stdout, stderr := runReencryptOn(t, db, reencryptNewKey, reencryptOldKey)

	require.Equal(t, migrateExitOK, code, "stderr: %s", stderr)
	assert.Equal(t, "stored secrets re-encrypted to the current data key: 3, already under it: 1\n", stdout)
	assert.Empty(t, stderr)
	for where, value := range storedSecrets(t, db) {
		assert.Truef(t, opensUnder(reencryptNewKey, value), "%s is under the new key", where)
		assert.Falsef(t, opensUnder(reencryptOldKey, value), "%s is no longer under the old key", where)
	}
	settings, err := db.GetSettingsByID(context.Background(), nil, 1)
	require.NoError(t, err)
	password, err := encryption.DecryptText(settings.SMTPPasswordEncrypted, reencryptNewKey)
	require.NoError(t, err)
	assert.Equal(t, reencryptSMTPPassword, password, "the value is the one it was")

	rows := reencryptAuditRows(t, db)
	require.Len(t, rows, 1)
	assert.Equal(t, "reencrypted_stored_secrets", rows[0].AuditEvent)
	assert.Equal(t, map[string]interface{}{
		"command":     "goiabada-authserver reencrypt",
		"reencrypted": float64(3),
		"unreadable":  float64(0),
	}, reencryptDetails(t, rows[0]))
	assert.False(t, rows[0].UserID.Valid, "the event is about no user")
	assert.False(t, rows[0].LoggedInUserID.Valid, "and no user's token made it")

	// Run again, it finds everything under the current key, re-encrypts nothing and records nothing.
	code, stdout, stderr = runReencryptOn(t, db, reencryptNewKey, reencryptOldKey)
	require.Equal(t, migrateExitOK, code, "stderr: %s", stderr)
	assert.Equal(t, "stored secrets re-encrypted to the current data key: 0, already under it: 4\n", stdout)
	assert.Empty(t, stderr)
	assert.Len(t, reencryptAuditRows(t, db), 1, "a run that changed nothing writes no event")
}

// TestReencrypt_GoesOnPastAValueNeitherKeyOpens: a value under neither key is left byte for byte,
// named on stderr by table, column and row id, never by its content; every other value is
// re-encrypted, and the run exits 1. The event counts both.
func TestReencrypt_GoesOnPastAValueNeitherKeyOpens(t *testing.T) {
	db := newReencryptDatabase(t, reencryptSeal{
		smtp:       reencryptOldKey,
		clients:    [][]byte{reencryptOtherKey, reencryptOldKey},
		signingKey: reencryptOldKey,
	})
	before := storedSecrets(t, db)

	code, stdout, stderr := runReencryptOn(t, db, reencryptNewKey, reencryptOldKey)

	require.Equal(t, migrateExitError, code)
	assert.Equal(t, "stored secrets re-encrypted to the current data key: 3, already under it: 0\n", stdout)
	assert.Equal(t, "unreadable: clients.client_secret_encrypted, row 1: neither data key opens it, so it was left as it is\n"+
		"1 stored secret opens under neither data key and was left as it is. If it was sealed under "+
		"an older key, set that key as GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS and run reencrypt again\n", stderr)
	assert.NotContains(t, stderr, reencryptClientSecret)

	after := storedSecrets(t, db)
	assert.Equal(t, before["clients.client-1"], after["clients.client-1"], "the unreadable value is left byte for byte")
	for _, where := range []string{"settings.smtp_password_encrypted", "clients.client-2", "key_pairs.current"} {
		assert.Truef(t, opensUnder(reencryptNewKey, after[where]), "%s is under the new key", where)
	}

	rows := reencryptAuditRows(t, db)
	require.Len(t, rows, 1)
	assert.Equal(t, "reencrypted_stored_secrets", rows[0].AuditEvent)
	assert.Equal(t, map[string]interface{}{
		"command":     "goiabada-authserver reencrypt",
		"reencrypted": float64(3),
		"unreadable":  float64(1),
	}, reencryptDetails(t, rows[0]))
}

// TestReencrypt_NamesEveryUnreadableValueAcrossBatches: a table larger than one of the sweep's
// batches has each value neither key opens named on stderr, once and in id order, however many
// batches the sweep reads it in, and the closing line counts them all.
func TestReencrypt_NamesEveryUnreadableValueAcrossBatches(t *testing.T) {
	const clients = 250
	seal := reencryptSeal{smtp: reencryptOldKey, signingKey: reencryptOldKey}
	for range clients {
		seal.clients = append(seal.clients, reencryptOtherKey)
	}
	db := newReencryptDatabase(t, seal)

	code, stdout, stderr := runReencryptOn(t, db, reencryptNewKey, reencryptOldKey)

	require.Equal(t, migrateExitError, code)
	assert.Equal(t, "stored secrets re-encrypted to the current data key: 2, already under it: 0\n", stdout)
	var want strings.Builder
	for id := 1; id <= clients; id++ {
		fmt.Fprintf(&want, "unreadable: clients.client_secret_encrypted, row %d: neither data key opens it, so it was left as it is\n", id)
	}
	want.WriteString("250 stored secrets open under neither data key and were left as they are. If they were sealed " +
		"under an older key, set that key as GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS and run reencrypt again\n")
	assert.Equal(t, want.String(), stderr)

	rows := reencryptAuditRows(t, db)
	require.Len(t, rows, 1)
	assert.Equal(t, map[string]interface{}{
		"command":     "goiabada-authserver reencrypt",
		"reencrypted": float64(2),
		"unreadable":  float64(clients),
	}, reencryptDetails(t, rows[0]))
}

// TestReencrypt_WithNoPreviousKeyItChecks is the check an operator runs after removing the previous
// key: nothing is re-encrypted or written, the summary says the run checked, and the exit status
// says whether every stored secret opens under the current key alone. A run that changed nothing
// writes no event.
func TestReencrypt_WithNoPreviousKeyItChecks(t *testing.T) {
	t.Run("everything under the current key", func(t *testing.T) {
		db := newReencryptDatabase(t, allUnder(reencryptNewKey))
		before := storedSecrets(t, db)

		for _, previous := range [][]byte{nil, reencryptNewKey} {
			code, stdout, stderr := runReencryptOn(t, db, reencryptNewKey, previous)

			require.Equal(t, migrateExitOK, code, "stderr: %s", stderr)
			assert.Equal(t, "no previous data key is set, so nothing was re-encrypted; stored secrets "+
				"under the current data key: 3\n", stdout)
			assert.Empty(t, stderr)
		}
		assert.Equal(t, before, storedSecrets(t, db), "nothing was written")
		assert.Empty(t, reencryptAuditRows(t, db), "and nothing recorded")
	})

	t.Run("a value still under the old key", func(t *testing.T) {
		db := newReencryptDatabase(t, reencryptSeal{
			smtp:       reencryptNewKey,
			clients:    [][]byte{reencryptOldKey},
			signingKey: reencryptNewKey,
		})
		before := storedSecrets(t, db)

		code, stdout, stderr := runReencryptOn(t, db, reencryptNewKey, nil)

		require.Equal(t, migrateExitError, code)
		assert.Equal(t, "no previous data key is set, so nothing was re-encrypted; stored secrets "+
			"under the current data key: 2\n", stdout)
		assert.True(t, strings.HasPrefix(stderr,
			"unreadable: clients.client_secret_encrypted, row 1: neither data key opens it, so it was left as it is\n"), stderr)
		assert.Equal(t, before, storedSecrets(t, db), "nothing was written")
		assert.Empty(t, reencryptAuditRows(t, db), "and nothing recorded")
	})
}

// TestReencrypt_ADatabaseNotYetSeededIsNothingToDo: migrated to the binary's schema but holding no
// stored secret, the run exits 0 and records nothing.
func TestReencrypt_ADatabaseNotYetSeededIsNothingToDo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unseeded.db")
	sqlitedbtest.WriteMigrated(t, path)
	db, err := sqlitedb.New(context.Background(), "file:"+path, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.DB.Close() })

	code, stdout, stderr := runReencryptOn(t, db, reencryptNewKey, reencryptOldKey)

	require.Equal(t, migrateExitOK, code, "stderr: %s", stderr)
	assert.Equal(t, "stored secrets re-encrypted to the current data key: 0, already under it: 0\n", stdout)
	assert.Empty(t, stderr)
}

// TestReencrypt_AFailureSaysHowFarItGot: a run whose database fails under it exits 1, says what it
// had done, and records the event for what it re-encrypted before the failure.
func TestReencrypt_AFailureSaysHowFarItGot(t *testing.T) {
	db := newReencryptDatabase(t, allUnder(reencryptOldKey))
	// The signing keys go last, so the settings row and the client are re-encrypted before the
	// read of a table that is gone fails the run.
	_, err := db.DB.Exec("ALTER TABLE key_pairs RENAME TO key_pairs_gone")
	require.NoError(t, err)

	code, stdout, stderr := runReencryptOn(t, db, reencryptNewKey, reencryptOldKey)

	require.Equal(t, migrateExitError, code)
	assert.Empty(t, stdout)
	assert.True(t, strings.HasPrefix(stderr, "unable to re-encrypt the stored secrets: "), stderr)
	assert.Contains(t, stderr, "key_pairs")
	assert.Contains(t, stderr, "stored secrets re-encrypted before the failure: 2, already under the "+
		"current data key: 0; run the same command again to carry on\n")

	rows := reencryptAuditRows(t, db)
	require.Len(t, rows, 1, "the event is written after a failure too")
	assert.Equal(t, map[string]interface{}{
		"command":     "goiabada-authserver reencrypt",
		"reencrypted": float64(2),
		"unreadable":  float64(0),
	}, reencryptDetails(t, rows[0]))
}

// TestReencrypt_TheEventObeysTheAuditSwitches: the event goes through the server's audit logger,
// so a deployment that stores no audit event in its database finds none there.
func TestReencrypt_TheEventObeysTheAuditSwitches(t *testing.T) {
	db := newReencryptDatabase(t, allUnder(reencryptOldKey))
	_, err := db.DB.Exec("UPDATE settings SET audit_logs_in_database_enabled = 0")
	require.NoError(t, err)

	code, _, stderr := runReencryptOn(t, db, reencryptNewKey, reencryptOldKey)

	require.Equal(t, migrateExitOK, code, "stderr: %s", stderr)
	assert.Empty(t, reencryptAuditRows(t, db))
}

// reencryptStopTrigger holds the sweep's first client write, client-1's, inside it until the case
// lets it go: a trigger on the clients table calls the blocking function migrate's stop tests hold
// their files with. It fires for that client alone, so a write to the second is left for the case
// to find rather than meeting a hold already used.
const reencryptStopTrigger = "CREATE TRIGGER reencrypt_test_hold AFTER UPDATE OF client_secret_encrypted ON clients " +
	"WHEN NEW.client_identifier = 'client-1' BEGIN SELECT " + blockingFunction + "(); END"

// reencryptCounts reads the two counts out of a line the command printed.
func reencryptCounts(t *testing.T, pattern, printed string) (int, int) {
	t.Helper()
	match := regexp.MustCompile(pattern).FindStringSubmatch(printed)
	require.NotNilf(t, match, "%q is not printed in\n%s", pattern, printed)
	reencrypted, err := strconv.Atoi(match[1])
	require.NoError(t, err)
	already, err := strconv.Atoi(match[2])
	require.NoError(t, err)
	return reencrypted, already
}

// TestReencryptCommand_AStopSignalEndsItBetweenValues: a stop signal, sent to this process while
// the sweep is inside a write, is answered as it arrives, and the run ends between values: it says
// how far it got and exits 1, and records what it re-encrypted. A later run carries on and leaves
// every value under the new key. The signals are real, so what runReencryptCommand installs is
// what is tested.
//
// The write held when the signal arrives is a transaction of its own, so its outcome is known: the
// first run's count is exactly what it committed, which the second run finds already under the new
// key, and its event is written exactly when that count is not zero (#492 decision 8). With the
// SMTP password already under the new key, the held client write is the run's first.
//
// The held write is let go only once the stop is made: the acknowledgement is printed before it,
// so the case sends the signal again and waits for the reminder, printed after it. The held write
// may then commit or roll back, but no further one starts: the second client and the signing key
// are as they were before the run.
func TestReencryptCommand_AStopSignalEndsItBetweenValues(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		for _, smtp := range []struct {
			name           string
			key            []byte
			alreadyCurrent int
		}{
			{"the SMTP password written before the held write", reencryptOldKey, 0},
			{"the held write the first", reencryptNewKey, 1},
		} {
			t.Run(sig.String()+", "+smtp.name, func(t *testing.T) {
				hold := holdTheFile(t)
				path := filepath.Join(t.TempDir(), "held.db")
				db := newReencryptDatabaseAt(t, path, reencryptSeal{
					smtp:       smtp.key,
					clients:    [][]byte{reencryptOldKey, reencryptOldKey},
					signingKey: reencryptOldKey,
				})
				_, err := db.DB.Exec(reencryptStopTrigger)
				require.NoError(t, err)
				before := storedSecrets(t, db)
				require.NotEmpty(t, before["clients.client-2"])
				require.NotEmpty(t, before["key_pairs.current"])

				var stderr bytes.Buffer
				inv, ok := readReencryptCommand([]string{"--db-dsn=file:" + path}, sqliteBase(path), &stderr)
				require.True(t, ok, "stderr: %s", stderr.String())
				var out lockedWriter
				done := make(chan int, 1)
				go func() {
					done <- runReencryptCommand(inv, datafactory.OpenDatabase,
						reencryptDataKeys{current: reencryptNewKey, previous: reencryptOldKey}, &out, &stderr)
				}()

				select {
				case <-hold.entered:
				case code := <-done:
					t.Fatalf("reencrypt returned %d before reaching the held write\n%s%s", code, out.String(), stderr.String())
				case <-time.After(30 * time.Second):
					t.Fatal("the sweep never reached the held write")
				}
				require.NoError(t, syscall.Kill(syscall.Getpid(), sig))
				require.Eventually(t, func() bool {
					return strings.Contains(out.String(), reencryptStopAcknowledgement)
				}, 10*time.Second, 10*time.Millisecond, "the signal is answered as it arrives")
				// The second signal is sent once the first is answered, since the kernel coalesces
				// two identical signals still pending.
				require.NoError(t, syscall.Kill(syscall.Getpid(), sig))
				require.Eventually(t, func() bool {
					return strings.Contains(out.String(), reencryptStopReminder)
				}, 10*time.Second, 10*time.Millisecond, "the stop is made while the write is held")
				hold.let()

				var code int
				select {
				case code = <-done:
				case <-time.After(30 * time.Second):
					t.Fatal("reencrypt did not return after the held write was let go")
				}
				require.Equal(t, migrateExitError, code, "%s%s", out.String(), stderr.String())
				assert.True(t, strings.HasPrefix(out.String(), reencryptStopAcknowledgement+"\n"+reencryptStopReminder+"\n"),
					out.String())
				assert.NotContains(t, out.String(), "stored secrets re-encrypted to the current data key",
					"a stop is not a finished run")
				first, _ := reencryptCounts(t, `stopped by a signal: stored secrets re-encrypted so far: (\d+), `+
					`already under the current data key: (\d+); run the same command again to carry on\n`, out.String())
				if smtp.alreadyCurrent == 0 {
					assert.GreaterOrEqual(t, first, 1, "the SMTP password, before the clients, was re-encrypted")
				}
				assert.LessOrEqual(t, first, 2-smtp.alreadyCurrent,
					"the run ended at the held write: the SMTP password and the held client at most")
				assert.Empty(t, stderr.String(), "a stop is not a failure")
				stopped := storedSecrets(t, db)
				assert.Equal(t, before["clients.client-2"], stopped["clients.client-2"],
					"no write starts after the stop: the second client is as it was")
				assert.Equal(t, before["key_pairs.current"], stopped["key_pairs.current"],
					"nor is the signing key re-encrypted")

				rows := reencryptAuditRows(t, db)
				if first == 0 {
					assert.Empty(t, rows, "a stopped run that committed nothing records nothing")
				} else {
					require.Len(t, rows, 1, "the event is written after a stop too")
					assert.Equal(t, map[string]interface{}{
						"command":     "goiabada-authserver reencrypt",
						"reencrypted": float64(first),
						"unreadable":  float64(0),
					}, reencryptDetails(t, rows[0]))
				}

				_, err = db.DB.Exec("DROP TRIGGER reencrypt_test_hold")
				require.NoError(t, err)
				code, stdout, errOut := runReencryptOn(t, db, reencryptNewKey, reencryptOldKey)
				require.Equal(t, migrateExitOK, code, "stderr: %s", errOut)
				second, already := reencryptCounts(t, `stored secrets re-encrypted to the current data key: (\d+), `+
					`already under it: (\d+)\n`, stdout)
				assert.Equal(t, 4, second+already, "the second run reaches every value")
				assert.Equal(t, first+smtp.alreadyCurrent, already,
					"the first run counted exactly the writes it committed, the held one included when it landed")
				for where, value := range storedSecrets(t, db) {
					assert.Truef(t, opensUnder(reencryptNewKey, value), "%s is under the new key", where)
				}
			})
		}
	}
}

// TestMain_ReencryptRunsThroughTheRealMain is the reencrypt branch at the process: the real main,
// its real config.Load over a real command line and environment, and a SQLite file whose stored
// secrets are under the old key. These fail if main stops dispatching `reencrypt`, stops handing it
// the flags after it, or drops either data key on its way to the command; every function below it
// can be right while that wiring is wrong.
func TestMain_ReencryptRunsThroughTheRealMain(t *testing.T) {
	newKey := "GOIABADA_AES_ENCRYPTION_KEY=" + hex.EncodeToString(reencryptNewKey)
	oldKeyAsPrevious := "GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS=" + hex.EncodeToString(reencryptOldKey)

	t.Run("the swap, then the previous key removed", func(t *testing.T) {
		dir := t.TempDir()
		target, decoy := filepath.Join(dir, "f.db"), filepath.Join(dir, "d.db")
		db := newReencryptDatabaseAt(t, target, allUnder(reencryptOldKey))

		code, stderr := runMainProcessWith(t, decoy, []string{newKey, oldKeyAsPrevious},
			"reencrypt", "--db-dsn=file:"+target)

		require.Equal(t, migrateExitOK, code, "stderr: %s", stderr)
		assert.NoFileExists(t, decoy)
		for where, value := range storedSecrets(t, db) {
			assert.Truef(t, opensUnder(reencryptNewKey, value), "%s is under the new key", where)
		}
		rows := reencryptAuditRows(t, db)
		require.Len(t, rows, 1)
		assert.Equal(t, "reencrypted_stored_secrets", rows[0].AuditEvent)

		// The check after the previous key is removed.
		code, stderr = runMainProcessWith(t, decoy, []string{newKey}, "-db-dsn=file:"+target, "reencrypt")
		require.Equal(t, migrateExitOK, code, "stderr: %s", stderr)
		assert.Len(t, reencryptAuditRows(t, db), 1, "the check records nothing")
	})

	t.Run("the previous key removed too soon", func(t *testing.T) {
		dir := t.TempDir()
		target, decoy := filepath.Join(dir, "f.db"), filepath.Join(dir, "d.db")
		db := newReencryptDatabaseAt(t, target, allUnder(reencryptOldKey))
		before := storedSecrets(t, db)

		code, stderr := runMainProcessWith(t, decoy, []string{newKey}, "reencrypt", "--db-dsn=file:"+target)

		require.Equal(t, migrateExitError, code, "stderr: %s", stderr)
		assert.Contains(t, stderr, "unreadable: settings.smtp_password_encrypted, row 1: neither data key opens it")
		assert.Equal(t, before, storedSecrets(t, db), "nothing was written")
	})

	t.Run("a stray argument opens nothing", func(t *testing.T) {
		dir := t.TempDir()
		target, decoy := filepath.Join(dir, "f.db"), filepath.Join(dir, "d.db")

		code, stderr := runMainProcessWith(t, decoy, []string{newKey, oldKeyAsPrevious},
			"reencrypt", "--db-dsn=file:"+target, "everything")

		require.Equal(t, migrateExitUsage, code, "stderr: %s", stderr)
		assert.Equal(t, `"everything" is not an argument reencrypt takes: it takes only the --db-* flags`+
			"\n\n"+reencryptUsage+"\n", stderr)
		assert.NoFileExists(t, target)
		assert.NoFileExists(t, decoy)
	})

	t.Run("the published sample key opens nothing", func(t *testing.T) {
		dir := t.TempDir()
		target, decoy := filepath.Join(dir, "f.db"), filepath.Join(dir, "d.db")

		code, stderr := runMainProcessWith(t, decoy, []string{
			"GOIABADA_AES_ENCRYPTION_KEY=" + publishedSampleDataKey,
		}, "reencrypt", "--db-dsn=file:"+target)

		require.Equal(t, migrateExitError, code, "stderr: %s", stderr)
		assert.Contains(t, stderr, "refusing to re-encrypt: GOIABADA_AES_ENCRYPTION_KEY is the sample key")
		assert.NoFileExists(t, target)
		assert.NoFileExists(t, decoy)
	})
}
