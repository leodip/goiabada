package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/datafactory"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/recovery"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/core/builtin"
)

// recoverAuditRecorder is runRecover's audit logger in these tests: the events and payloads are
// the assertion, so they are captured rather than written to the database the way the running
// command does through audit.NewLogger.
type recoverAuditRecorder struct {
	events  []string
	details []map[string]interface{}
}

func (r *recoverAuditRecorder) Log(_ context.Context, auditEvent string, details map[string]interface{}) {
	r.events = append(r.events, auditEvent)
	r.details = append(r.details, details)
}

// newRecoverDatabase gives each test its own SQLite file database at the head of the real
// migration set, holding the rows recovery touches: the settings row, the auth server resource
// with its manage permission, and one user. Those are the parts of the seed the command reads,
// written through the data tier the same way the seed writes them, so the command is observed
// against what it will run against in production (#498).
func newRecoverDatabase(t *testing.T) (*sqlitedb.Database, *record.Permission) {
	t.Helper()
	return newRecoverDatabaseAt(t, filepath.Join(t.TempDir(), "recover_test.db"))
}

// newRecoverDatabaseAt is newRecoverDatabase at the path the test names, for a test that hands the
// path to the command rather than the handle.
func newRecoverDatabaseAt(t *testing.T, path string) (*sqlitedb.Database, *record.Permission) {
	t.Helper()

	db, err := sqlitedb.New(context.Background(), "file:"+path, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.DB.Close() })

	m, err := db.NewMigrator(context.Background(), nil)
	require.NoError(t, err)
	require.NoError(t, m.Up(context.Background()))

	ctx := context.Background()
	settings := &record.Settings{
		AppName:                "recover test",
		Issuer:                 "https://localhost:8080",
		PasswordPolicy:         record.PasswordPolicyLow,
		AESEncryptionKeyLegacy: []byte{},
	}
	resource := &record.Resource{
		ResourceIdentifier: builtin.AuthServerResourceIdentifier,
		Description:        "The authorization server",
	}
	manage := &record.Permission{
		PermissionIdentifier: builtin.ManagePermissionIdentifier,
		Description:          "Manage the authorization server via the admin console",
	}
	user := &record.User{
		Subject:      "recover-subject",
		Username:     "recover",
		Email:        "admin@example.com",
		Enabled:      true,
		PasswordHash: "not-a-bcrypt-hash",
	}
	require.NoError(t, db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		if err := db.CreateInitialSettings(ctx, tx, settings); err != nil {
			return err
		}
		if err := db.CreateResource(ctx, tx, resource); err != nil {
			return err
		}
		manage.ResourceId = resource.Id
		if err := db.CreatePermission(ctx, tx, manage); err != nil {
			return err
		}
		return db.CreateUser(ctx, tx, user)
	}))
	return db, manage
}

// enrollOTP gives the seeded user an authenticator, the state --remove-otp clears.
func enrollOTP(t *testing.T, db data.Database) {
	t.Helper()
	ctx := context.Background()
	user, err := db.GetUserByEmail(ctx, nil, "admin@example.com")
	require.NoError(t, err)
	user.OTPEnabled = true
	user.OTPSecretEncrypted = []byte("the-encrypted-seed")
	require.NoError(t, db.UpdateUser(ctx, nil, user))
}

// runRecoverOn runs one invocation against the database and its migrator, and answers the exit
// code with what the command printed on each stream.
func runRecoverOn(t *testing.T, db *sqlitedb.Database, audit *recoverAuditRecorder, inv recoverInvocation) (int, string, string) {
	t.Helper()
	m, err := db.NewMigrator(context.Background(), nil)
	require.NoError(t, err)
	var out, errOut bytes.Buffer
	code := runRecover(context.Background(), db, m, audit, inv, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestParseRecoverArgs(t *testing.T) {
	t.Run("reads the command's flags", func(t *testing.T) {
		inv, err := parseRecoverArgs([]string{
			"--email", "admin@example.com", "--grant-manage", "--remove-otp",
			"--password=alongenoughpassword",
		}, config.DatabaseConfig{Type: "sqlite"})
		require.NoError(t, err)
		assert.Equal(t, "admin@example.com", inv.email)
		assert.Equal(t, "alongenoughpassword", inv.password)
		assert.False(t, inv.passwordStdin)
		assert.True(t, inv.grantManage)
		assert.True(t, inv.removeOTP)
		assert.False(t, inv.help)
		assert.Equal(t, "sqlite", inv.database.Type)
	})

	t.Run("reads --password-stdin as an action", func(t *testing.T) {
		inv, err := parseRecoverArgs([]string{"--email", "admin@example.com", "--password-stdin"},
			config.DatabaseConfig{Type: "sqlite"})
		require.NoError(t, err)
		assert.True(t, inv.passwordStdin)
		assert.Empty(t, inv.password, "the password is read from stdin, not from the arguments")
	})

	// Each action is enough alone, so the no-action refusal never refuses one of them: given only
	// --remove-otp, the lost-authenticator recovery, or only --password, as a script types it
	// (#498 review round 10 F1).
	for _, tc := range []struct {
		name string
		args []string
		want recoverInvocation
	}{
		{"--grant-manage", []string{"--grant-manage"}, recoverInvocation{grantManage: true}},
		{"--remove-otp", []string{"--remove-otp"}, recoverInvocation{removeOTP: true}},
		{"--password <value>", []string{"--password", "alongenoughpassword"},
			recoverInvocation{password: "alongenoughpassword"}},
		{"--password=<value>", []string{"--password=alongenoughpassword"},
			recoverInvocation{password: "alongenoughpassword"}},
		{"--password-stdin", []string{"--password-stdin"}, recoverInvocation{passwordStdin: true}},
	} {
		t.Run("an action alone is enough: "+tc.name, func(t *testing.T) {
			base := config.DatabaseConfig{Type: "sqlite"}
			inv, err := parseRecoverArgs(append([]string{"--email", "admin@example.com"}, tc.args...), base)
			require.NoError(t, err)
			tc.want.email = "admin@example.com"
			tc.want.database = base
			assert.Equal(t, tc.want, inv, "only that action's field is set")
		})
	}

	t.Run("an undefined flag names what recover accepts", func(t *testing.T) {
		_, err := parseRecoverArgs([]string{"--email", "a@example.com", "--grant"},
			config.DatabaseConfig{Type: "sqlite"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--grant is not a flag recover accepts")
		assert.Contains(t, err.Error(), "--email, --password, --password-stdin, --grant-manage and --remove-otp")
	})

	t.Run("a positional argument is refused", func(t *testing.T) {
		_, err := parseRecoverArgs([]string{"admin@example.com"}, config.DatabaseConfig{Type: "sqlite"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not a flag recover takes as a positional argument")
	})

	t.Run("the email is required", func(t *testing.T) {
		_, err := parseRecoverArgs([]string{"--remove-otp"}, config.DatabaseConfig{Type: "sqlite"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--email is required")
	})

	// A run with no action is refused here, before anything is opened, rather than after the
	// database was opened and the user read (#498 review F10).
	t.Run("an action is required", func(t *testing.T) {
		_, err := parseRecoverArgs([]string{"--email", "admin@example.com"}, config.DatabaseConfig{Type: "sqlite"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nothing to do")
		assert.Contains(t, err.Error(), "--grant-manage, --password-stdin, --password or --remove-otp")
	})

	// An explicit empty --password, as `--password "$PW"` with PW unset gives, is refused whatever
	// else is asked: read as "no password", the other actions committed and the forgotten password
	// stayed in place while the command reported success (#498 review F2).
	for _, others := range [][]string{
		nil,
		{"--grant-manage"},
		{"--remove-otp"},
		{"--grant-manage", "--remove-otp"},
	} {
		for _, spelling := range [][]string{{"--password="}, {"--password", ""}} {
			args := append(append([]string{"--email", "admin@example.com"}, spelling...), others...)
			t.Run("an empty password is refused: "+strings.Join(args, " "), func(t *testing.T) {
				_, err := parseRecoverArgs(args, config.DatabaseConfig{Type: "sqlite"})
				require.Error(t, err)
				assert.Contains(t, err.Error(), "--password is empty")
			})
		}
	}

	t.Run("the two password flags together are refused", func(t *testing.T) {
		_, err := parseRecoverArgs([]string{"--email", "admin@example.com", "--password-stdin",
			"--password", "alongenoughpassword"}, config.DatabaseConfig{Type: "sqlite"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--password and --password-stdin both give the new password")
	})
}

// TestParseRecoverArgs_Help: help is answered before the email or an action is required, as
// `migrate --help` is (#498 review F10).
func TestParseRecoverArgs_Help(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"-help"}, {"--h"}, {"--help"}, {"--email", "a@example.com", "--help"}} {
		inv, err := parseRecoverArgs(args, migrateArgsBase())
		require.NoError(t, err, "%#v", args)
		assert.True(t, inv.help, "%#v", args)
	}
}

func TestRecoverCommand_HelpPrintsTheUsageAndOpensNothing(t *testing.T) {
	a := filepath.Join(t.TempDir(), "a.db")

	var stdout, stderr bytes.Buffer
	inv, ok := readRecoverCommand([]string{"--help", "--password-stdin"}, sqliteBase(a),
		strings.NewReader(""), &stderr)
	require.True(t, ok, "stderr: %s", stderr.String())
	code := runRecoverCommand(inv, datafactory.OpenDatabase, &stdout, &stderr)

	require.Equal(t, migrateExitOK, code)
	assert.Equal(t, recoverUsage+"\n", stdout.String())
	assert.Empty(t, stderr.String(), "help reads no password from stdin, and refuses nothing")
	assert.NoFileExists(t, a)
}

// TestRecoverCommand_RefusesAUsageMistakeBeforeOpeningAnything: a run with no action, or with an
// empty password, is refused with the usage and exit 2, and the database named is never created
// (#498 review F2 and F10).
func TestRecoverCommand_RefusesAUsageMistakeBeforeOpeningAnything(t *testing.T) {
	for _, args := range [][]string{
		{"--email", "admin@example.com"},
		{"--email", "admin@example.com", "--password=", "--grant-manage"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			a := filepath.Join(t.TempDir(), "a.db")

			var stderr bytes.Buffer
			_, ok := readRecoverCommand(args, sqliteBase(a), strings.NewReader(""), &stderr)

			require.False(t, ok)
			assert.Contains(t, stderr.String(), "\n\n"+recoverUsage+"\n")
			assert.NoFileExists(t, a)
		})
	}
}

// TestReadRecoverCommand_ReadsThePasswordFromStdin: --password-stdin takes the first line of
// stdin, without its line ending and with every other character kept, and refuses an empty line
// or none at all, as it refuses an empty --password (#498 review F4).
func TestReadRecoverCommand_ReadsThePasswordFromStdin(t *testing.T) {
	args := []string{"--email", "admin@example.com", "--password-stdin"}

	for _, tc := range []struct{ name, stdin, want string }{
		{"a line", "Aa$$1 23456!`x`\\\nthe next line is not read\n", "Aa$$1 23456!`x`\\"},
		{"a line ended by CRLF", "alongenoughpassword\r\n", "alongenoughpassword"},
		{"no line ending", "alongenoughpassword", "alongenoughpassword"},
		// Sign-in compares the password untrimmed, so a trimmed one could never be signed in with.
		{"spaces and tabs at either end", " \tLong Passw0rd!\t \n", " \tLong Passw0rd!\t "},
		{"spaces and tabs at either end, CRLF", " \tLong Passw0rd!\t \r\n", " \tLong Passw0rd!\t "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			inv, ok := readRecoverCommand(args, config.DatabaseConfig{Type: "sqlite"},
				strings.NewReader(tc.stdin), &stderr)
			require.True(t, ok, "stderr: %s", stderr.String())
			assert.Equal(t, tc.want, inv.password)
		})
	}

	for _, tc := range []struct{ name, stdin, want string }{
		{"an empty line", "\nalongenoughpassword\n", "--password-stdin read an empty line"},
		{"nothing", "", "--password-stdin read nothing"},
	} {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			a := filepath.Join(t.TempDir(), "a.db")
			var stderr bytes.Buffer
			_, ok := readRecoverCommand(args, sqliteBase(a), strings.NewReader(tc.stdin), &stderr)
			require.False(t, ok)
			assert.Contains(t, stderr.String(), tc.want)
			assert.NoFileExists(t, a)
		})
	}
}

// TestRecoverCommand_AFlagAfterRecoverChoosesTheDatabaseOpened: the base names file A, the flag
// after `recover` names file B, and B is the database the command recovers the user in. A is never
// created, which is how "not opened" is observed: SQLite creates the file on the first connection.
func TestRecoverCommand_AFlagAfterRecoverChoosesTheDatabaseOpened(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.db"), filepath.Join(dir, "b.db")
	db, manage := newRecoverDatabaseAt(t, b)

	var stdout, stderr bytes.Buffer
	inv, ok := readRecoverCommand([]string{"--email", "admin@example.com", "--grant-manage",
		"--db-dsn=file:" + b}, sqliteBase(a), strings.NewReader(""), &stderr)
	require.True(t, ok, "stderr: %s", stderr.String())
	code := runRecoverCommand(inv, datafactory.OpenDatabase, &stdout, &stderr)

	require.Equal(t, migrateExitOK, code, "stderr: %s", stderr.String())
	assert.NoFileExists(t, a)
	user, err := db.GetUserByEmail(context.Background(), nil, "admin@example.com")
	require.NoError(t, err)
	grants, err := db.GetUserPermissionsByUserId(context.Background(), nil, user.Id)
	require.NoError(t, err)
	require.Len(t, grants, 1, "the grant was written in the database the flag after recover named")
	assert.Equal(t, manage.Id, grants[0].PermissionId)
}

// TestRecoverCommand_NeverCreatesTheDatabase: the opener is handed a configuration that does not
// create the database, whether the base asks to, as GOIABADA_DB_CREATE's default does, or a
// --db-create after recover does, so a mistyped name is refused as missing rather than created
// empty on the server (#498 review round 10 F2). SQLite creates a missing file whatever this says,
// which is why a server engine is named here.
func TestRecoverCommand_NeverCreatesTheDatabase(t *testing.T) {
	for _, tc := range []struct {
		name       string
		baseCreate bool
		args       []string
	}{
		{"the base creates", true, nil},
		{"the base creates and --db-create=true follows recover", true, []string{"--db-create=true"}},
		{"--db-create follows recover", false, []string{"--db-create"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := config.DatabaseConfig{Type: "postgres", Host: "localhost", Port: 5432,
				Name: "goiabada_typo", Create: tc.baseCreate}
			args := append([]string{"--email", "admin@example.com", "--grant-manage"}, tc.args...)

			var stdout, stderr bytes.Buffer
			inv, ok := readRecoverCommand(args, base, strings.NewReader(""), &stderr)
			require.True(t, ok, "stderr: %s", stderr.String())
			require.True(t, inv.database.Create, "the invocation read asks to create the database")

			var opened []config.DatabaseConfig
			open := func(_ context.Context, c *config.DatabaseConfig, _ bool) (datafactory.Migratable, error) {
				opened = append(opened, *c)
				return nil, errors.New(`database "goiabada_typo" does not exist`)
			}
			code := runRecoverCommand(inv, open, &stdout, &stderr)

			require.Equal(t, migrateExitError, code)
			require.Len(t, opened, 1)
			assert.False(t, opened[0].Create, "the recovery asked the opener to create the database")
			assert.Equal(t, "goiabada_typo", opened[0].Name)
			assert.Contains(t, stderr.String(), `unable to open the database: database "goiabada_typo" does not exist`)
			assert.Empty(t, stdout.String())
		})
	}
}

// TestRecoverUsage_NamesEveryDatabaseFlag: every flag config.RegisterDatabaseFlags registers can
// follow recover, so the usage, the only place they are spelled out, names each one, as migrate's
// does.
func TestRecoverUsage_NamesEveryDatabaseFlag(t *testing.T) {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	config.RegisterDatabaseFlags(fs, &config.DatabaseConfig{})
	var names []string
	fs.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	require.NotEmpty(t, names)
	for _, name := range names {
		named := regexp.MustCompile(`--` + regexp.QuoteMeta(name) + `([^-a-z]|$)`)
		assert.Truef(t, named.MatchString(recoverUsage), "the recover usage does not name --%s", name)
	}
}

func TestRecover_RefusesAnUnknownUser(t *testing.T) {
	db, _ := newRecoverDatabase(t)
	recorder := &recoverAuditRecorder{}

	code, _, stderr := runRecoverOn(t, db, recorder, recoverInvocation{
		email: "nobody@example.com", removeOTP: true,
	})

	assert.Equal(t, migrateExitError, code)
	assert.Contains(t, stderr, "refusing to recover: no user holds the address nobody@example.com")
	assert.Empty(t, recorder.events, "a refusal writes no audit event")
}

func TestRecover_RefusesADisabledUser(t *testing.T) {
	db, _ := newRecoverDatabase(t)
	recorder := &recoverAuditRecorder{}
	disabled := &record.User{
		Subject:      "disabled-subject",
		Username:     "disabled",
		Email:        "disabled@example.com",
		Enabled:      false,
		PasswordHash: "not-a-bcrypt-hash",
	}
	require.NoError(t, db.CreateUser(context.Background(), nil, disabled))

	code, _, stderr := runRecoverOn(t, db, recorder, recoverInvocation{
		email: "disabled@example.com", removeOTP: true,
	})

	assert.Equal(t, migrateExitError, code)
	assert.Contains(t, stderr, "is disabled; enable the user first")
	assert.Empty(t, recorder.events, "a refusal writes no audit event")
}

// TestRecover_FindsTheUserByATrimmedLowercasedAddress: the address is looked up as every write
// path stores one, so one typed with capitals or padding names the stored user.
func TestRecover_FindsTheUserByATrimmedLowercasedAddress(t *testing.T) {
	db, _ := newRecoverDatabase(t)
	recorder := &recoverAuditRecorder{}

	code, stdout, stderr := runRecoverOn(t, db, recorder, recoverInvocation{
		email: "  Admin@Example.COM \t", grantManage: true,
	})

	require.Equal(t, migrateExitOK, code, stderr)
	assert.Contains(t, stdout, "recovered admin@example.com")
}

// TestRecover_HoldsThePasswordToTheStoredPolicy: the policy is the one the settings row stores,
// not a default. "abcdefghij" passes the low policy's six characters and fails the high policy's
// mixed classes, so only the stored policy tells its two cases apart (#498 round 3 F2). A password
// of whitespace alone is refused before the policy, even the none policy, which would allow it:
// sign-in refuses it as blank, so stored it could never be signed in with. It is refused from
// --password and from --password-stdin alike, while spaces around a real password are kept.
func TestRecover_HoldsThePasswordToTheStoredPolicy(t *testing.T) {
	const policyRefusal = "the password is refused by the stored password policy"
	const blankRefusal = "the password is blank"
	for _, tc := range []struct {
		name     string
		policy   record.PasswordPolicy
		password string
		stdin    string // when set, the password is read from it through --password-stdin
		accepted bool
		refusal  string
	}{
		{"a password every policy refuses", record.PasswordPolicyLow, "short", "", false, policyRefusal},
		{"the stored high policy refuses what the low one allows", record.PasswordPolicyHigh, "abcdefghij", "", false, policyRefusal},
		{"the stored low policy allows it", record.PasswordPolicyLow, "abcdefghij", "", true, ""},
		{"a space alone, under the none policy", record.PasswordPolicyNone, " ", "", false, blankRefusal},
		{"spaces and tabs alone from stdin, under the none policy", record.PasswordPolicyNone, "", " \t \n", false, blankRefusal},
		{"spaces around a real password from stdin", record.PasswordPolicyLow, " \tabcdefghij\t ", " \tabcdefghij\t \n", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := newRecoverDatabase(t)
			ctx := context.Background()
			settings, err := db.GetSettingsById(ctx, nil, 1)
			require.NoError(t, err)
			settings.PasswordPolicy = tc.policy
			require.NoError(t, db.UpdateSettings(ctx, nil, settings))
			recorder := &recoverAuditRecorder{}

			inv := recoverInvocation{email: "admin@example.com", password: tc.password}
			if tc.stdin != "" {
				var readErr bytes.Buffer
				var ok bool
				inv, ok = readRecoverCommand([]string{"--email", "admin@example.com", "--password-stdin"},
					config.DatabaseConfig{Type: "sqlite"}, strings.NewReader(tc.stdin), &readErr)
				require.True(t, ok, "stderr: %s", readErr.String())
			}
			code, _, stderr := runRecoverOn(t, db, recorder, inv)

			after, err := db.GetUserByEmail(ctx, nil, "admin@example.com")
			require.NoError(t, err)
			if tc.accepted {
				assert.Equal(t, migrateExitOK, code, stderr)
				assert.True(t, passwordhash.Verify(after.PasswordHash, tc.password), "the new password verifies")
				assert.Equal(t, int64(1), after.AuthStateGeneration)
				assert.Equal(t, []string{audit.EventUpdatedUserAuthentication, audit.EventRevokedUserAuthState},
					recorder.events)
				return
			}
			assert.Equal(t, migrateExitError, code)
			assert.Contains(t, stderr, tc.refusal)
			assert.Equal(t, "not-a-bcrypt-hash", after.PasswordHash, "the password is as it was")
			assert.Equal(t, int64(0), after.AuthStateGeneration, "the generation did not move")
			assert.Empty(t, recorder.events, "a refusal writes no audit event")
		})
	}
}

// TestRecover_RefusesASchemaThisBinaryDoesNotCarry: the server refuses to start on a database a
// newer release migrated or a migration left dirty, and the recovery, which writes credentials and
// a permission through this binary's data tier, refuses both too, writing nothing (#498 review F9).
// It refuses an older schema as well, rather than migrate it. Each refusal names the step that gets
// past it, none of them a command that refuses the same schema (#498 round 2 F4).
func TestRecover_RefusesASchemaThisBinaryDoesNotCarry(t *testing.T) {
	for _, tc := range []struct {
		name  string
		place func(t *testing.T, sqlDB *sql.DB, head int)
		want  string
	}{
		{"a newer schema", func(t *testing.T, sqlDB *sql.DB, head int) {
			_, err := sqlDB.Exec("UPDATE schema_migrations SET version = ?", head+1)
			require.NoError(t, err)
		}, "a newer release migrated it. Run the recover command of that release"},
		{"a dirty schema", func(t *testing.T, sqlDB *sql.DB, _ int) {
			_, err := sqlDB.Exec("UPDATE schema_migrations SET dirty = 1")
			require.NoError(t, err)
		}, "DIRTY: a migration did not finish. Repair the schema by hand as " +
			"https://goiabada.dev/troubleshooting/waiting-for-the-migration-lock-or-marked-dirty/ " +
			"describes, then run the recovery again"},
		{"an older schema", func(t *testing.T, sqlDB *sql.DB, head int) {
			_, err := sqlDB.Exec("UPDATE schema_migrations SET version = ?", head-1)
			require.NoError(t, err)
		}, "it is behind this release. Run `goiabada-authserver migrate to %d`, or start this " +
			"release's auth server once, then run the recovery again"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := newRecoverDatabase(t)
			enrollOTP(t, db)
			m, err := db.NewMigrator(context.Background(), nil)
			require.NoError(t, err)
			tc.place(t, db.DB, m.Head())
			recorder := &recoverAuditRecorder{}

			code, _, stderr := runRecoverOn(t, db, recorder, recoverInvocation{
				email: "admin@example.com", grantManage: true, removeOTP: true,
			})

			assert.Equal(t, migrateExitError, code)
			assert.Contains(t, stderr, "refusing to recover: the database records schema version")
			want := tc.want
			if strings.Contains(want, "%d") {
				want = fmt.Sprintf(want, m.Head())
			}
			assert.Contains(t, stderr, want)
			assert.Empty(t, recorder.events)
			user, err := db.GetUserByEmail(context.Background(), nil, "admin@example.com")
			require.NoError(t, err)
			assert.True(t, user.OTPEnabled, "nothing was removed")
			assert.Zero(t, user.AuthStateGeneration, "the generation did not move")
			grants, err := db.GetUserPermissionsByUserId(context.Background(), nil, user.Id)
			require.NoError(t, err)
			assert.Empty(t, grants, "nothing was granted")
		})
	}

	t.Run("a database never migrated", func(t *testing.T) {
		db, err := sqlitedb.New(context.Background(), "file:"+filepath.Join(t.TempDir(), "empty.db"), false)
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.DB.Close() })

		code, _, stderr := runRecoverOn(t, db, &recoverAuditRecorder{}, recoverInvocation{
			email: "admin@example.com", grantManage: true,
		})

		assert.Equal(t, migrateExitError, code)
		assert.Contains(t, stderr, "refusing to recover: the database records no schema version")
	})
}

func TestRecover_AppliesEachAskedActionInOneRevocation(t *testing.T) {
	db, manage := newRecoverDatabase(t)
	recorder := &recoverAuditRecorder{}
	ctx := context.Background()
	enrollOTP(t, db)

	code, stdout, stderr := runRecoverOn(t, db, recorder, recoverInvocation{
		email:       "admin@example.com",
		password:    "alongenoughpassword",
		grantManage: true,
		removeOTP:   true,
	})

	assert.Equal(t, migrateExitOK, code, stderr)
	assert.Contains(t, stdout, "recovered admin@example.com")
	assert.Contains(t, stdout, "password set")
	assert.Contains(t, stdout, "otp authenticator removed")
	assert.Contains(t, stdout, "granted")
	assert.Contains(t, stdout, "authentication generation 0 to 1")

	after, err := db.GetUserByEmail(ctx, nil, "admin@example.com")
	require.NoError(t, err)

	// The password was set: the new one verifies and the stored one no longer does.
	assert.True(t, passwordhash.Verify(after.PasswordHash, "alongenoughpassword"),
		"the new password verifies against the stored hash")
	assert.False(t, passwordhash.Verify(after.PasswordHash, "not-a-bcrypt-hash"),
		"the password the user had before the recovery no longer verifies")

	// The authenticator is gone, and the generation moved.
	assert.False(t, after.OTPEnabled, "the OTP authenticator was removed")
	assert.Equal(t, int64(1), after.AuthStateGeneration)

	// The permission is granted.
	grants, err := db.GetUserPermissionsByUserId(ctx, nil, after.Id)
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, manage.Id, grants[0].PermissionId)

	// The audit trail: one record per thing done, in the Admin API's order, each naming the
	// command as the actor under one key (#498 review F6, F7 and F11).
	assert.Equal(t, []string{
		audit.EventUpdatedUserAuthentication,
		audit.EventDisabledOTP,
		audit.EventAddedUserPermission,
		audit.EventAdministrativePermissionChanged,
		audit.EventRevokedUserAuthState,
	}, recorder.events)
	assert.Equal(t, map[string]interface{}{"user_id": after.Id, "command": recovery.Actor}, recorder.details[0])
	assert.Equal(t, map[string]interface{}{"user_id": after.Id, "command": recovery.Actor}, recorder.details[1])
	assert.Equal(t, map[string]interface{}{
		"user_id": after.Id, "permission_id": manage.Id, "command": recovery.Actor,
	}, recorder.details[2])
	assert.Equal(t, map[string]interface{}{
		"change":                 "granted",
		"target_kind":            "user",
		"target_id":              after.Id,
		"permission_identifiers": []string{"authserver:manage"},
		"command":                recovery.Actor,
	}, recorder.details[3])
	revoked := recorder.details[4]
	assert.Equal(t, revocation.ReasonRecoveryCommand, revoked["reason"])
	assert.Equal(t, recovery.Actor, revoked["command"])
	assert.Empty(t, revoked["logged_in_user"], "no token made the recovery")
	assert.Contains(t, revoked, "logged_in_user", "the key is present, empty, as at the sign-in sites")
	assert.Equal(t, after.Id, revoked["user_id"])
	assert.Equal(t, int64(0), revoked["old_generation"])
	assert.Equal(t, int64(1), revoked["new_generation"])
}

// TestRecover_ARemovalWithNothingEnrolledRecordsNoAuthenticationChange: --remove-otp on a user
// with no authenticator removes nothing, says so, and records neither a password set nor an
// authenticator removed, only the revocation every recovery makes (#498 review F7).
func TestRecover_ARemovalWithNothingEnrolledRecordsNoAuthenticationChange(t *testing.T) {
	db, _ := newRecoverDatabase(t)
	recorder := &recoverAuditRecorder{}

	code, stdout, stderr := runRecoverOn(t, db, recorder, recoverInvocation{
		email: "admin@example.com", removeOTP: true,
	})

	require.Equal(t, migrateExitOK, code, stderr)
	assert.Contains(t, stdout, "no otp authenticator was enrolled, so nothing was removed")
	assert.NotContains(t, stdout, "password set")
	assert.Equal(t, []string{audit.EventRevokedUserAuthState}, recorder.events)
}

// TestRecover_ARemovalAloneRecordsTheAuthenticatorRemoved: a real removal with no password asked
// is recorded as disabled_otp, the event the Admin API and the account API write for it, and not
// as a password set (#498 review F7).
func TestRecover_ARemovalAloneRecordsTheAuthenticatorRemoved(t *testing.T) {
	db, _ := newRecoverDatabase(t)
	recorder := &recoverAuditRecorder{}
	enrollOTP(t, db)

	code, stdout, stderr := runRecoverOn(t, db, recorder, recoverInvocation{
		email: "admin@example.com", removeOTP: true,
	})

	require.Equal(t, migrateExitOK, code, stderr)
	assert.Contains(t, stdout, "otp authenticator removed")
	assert.Equal(t, []string{audit.EventDisabledOTP, audit.EventRevokedUserAuthState}, recorder.events)
	user, err := db.GetUserByEmail(context.Background(), nil, "admin@example.com")
	require.NoError(t, err)
	assert.False(t, user.OTPEnabled)
	assert.Equal(t, "not-a-bcrypt-hash", user.PasswordHash, "the password is untouched")
}

// TestRecover_AnotherActionLeavesTheAuthenticatorAlone: an authenticator is removed only when
// --remove-otp asks, however much else the recovery does.
func TestRecover_AnotherActionLeavesTheAuthenticatorAlone(t *testing.T) {
	db, _ := newRecoverDatabase(t)
	enrollOTP(t, db)

	code, stdout, stderr := runRecoverOn(t, db, &recoverAuditRecorder{}, recoverInvocation{
		email: "admin@example.com", password: "alongenoughpassword", grantManage: true,
	})

	require.Equal(t, migrateExitOK, code, stderr)
	assert.NotContains(t, stdout, "otp")
	user, err := db.GetUserByEmail(context.Background(), nil, "admin@example.com")
	require.NoError(t, err)
	assert.True(t, user.OTPEnabled, "the authenticator is still enrolled")
	assert.Equal(t, []byte("the-encrypted-seed"), user.OTPSecretEncrypted)
}

func TestRecover_ReportsManageAlreadyHeldAndGrantsNothing(t *testing.T) {
	db, manage := newRecoverDatabase(t)
	recorder := &recoverAuditRecorder{}
	ctx := context.Background()

	inv := recoverInvocation{email: "admin@example.com", grantManage: true}
	code, _, stderr := runRecoverOn(t, db, recorder, inv)
	require.Equal(t, migrateExitOK, code, stderr)

	recorder.events = nil
	code, stdout, stderr := runRecoverOn(t, db, recorder, inv)
	assert.Equal(t, migrateExitOK, code, stderr)
	assert.Contains(t, stdout, "was already held, so nothing was granted")

	user, err := db.GetUserByEmail(ctx, nil, "admin@example.com")
	require.NoError(t, err)
	grants, err := db.GetUserPermissionsByUserId(ctx, nil, user.Id)
	require.NoError(t, err)
	assert.Len(t, grants, 1, "the second run wrote no second grant")
	assert.Equal(t, manage.Id, grants[0].PermissionId)
	assert.Equal(t, []string{audit.EventRevokedUserAuthState}, recorder.events,
		"no permission event for a grant that did not happen")
}
