package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
)

// runMainMarker, set in a child's environment, makes this test binary run the real main instead
// of the tests: the os/exec helper-process idiom.
const runMainMarker = "GOIABADA_TEST_RUN_MAIN"

// TestMain hands a marked child process to main before any test flag is parsed, so the child's
// command line is exactly the one the case gave it, parsed by config.Load on a fresh
// flag.CommandLine. Every other run is the test run.
func TestMain(m *testing.M) {
	if os.Getenv(runMainMarker) == "1" {
		os.Args = append([]string{"goiabada-authserver"}, os.Args[1:]...)
		main()
		// main returns only when the server stops, which no case asks for.
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// mainProcessBound is how long a child may run. Every case expects an exit within a second or
// two; a child that got past the refusal a case is written against could otherwise go on to serve,
// and the case would wait on it for as long as the tier allows.
const mainProcessBound = 30 * time.Second

// runMainProcess runs main in a fresh process with args, over an environment naming decoy as the
// database, and answers its exit code and stderr.
func runMainProcess(t *testing.T, decoy string, args ...string) (int, string) {
	t.Helper()
	return runMainProcessWith(t, decoy, nil, args...)
}

// runMainProcessWith is runMainProcess with env appended to the child's environment.
func runMainProcessWith(t *testing.T, decoy string, env []string, args ...string) (int, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append([]string{
		runMainMarker + "=1",
		"GOIABADA_DB_TYPE=sqlite",
		"GOIABADA_DB_DSN=file:" + decoy,
	}, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("main did not exit within %s\nstdout: %s\nstderr: %s", mainProcessBound, stdout.String(), stderr.String())
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, stderr.String()
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), stderr.String()
	default:
		t.Fatalf("running main: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
		return -1, ""
	}
}

// migratedToHead creates a SQLite file at path and migrates it to the head, closing it again so
// the child is the only process holding it.
func migratedToHead(t *testing.T, path string) {
	t.Helper()

	db, err := sqlitedb.New(context.Background(), "file:"+path, false)
	require.NoError(t, err)
	defer func() { _ = db.DB.Close() }()

	m, err := db.NewMigrator(context.Background())
	require.NoError(t, err)
	require.NoError(t, m.Up(context.Background()))
}

// recordedVersion reads back the schema version the SQLite file at path records.
func recordedVersion(t *testing.T, path string) int {
	t.Helper()

	db, err := sqlitedb.New(context.Background(), "file:"+path, false)
	require.NoError(t, err)
	defer func() { _ = db.DB.Close() }()

	m, err := db.NewMigrator(context.Background())
	require.NoError(t, err)
	version, dirty, err := m.Version(context.Background())
	require.NoError(t, err)
	require.False(t, dirty)
	return version
}

// TestMain_MigrateFindsItsFlagsWhereverTheyAre is R1 at the process: the real main, its real
// config.Load over a real command line, and a SQLite file stepped down from the head to 44.
// These are the cases that fail if main stops dispatching on the loaded Args, or stops handing
// migrate the configuration its flags were parsed into; every function below it can be right
// while that wiring is wrong.
func TestMain_MigrateFindsItsFlagsWhereverTheyAre(t *testing.T) {
	cases := []struct {
		name string
		args func(target, decoy string) []string
	}{
		{"flags before migrate", func(f, _ string) []string {
			return []string{"-db-dsn=file:" + f, "migrate", "to", "44"}
		}},
		{"flags after migrate", func(f, _ string) []string {
			return []string{"migrate", "to", "44", "-db-dsn=file:" + f}
		}},
		{"flags interleaved", func(f, _ string) []string {
			return []string{"migrate", "-db-dsn=file:" + f, "to", "44"}
		}},
		{"a flag after migrate overrides the same flag before it", func(f, d string) []string {
			return []string{"-db-dsn=file:" + d, "migrate", "-db-dsn=file:" + f, "to", "44"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target, decoy := filepath.Join(dir, "f.db"), filepath.Join(dir, "d.db")
			migratedToHead(t, target)

			code, stderr := runMainProcess(t, decoy, tc.args(target, decoy)...)

			require.Equal(t, migrateExitOK, code, "stderr: %s", stderr)
			assert.Equal(t, 44, recordedVersion(t, target))
			assert.NoFileExists(t, decoy)
		})
	}
}

// TestMain_RefusesAStrayArgumentBeforeOpeningAnything: a typo used to start the server, which
// migrated the database up. Now it prints the one refusal and exits 2, and no database named
// anywhere on the command line or in the environment is created.
func TestMain_RefusesAStrayArgumentBeforeOpeningAnything(t *testing.T) {
	dir := t.TempDir()
	flagged, decoy := filepath.Join(dir, "g.db"), filepath.Join(dir, "d.db")

	code, stderr := runMainProcess(t, decoy, "-db-dsn=file:"+flagged, "migrat", "to", "44")

	require.Equal(t, migrateExitUsage, code)
	_, _, err := dispatch([]string{"migrat"})
	require.Error(t, err)
	assert.Equal(t, err.Error()+"\n", stderr)
	assert.NoFileExists(t, flagged)
	assert.NoFileExists(t, decoy)
}

func TestMain_RefusesAServerFlagAfterMigrateBeforeOpeningAnything(t *testing.T) {
	dir := t.TempDir()
	flagged, decoy := filepath.Join(dir, "g.db"), filepath.Join(dir, "d.db")

	code, stderr := runMainProcess(t, decoy, "-db-dsn=file:"+flagged, "migrate", "to", "44", "--authserver-log-level=debug")

	require.Equal(t, migrateExitUsage, code)
	assert.Contains(t, stderr, "--authserver-log-level is not a flag migrate accepts")
	assert.NoFileExists(t, flagged)
	assert.NoFileExists(t, decoy)
}

// TestMain_RefusesAMalformedVariableBeforeOpeningAnything is decisions 6 and 10 of #434 at the
// process: a numeric or boolean variable that does not parse stops main at the load, with the
// channel and code a malformed flag has, before the log handler exists and before anything is
// opened, and it does so under `migrate` too, whose schema work never reads the listen port.
//
// Two variables are malformed, so the one line naming both is what shows the refusal came from
// the whole load. The exit code alone proves little under `migrate version`, which would also exit
// on the decoy database; the exact stderr and the decoy never being created are what fail.
func TestMain_RefusesAMalformedVariableBeforeOpeningAnything(t *testing.T) {
	const want = `malformed configuration: GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP is "90 90", not an integer; ` +
		`GOIABADA_DB_CREATE is "yes", not a boolean (true or false)` + "\n"
	env := []string{
		"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=90 90",
		"GOIABADA_DB_CREATE=yes",
		// Present, so a child that got past the load would go on to open the decoy.
		"GOIABADA_AES_ENCRYPTION_KEY=" + strings.Repeat("ab", 32),
	}

	cases := []struct {
		name string
		args []string
	}{
		{"the server", nil},
		{"migrate version", []string{"migrate", "version"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decoy := filepath.Join(t.TempDir(), "d.db")

			code, stderr := runMainProcessWith(t, decoy, env, tc.args...)

			require.Equal(t, migrateExitUsage, code, "stderr: %s", stderr)
			assert.Equal(t, want, stderr)
			assert.NoFileExists(t, decoy)
		})
	}
}

// TestMain_RefusesAMalformedTrustedProxyListBeforeOpeningAnything: an entry that is neither an IP
// nor a CIDR used to be logged and skipped, and a list of nothing but typos then meant trusting any
// single hop. Now the server refuses to start (#425).
//
// The exit code alone proves nothing here: without the check the child still exits 1, later, at
// the data-encryption key this harness never sets. The variable's name in stderr does, because
// only this refusal writes it.
func TestMain_RefusesAMalformedTrustedProxyListBeforeOpeningAnything(t *testing.T) {
	decoy := filepath.Join(t.TempDir(), "d.db")

	code, stderr := runMainProcess(t, decoy, "--authserver-trusted-proxies=not-an-ip,10.0.0.0/33")

	require.Equal(t, 1, code)
	assert.Contains(t, stderr, "the trusted proxy list is malformed, so the auth server cannot start")
	assert.Contains(t, stderr, "GOIABADA_AUTHSERVER_TRUSTED_PROXIES")
	// Unquoted: the text handler escapes the quotes the error puts around each entry.
	assert.Contains(t, stderr, "not-an-ip")
	assert.Contains(t, stderr, "10.0.0.0/33")
	assert.NoFileExists(t, decoy)
}

// TestMain_HandsTheOverridesDirectoryToTheCatalogs is the wiring between the two halves the
// configuration matrix and core/i18n's own tests each cover alone: that main passes the directory
// config read from GOIABADA_I18N_OVERRIDES_DIR to LoadBundle. The directory holds a catalog that
// does not parse, so a main that forwards it stops with the catalog refusal before opening
// anything (#431).
//
// The exit code alone proves nothing: a main that passed "" instead goes on to open the decoy
// database and then stops, 1 again, at the listener this harness disables. The refusal's text,
// which only it writes, and the decoy not existing are what fail.
func TestMain_HandsTheOverridesDirectoryToTheCatalogs(t *testing.T) {
	decoy := filepath.Join(t.TempDir(), "d.db")
	overrides := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(overrides, "catalogs"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(overrides, "catalogs", "active.en.toml"),
		[]byte("[section]\nother = \"x\"\n"), 0o644))

	code, stderr := runMainProcessWith(t, decoy, []string{
		"GOIABADA_AES_ENCRYPTION_KEY=" + strings.Repeat("ab", 32),
		"GOIABADA_I18N_OVERRIDES_DIR=" + overrides,
		// Neither listener, so a child that got past the catalogs stops rather than serves.
		"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=0",
	})

	require.Equal(t, 1, code, "stderr: %s", stderr)
	assert.Contains(t, stderr, "unable to load the i18n message catalogs")
	assert.Contains(t, stderr, "active.en.toml")
	assert.NoFileExists(t, decoy)
}

// TestMain_RefusesAMalformedPreviousSessionKeyAfterBootstrap is the wiring between the session-key
// rule core/sessionstore's table covers and the process: that main calls SessionKeys after
// bootstrap, which mints the keys on a fresh install, and stops on its refusal (#434). The child
// seeds its own database in single-step mode, so startup reaches the check, and sets the previous
// encryption key alone.
//
// The exit code alone proves nothing: a main that dropped the error or never called SessionKeys
// goes on to stop, 1 again, at the listener this harness disables. The refusal's text naming the
// missing half, which only the rule writes, and the listener refusal's absence are what fail. The
// seed's record is what shows the refusal came after bootstrap rather than before it.
func TestMain_RefusesAMalformedPreviousSessionKeyAfterBootstrap(t *testing.T) {
	decoy := filepath.Join(t.TempDir(), "d.db")

	code, stderr := runMainProcessWith(t, decoy, []string{
		"GOIABADA_AES_ENCRYPTION_KEY=" + strings.Repeat("ab", 32),
		"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=" + strings.Repeat("ef", 32),
		"GOIABADA_ADMIN_EMAIL=admin@example.com",
		"GOIABADA_ADMIN_PASSWORD=a-long-enough-password-for-the-seed",
		"GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY=" + strings.Repeat("ab", 64),
		"GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY=" + strings.Repeat("cd", 32),
		"GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY_PREVIOUS=" + strings.Repeat("34", 32),
		// Neither listener, so a child that got past the refusal stops rather than serves.
		"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=0",
	})

	require.Equal(t, 1, code, "stderr: %s", stderr)
	assert.Contains(t, stderr, "database seeded")
	assert.Contains(t, stderr, "bootstrap credentials are not configured, so the auth server cannot start")
	assert.Contains(t, stderr, "GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY_PREVIOUS is required when GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY_PREVIOUS is set: both halves of the previous pair are needed to open a session sealed under it")
	assert.NotContains(t, stderr, "no listener is enabled")
}

// TestMain_RefusesATimeZoneItCannotLoadBeforeOpeningAnything is decisions 10 and 14 of #331 at
// the process: a TZ naming no zone, the name Local, which the time package accepts but which names
// no zone, and an absolute path to a zone file that does not load, with or without POSIX's leading
// colon, each stop main with one line on stderr and exit 2, the channel and code of a malformed
// variable, before the log handler exists and before anything is opened. Each used to give UTC in
// silence.
//
// The exit code alone proves little under `migrate version`, which would also exit on the decoy
// database; the exact stderr and the decoy never being created are what fail.
func TestMain_RefusesATimeZoneItCannotLoadBeforeOpeningAnything(t *testing.T) {
	cases := []struct {
		name string
		tz   string
		want string
	}{
		{"a name that is no zone", "Mars/Olympus",
			`TZ is "Mars/Olympus", which names no time zone` + "\n"},
		{"Local", "Local",
			`TZ is "Local", which names no time zone` + "\n"},
		{"a name with the leading colon", ":Mars/Olympus",
			`TZ is ":Mars/Olympus", which names no time zone` + "\n"},
		{"an absolute path that does not exist", "/nonexistent/Asia/Kolkata",
			`TZ is "/nonexistent/Asia/Kolkata", a zone file that does not load: ` +
				`open /nonexistent/Asia/Kolkata: no such file or directory` + "\n"},
		{"an absolute path with the leading colon", ":/nonexistent/Asia/Kolkata",
			`TZ is ":/nonexistent/Asia/Kolkata", a zone file that does not load: ` +
				`open /nonexistent/Asia/Kolkata: no such file or directory` + "\n"},
	}
	for _, tc := range cases {
		for _, command := range []struct {
			name string
			args []string
		}{
			{"the server", nil},
			{"migrate version", []string{"migrate", "version"}},
		} {
			t.Run(tc.name+", "+command.name, func(t *testing.T) {
				decoy := filepath.Join(t.TempDir(), "d.db")

				code, stderr := runMainProcessWith(t, decoy, []string{
					"TZ=" + tc.tz,
					// Present, so a child that got past the check would go on to open the decoy.
					"GOIABADA_AES_ENCRYPTION_KEY=" + strings.Repeat("ab", 32),
					"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=0",
				}, command.args...)

				require.Equal(t, migrateExitUsage, code, "stderr: %s", stderr)
				assert.Equal(t, tc.want, stderr)
				assert.NoFileExists(t, decoy)
			})
		}
	}
}

// TestMain_HonorsATimeZoneFromTheFirstRecord: a zone name, the same name behind POSIX's leading
// colon, and an absolute path to a zone file all pass the check, and the first record the child
// writes already carries that zone's offset. Asia/Kolkata has had no daylight saving since 1945,
// so +05:30 holds whatever the date.
//
// The child stops, 1, at the data-encryption key this harness never sets, which is what shows it
// got past the check. On this host the zone database is present, so these cases hold with the
// re-resolution reverted too; what they pin is that every honored form stays honored.
func TestMain_HonorsATimeZoneFromTheFirstRecord(t *testing.T) {
	for _, tz := range []string{
		"Asia/Kolkata",
		":Asia/Kolkata",
		"/usr/share/zoneinfo/Asia/Kolkata",
		":/usr/share/zoneinfo/Asia/Kolkata",
	} {
		t.Run(tz, func(t *testing.T) {
			if strings.Contains(tz, "/usr/share/zoneinfo/") {
				require.FileExists(t, strings.TrimPrefix(tz, ":"), "the case reads the host's own zone file")
			}
			decoy := filepath.Join(t.TempDir(), "d.db")

			code, stderr := runMainProcessWith(t, decoy, []string{"TZ=" + tz})

			require.Equal(t, 1, code, "stderr: %s", stderr)
			assert.Contains(t, stderr, "the data encryption key is missing or malformed")
			first, _, _ := strings.Cut(stderr, "\n")
			assert.Contains(t, first, "+05:30 level=INFO msg=\"auth server started\"")
			assert.NoFileExists(t, decoy)
		})
	}
}

// TestMain_LeavesAnUnsetOrEmptyTimeZoneAsItWas: TZ unset reads the host's /etc/localtime and TZ
// empty means UTC, as they did before #331, so neither is refused. An empty TZ is the one form
// whose result is fixed whatever the host, and its first record is in UTC.
func TestMain_LeavesAnUnsetOrEmptyTimeZoneAsItWas(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		decoy := filepath.Join(t.TempDir(), "d.db")

		code, stderr := runMainProcessWith(t, decoy, nil)

		require.Equal(t, 1, code, "stderr: %s", stderr)
		assert.Contains(t, stderr, "the data encryption key is missing or malformed")
	})
	for _, tz := range []string{"", ":"} {
		t.Run("TZ="+tz, func(t *testing.T) {
			decoy := filepath.Join(t.TempDir(), "d.db")

			code, stderr := runMainProcessWith(t, decoy, []string{"TZ=" + tz})

			require.Equal(t, 1, code, "stderr: %s", stderr)
			first, _, _ := strings.Cut(stderr, "\n")
			assert.Regexp(t, `^time=\S+Z level=INFO msg="auth server started"`, first)
		})
	}
}
