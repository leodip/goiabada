package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
)

// runMainMarker, set in a child's environment, makes this test binary run the real main instead
// of the tests: the os/exec helper-process idiom.
const runMainMarker = "GOIABADA_TEST_RUN_MAIN"

// TestMain hands a marked child process to main before any test flag is parsed, so the child's
// command line is exactly the one the case gave it, parsed by config.Init on a fresh
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

// runMainProcess runs main in a fresh process with args, over an environment naming decoy as the
// database, and answers its exit code and stderr.
func runMainProcess(t *testing.T, decoy string, args ...string) (int, string) {
	t.Helper()

	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = []string{
		runMainMarker + "=1",
		"GOIABADA_DB_TYPE=sqlite",
		"GOIABADA_DB_DSN=file:" + decoy,
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	err := cmd.Run()
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

	db, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{Type: "sqlite", DSN: "file:" + path}, false)
	require.NoError(t, err)
	defer func() { _ = db.DB.Close() }()

	m, err := db.NewMigrator(context.Background())
	require.NoError(t, err)
	require.NoError(t, m.Up(context.Background()))
}

// recordedVersion reads back the schema version the SQLite file at path records.
func recordedVersion(t *testing.T, path string) int {
	t.Helper()

	db, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{Type: "sqlite", DSN: "file:" + path}, false)
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
// config.Init over a real command line, and a SQLite file stepped down from the head to 44.
// These are the cases that fail if main stops dispatching on config.Args(), or stops handing
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
