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
)

// runMainMarker, set in a child's environment, makes this test binary run the real main instead
// of the tests: the os/exec helper-process idiom, as the auth server's main package uses it.
const runMainMarker = "GOIABADA_TEST_RUN_MAIN"

// mainProcessBound is how long a child may run. The case expects an exit within a second or two;
// a child that got past the refusal it is written against could otherwise go on to serve, and the
// case would wait on it for as long as the tier allows.
const mainProcessBound = 30 * time.Second

// TestMain hands a marked child process to main before any test flag is parsed, so the child's
// command line is exactly the one the case gave it, parsed by config.Load on a fresh
// flag.CommandLine. Every other run is the test run.
func TestMain(m *testing.M) {
	if os.Getenv(runMainMarker) == "1" {
		os.Args = append([]string{"goiabada-adminconsole"}, os.Args[1:]...)
		// main does not return: it exits with the code run answers.
		main()
	}
	os.Exit(m.Run())
}

// runMainProcess runs main in a fresh process over env and answers its exit code and stderr. The
// environment carries the session keys and the client secret, which main refuses to start
// without, so a case reaches whatever comes after them.
func runMainProcess(t *testing.T, env []string, args ...string) (int, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append([]string{
		runMainMarker + "=1",
		"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY=" + strings.Repeat("b1", 64),
		"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY=" + strings.Repeat("b2", 32),
		"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=process-test-secret",
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

// TestMain_HandsTheOverridesDirectoryToTheCatalogs is the wiring between the two halves the
// configuration matrix and core/i18n's own tests each cover alone: that main passes the directory
// config read from GOIABADA_I18N_OVERRIDES_DIR to LoadBundle. The directory holds a catalog that
// does not parse, so a main that forwards it stops with the catalog refusal (#431).
//
// The exit code alone proves nothing: a main that passed "" instead goes on and stops, 1 again, at
// the listener this harness disables. The refusal's text, which only it writes, is what fails.
func TestMain_HandsTheOverridesDirectoryToTheCatalogs(t *testing.T) {
	overrides := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(overrides, "catalogs"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(overrides, "catalogs", "active.en.toml"),
		[]byte("[section]\nother = \"x\"\n"), 0o644))

	code, stderr := runMainProcess(t, []string{
		"GOIABADA_I18N_OVERRIDES_DIR=" + overrides,
		// Neither listener, so a child that got past the catalogs stops rather than serves.
		"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=0",
	})

	require.Equal(t, 1, code, "stderr: %s", stderr)
	assert.Contains(t, stderr, "unable to load the i18n message catalogs")
	assert.Contains(t, stderr, "active.en.toml")
}

// TestMain_RefusesAMalformedVariable is the wiring between config.Load's refusal and the process:
// that main stops on it with exit 2, the code a bad flag gets, and writes it to stderr as the one
// line an operator reads, before the log handler is installed (#434). Two variables are malformed,
// so a main that printed only the first would fail.
//
// The exit code is what a main ignoring the error cannot fake here: it would go on and stop, 1, at
// the listener this harness disables. stderr holding the refusal line and nothing else is what
// shows the refusal came before anything was logged.
func TestMain_RefusesAMalformedVariable(t *testing.T) {
	code, stderr := runMainProcess(t, []string{
		"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS=94x4",
		"GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS=yes",
		// Neither listener, so a child that got past the refusal stops rather than serves.
		"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=0",
	})

	require.Equal(t, 2, code, "stderr: %s", stderr)
	assert.Equal(t, `malformed configuration: GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS is "94x4", not an integer; `+
		`GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS is "yes", not a boolean (true or false)`+"\n", stderr)
}

// TestMain_RefusesAMalformedPreviousSessionKey is the wiring between the session-key rule
// core/sessionstore's table covers and the process: that main calls SessionKeys and stops on its
// refusal (#434). The previous authentication key is 32 bytes where 64 are required.
//
// The exit code alone proves nothing: a main that dropped the error or never called SessionKeys
// goes on and stops, 1 again, at the listener this harness disables. The refusal's text, which
// only the rule writes, is what fails.
func TestMain_RefusesAMalformedPreviousSessionKey(t *testing.T) {
	code, stderr := runMainProcess(t, []string{
		"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY_PREVIOUS=" + strings.Repeat("c1", 32),
		"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS=" + strings.Repeat("c2", 32),
		// Neither listener, so a child that got past the refusal stops rather than serves.
		"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=0",
	})

	require.Equal(t, 1, code, "stderr: %s", stderr)
	assert.Contains(t, stderr, "GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY_PREVIOUS must be 64 bytes (128 hex chars), got 32 bytes")
}

// TestMain_RefusesATimeZoneItCannotLoad is decisions 10 and 14 of #331 at the process: a TZ naming
// no zone, the name Local, which the time package accepts but which names no zone, and an absolute
// path to a zone file that does not load, with or without POSIX's leading colon, each stop main
// with one line on stderr and exit 2, the channel and code of a malformed variable, before
// anything is logged. Each used to give UTC in silence.
//
// The exit code is what a main ignoring the check cannot fake: it would go on and stop, 1, at the
// listener this harness disables. stderr holding the refusal line and nothing else is what shows
// the refusal came before anything was logged.
func TestMain_RefusesATimeZoneItCannotLoad(t *testing.T) {
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
		t.Run(tc.name, func(t *testing.T) {
			code, stderr := runMainProcess(t, []string{
				"TZ=" + tc.tz,
				// Neither listener, so a child that got past the refusal stops rather than serves.
				"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=0",
			})

			require.Equal(t, 2, code, "stderr: %s", stderr)
			assert.Equal(t, tc.want, stderr)
		})
	}
}

// TestMain_HonorsATimeZoneFromTheFirstRecord: a zone name, the same name behind POSIX's leading
// colon, and an absolute path to a zone file all pass the check, and the first record the child
// writes already carries that zone's offset. Asia/Kolkata has had no daylight saving since 1945,
// so +05:30 holds whatever the date.
//
// The child stops, 1, at the listener this harness disables, which is what shows it got past the
// check. On this host the zone database is present, so these cases hold with the re-resolution
// reverted too; what they pin is that every honored form stays honored.
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

			code, stderr := runMainProcess(t, []string{
				"TZ=" + tz,
				"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=0",
			})

			require.Equal(t, 1, code, "stderr: %s", stderr)
			first, _, _ := strings.Cut(stderr, "\n")
			assert.Contains(t, first, "+05:30 level=INFO msg=\"admin console started\"")
		})
	}
}

// TestMain_LeavesAnUnsetOrEmptyTimeZoneAsItWas: TZ unset reads the host's /etc/localtime and TZ
// empty means UTC, as they did before #331, so neither is refused. An empty TZ is the one form
// whose result is fixed whatever the host, and its first record is in UTC.
func TestMain_LeavesAnUnsetOrEmptyTimeZoneAsItWas(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		code, stderr := runMainProcess(t, []string{"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=0"})

		require.Equal(t, 1, code, "stderr: %s", stderr)
		first, _, _ := strings.Cut(stderr, "\n")
		assert.Contains(t, first, `level=INFO msg="admin console started"`)
	})
	for _, tz := range []string{"", ":"} {
		t.Run("TZ="+tz, func(t *testing.T) {
			code, stderr := runMainProcess(t, []string{
				"TZ=" + tz,
				"GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=0",
			})

			require.Equal(t, 1, code, "stderr: %s", stderr)
			first, _, _ := strings.Cut(stderr, "\n")
			assert.Regexp(t, `^time=\S+Z level=INFO msg="admin console started"`, first)
		})
	}
}
