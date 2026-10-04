package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
)

// TestMain_AShutdownSignalDuringStartupStopsCleanly is #390 decisions 8 and 9 at the process. A
// signal used to end a starting auth server on the spot, wherever it was: a migration file cut off
// that way is left dirty, and on MySQL and SQL Server partly applied, and the next start refuses
// until an operator repairs it. Now, wherever the signal lands, the running step finishes, nothing
// new starts, the start says so and the process exits 0 with the schema clean.
//
// The child is the real main over a fresh SQLite file it migrates and seeds, signalled with SIGTERM,
// what a container runtime sends, the moment it writes the record each case names. Each record
// marks a phase: the open, the migrations, the step after them, the seed, and the running server,
// where the existing drain answers. What every case asserts holds whichever step the signal
// actually lands in, so the cases do not depend on timing; what each phase adds is asserted when
// the records show the signal landed there.
func TestMain_AShutdownSignalDuringStartupStopsCleanly(t *testing.T) {
	for _, at := range []string{
		"opening the database",
		"migrating the database",
		"database migrated",
		"database is empty, performing initial bootstrap",
		"starting the http listener",
	} {
		t.Run("signalled at "+at, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "s.db")

			code, records := runMainSignalledAt(t, path, at)

			require.Equalf(t, 0, code, "a stop the platform asked for, carried out cleanly, exits 0\n%s", dump(records))
			messages := messagesOf(records)
			require.Containsf(t, messages, at, "the signal was sent at this record\n%s", dump(records))
			assert.Equal(t, 1, count(messages, "shutdown signal received"),
				"the signal is said once, whichever phase it reached\n%s", dump(records))
			require.NotEmpty(t, messages)
			assert.Equal(t, "auth server stopped", messages[len(messages)-1], "and the stop is the last thing said")
			assert.Less(t, indexOf(messages, at), indexOf(messages, "shutdown signal received"))
			assert.NotContains(t, messages, "unable to create the database connection", "a stop is not a failure")
			assert.NotContains(t, messages, "unable to bootstrap the database", "a stop is not a failure")

			version, dirty, versionErr := schemaVersion(t, path)
			assert.False(t, dirty, "the schema is left clean wherever the signal landed")

			if stopped := recordNamed(records, "database migration stopped"); stopped != nil {
				// The signal landed during the migrations: the running file finished, the next did
				// not start, and the record says where the schema stopped, which is where it is.
				assert.Less(t, indexOf(messages, "shutdown signal received"), indexOf(messages, "database migration stopped"),
					"the signal is said when it arrives, before the file it waits for ends")
				assert.NotContains(t, messages, "database migrated")
				assert.NotContains(t, messages, "database is empty, performing initial bootstrap", "nothing after the migrations starts")
				reached := int(stopped["reached_version"].(float64))
				if reached == 0 {
					assert.Truef(t, migrator.IsNilVersion(versionErr), "nothing was applied: %v", versionErr)
				} else {
					require.NoError(t, versionErr)
					assert.Equal(t, reached, version, "the schema is at the version the record names")
				}
				assert.Positive(t, int(stopped["remaining"].(float64)), "a stop with nothing left is no stop")
			}
			if contains(messages, "database is empty, performing initial bootstrap") {
				// The seed began, so it committed.
				assert.Contains(t, messages, "database seeded", "a seed under way when the signal arrived runs to its end")
			}
			if at == "migrating the database" {
				// The chain is dozens of files; the signal is sent as the first begins.
				assert.NotNilf(t, recordNamed(records, "database migration stopped"),
					"a signal sent as the migrations begin stops them part of the way\n%s", dump(records))
			}
		})
	}
}

// TestMain_ASignalDuringALegacyBootstrapStillSaysTheServerStopped is the same stop in the legacy
// two-step mode, whose seed ends the process rather than handing it to the server. A signal landing
// as the seed begins lets the seed commit and its bootstrap file be published, and the process
// exits 0 either way; what the stop adds is the last record, "auth server stopped", which a stopped
// start writes in every phase (#390 decision 9). The legacy exit used to come before it.
func TestMain_ASignalDuringALegacyBootstrapStillSaysTheServerStopped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.db")
	outFile := filepath.Join(dir, "bootstrap.env")
	at := "database is empty, performing initial bootstrap"

	code, records := runMainSignalledAtWith(t, path, at, []string{
		"GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE=" + outFile,
	})

	require.Equalf(t, 0, code, "the seed committed and the stop was carried out cleanly\n%s", dump(records))
	messages := messagesOf(records)
	require.Containsf(t, messages, "using legacy two-step bootstrap mode", "the case runs the legacy mode\n%s", dump(records))
	assert.Contains(t, messages, "database seeded", "a seed under way when the signal arrived runs to its end")
	assert.Truef(t, slices.ContainsFunc(messages, func(m string) bool { return strings.HasPrefix(m, "bootstrap complete") }),
		"and its file is published\n%s", dump(records))
	assert.Equal(t, 1, count(messages, "shutdown signal received"), "the signal is said once\n%s", dump(records))
	assert.Equalf(t, 1, count(messages, "auth server stopped"), "the stop is said once\n%s", dump(records))
	assert.Equalf(t, "auth server stopped", messages[len(messages)-1], "and it is the last thing said\n%s", dump(records))

	_, statErr := os.Stat(outFile)
	assert.NoError(t, statErr, "the bootstrap file holding the generated credentials is in place")
	version, dirty, versionErr := schemaVersion(t, path)
	require.NoError(t, versionErr)
	assert.False(t, dirty, "the schema is left clean")
	assert.Positive(t, version, "the database was migrated before it was seeded")
}

// singleStepEnv is the configuration that selects the single-step seed and lets the server start
// after it: the admin console's client secret and the auth server's session keys.
var singleStepEnv = []string{
	"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=" + strings.Repeat("ef", 32),
	"GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY=" + strings.Repeat("ab", 64),
	"GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY=" + strings.Repeat("cd", 32),
}

// runMainSignalledAt runs main over a fresh SQLite file at path, seeding it in single-step mode and
// listening on a free loopback port, sends SIGTERM as it writes the record at, and answers its exit
// code and every record it wrote, in order.
func runMainSignalledAt(t *testing.T, path, at string) (int, []map[string]any) {
	t.Helper()
	return runMainSignalledAtWith(t, path, at, singleStepEnv)
}

// runMainSignalledAtWith is runMainSignalledAt with mode, the variables selecting how an empty
// database is seeded, in place of the single-step ones.
func runMainSignalledAtWith(t *testing.T, path, at string, mode []string) (int, []map[string]any) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), mainProcessBound)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0])
	cmd.Env = append([]string{
		runMainMarker + "=1",
		"GOIABADA_DB_TYPE=sqlite",
		"GOIABADA_DB_DSN=file:" + path,
		"GOIABADA_AUTHSERVER_LOG_FORMAT=json",
		"GOIABADA_AES_ENCRYPTION_KEY=" + strings.Repeat("ab", 32),
		"GOIABADA_ADMIN_EMAIL=admin@example.com",
		"GOIABADA_ADMIN_PASSWORD=a-long-enough-password-for-the-seed",
		"GOIABADA_AUTHSERVER_LISTEN_HOST_HTTP=127.0.0.1",
		"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=" + strconv.Itoa(freePort(t)),
	}, mode...)
	stderr, err := cmd.StderrPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	var records []map[string]any
	signalled := false
	scanner := bufio.NewScanner(stderr)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		var record map[string]any
		if json.Unmarshal(scanner.Bytes(), &record) != nil {
			record = map[string]any{"msg": "(not a record) " + scanner.Text()}
		}
		records = append(records, record)
		if !signalled && record["msg"] == at {
			signalled = true
			require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
		}
	}

	err = cmd.Wait()
	if ctx.Err() != nil {
		t.Fatalf("main did not exit within %s\n%s", mainProcessBound, dump(records))
	}
	require.Truef(t, signalled, "main never wrote %q\n%s", at, dump(records))

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, records
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), records
	default:
		t.Fatalf("running main: %v\n%s", err, dump(records))
		return -1, nil
	}
}

// freePort answers a loopback port nothing is listening on.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// schemaVersion reads the version the SQLite file at path records, and whether it is dirty.
func schemaVersion(t *testing.T, path string) (int, bool, error) {
	t.Helper()
	db, err := sqlitedb.New(context.Background(), "file:"+path, false)
	require.NoError(t, err)
	defer func() { _ = db.DB.Close() }()
	m, err := db.NewMigrator(context.Background(), nil)
	require.NoError(t, err)
	return m.Version(context.Background())
}

func messagesOf(records []map[string]any) []string {
	messages := make([]string, 0, len(records))
	for _, r := range records {
		msg, _ := r["msg"].(string)
		messages = append(messages, msg)
	}
	return messages
}

func recordNamed(records []map[string]any, message string) map[string]any {
	for _, r := range records {
		if r["msg"] == message {
			return r
		}
	}
	return nil
}

func indexOf(messages []string, message string) int {
	for i, m := range messages {
		if m == message {
			return i
		}
	}
	return -1
}

func contains(messages []string, message string) bool { return indexOf(messages, message) >= 0 }

func count(messages []string, message string) int {
	n := 0
	for _, m := range messages {
		if m == message {
			n++
		}
	}
	return n
}

// dump renders the records for a failure message.
func dump(records []map[string]any) string {
	var b strings.Builder
	for _, r := range records {
		line, _ := json.Marshal(r)
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String()
}
