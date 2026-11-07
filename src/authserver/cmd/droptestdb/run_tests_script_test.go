package main

// run-tests.sh drops goiabada_data or goiabada_integration through this command, with the
// password the stack generated, and starts the data tier with the data key it generated. A
// container created before #627 carries neither, so the script refuses first, with one line naming
// the variable and the remedy (#501). These run it, with each variable unset in turn, against
// stubs first on PATH, so no database is dropped, no test runs, no listener is killed and no file
// under /tmp is removed. The script's lock and its exit cleanup are held here the same way, with
// the lock moved into the test's own directory so that a real run beside the tests is not met.

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/sourceroot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stackVariables are the four values run-tests.sh takes from the stack's generated .env.
var stackVariables = []string{"GOIABADA_AES_ENCRYPTION_KEY", "MYSQL_ROOT_PASSWORD", "POSTGRES_PASSWORD", "MSSQL_SA_PASSWORD"}

// stubBin writes a directory of stubs: go, curl, unparam and golangci-lint, which every tier's work
// goes through, each leaving a marker in markers named after itself when it runs and failing; the
// housekeeping the script does on its way in and on exit, netstat for the listeners it kills and
// rm for the SQLite files, which does nothing but add a line to markers' cleanup file for each
// call; and mkdir for its log and lock directories and sleep, which do nothing.
func stubBin(t *testing.T, markers string) string {
	t.Helper()
	bin := t.TempDir()
	stubs := map[string]string{
		"netstat": "#!/bin/sh\necho netstat >> \"" + markers + "/cleanup\"\nexit 0\n",
		"rm":      "#!/bin/sh\necho rm >> \"" + markers + "/cleanup\"\nexit 0\n",
		"mkdir":   "#!/bin/sh\nexit 0\n",
		"sleep":   "#!/bin/sh\nexit 0\n",
	}
	for _, tool := range tierTools {
		stubs[tool] = "#!/bin/sh\ntouch \"" + markers + "/" + tool + "\"\nexit 1\n"
	}
	for name, body := range stubs {
		require.NoError(t, os.WriteFile(filepath.Join(bin, name), []byte(body), 0o600))
		require.NoError(t, os.Chmod(filepath.Join(bin, name), 0o700))
	}
	return bin
}

// tierTools are the commands a tier's work goes through, stubbed to leave a marker and fail.
var tierTools = []string{"go", "curl", "unparam", "golangci-lint"}

// toolsRun lists the tier tools that left a marker.
func toolsRun(t *testing.T, markers string) []string {
	t.Helper()
	var ran []string
	for _, tool := range tierTools {
		if _, err := os.Stat(filepath.Join(markers, tool)); err == nil {
			ran = append(ran, tool)
		}
	}
	return ran
}

// cleanupCalls is how many times each housekeeping stub ran, from markers' cleanup file.
func cleanupCalls(t *testing.T, markers string) map[string]int {
	t.Helper()
	calls := map[string]int{}
	content, err := os.ReadFile(filepath.Join(markers, "cleanup"))
	if os.IsNotExist(err) {
		return calls
	}
	require.NoError(t, err)
	for _, line := range strings.Fields(string(content)) {
		calls[line]++
	}
	return calls
}

// scriptEnv is this process's environment with the stubs first on PATH, the lock moved to lockDir,
// GITHUB_ACTIONS left out, and the stack's four variables left out unless set: each name in set is
// given a value.
func scriptEnv(bin, lockDir string, set ...string) []string {
	env := []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"TEST_STACK_LOCK_DIR=" + lockDir,
	}
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if name != "PATH" && name != "GITHUB_ACTIONS" && name != "TEST_STACK_LOCK_DIR" && !slices.Contains(stackVariables, name) {
			env = append(env, kv)
		}
	}
	for _, name := range set {
		env = append(env, name+"=set-by-the-test")
	}
	return env
}

// runScript runs run-tests.sh with args from src/authserver, under flock(1) holding heldLock when
// it is not empty, as another run would hold it, and returns the exit status and the standard
// error.
func runScript(t *testing.T, env []string, heldLock string, args ...string) (int, string) {
	t.Helper()
	cwd, err := os.Getwd()
	require.NoError(t, err)
	root, err := sourceroot.FindSourceRoot(cwd)
	require.NoError(t, err)

	command := append([]string{"bash", filepath.Join(root, "authserver", "run-tests.sh")}, args...)
	if heldLock != "" {
		command = append([]string{"flock", heldLock}, command...)
	}
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Dir = filepath.Join(root, "authserver")
	cmd.Env = env
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err = cmd.Run()

	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit, "run-tests.sh did not exit with a status")
	return exit.ExitCode(), stderr.String()
}

// TestRunTests_AMissingStackVariableIsRefusedFirst: with one of the four unset, or set empty,
// run-tests.sh exits 1 naming it and pointing at the README's remedy, before droptestdb or a test
// is run.
func TestRunTests_AMissingStackVariableIsRefusedFirst(t *testing.T) {
	for variable, db := range map[string]string{
		"GOIABADA_AES_ENCRYPTION_KEY": "sqlite",
		"MYSQL_ROOT_PASSWORD":         "mysql",
		"POSTGRES_PASSWORD":           "postgres",
		"MSSQL_SA_PASSWORD":           "mssql",
	} {
		for _, missing := range []string{"unset", "empty"} {
			t.Run(variable+"/"+missing, func(t *testing.T) {
				markers := t.TempDir()
				var others []string
				for _, other := range stackVariables {
					if other != variable {
						others = append(others, other)
					}
				}
				env := scriptEnv(stubBin(t, markers), t.TempDir(), others...)
				if missing == "empty" {
					env = append(env, variable+"=")
				}

				status, stderr := runScript(t, env, "", "--type", "data", "--db", db, "--no-build")

				assert.Equal(t, 1, status)
				assert.Contains(t, stderr, "run-tests.sh: "+variable+" is not set")
				assert.Contains(t, stderr, "src/.devcontainer/README.md")
				assert.Empty(t, toolsRun(t, markers), "a tier's command ran before the refusal")
			})
		}
	}
}

// TestRunTests_ASecondStackRunIsRefusedNamingTheFirst: while another run holds the lock, a run of
// the data or the integration tier exits 2 with the holder's record, before it builds, kills a
// listener or removes a file, and leaves the record as it found it.
func TestRunTests_ASecondStackRunIsRefusedNamingTheFirst(t *testing.T) {
	const record = "pid 4242 (--type integration --db sqlite), started 2026-11-07 10:00:00"
	for _, args := range [][]string{
		{"--type", "data", "--db", "sqlite"},
		{"--type", "integration", "--db", "sqlite"},
		{"--type", "all"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			markers := t.TempDir()
			lockDir := t.TempDir()
			lock := filepath.Join(lockDir, "lock")
			require.NoError(t, os.WriteFile(lock, []byte(record+"\n"), 0o600))

			status, stderr := runScript(t, scriptEnv(stubBin(t, markers), lockDir, stackVariables...), lock, args...)

			assert.Equal(t, 2, status)
			assert.Contains(t, stderr, "another data or integration run is using this container's test server and databases: "+record+".")
			assert.Contains(t, stderr, "the lint, module and setup tiers can run beside it with --no-build")
			assert.Empty(t, toolsRun(t, markers), "a tier's command ran after the refusal")
			assert.Empty(t, cleanupCalls(t, markers), "the refused run freed the first run's ports or files")
			after, err := os.ReadFile(lock)
			require.NoError(t, err)
			assert.Equal(t, record+"\n", string(after))
		})
	}
}

// TestRunTests_TheOtherTiersNeitherLockNorCleanUp: the lint, module and setup tiers run while
// another run holds the lock, and neither kill a listener nor remove a SQLite file, on the way in
// or on exit. Each stops on its stubbed tool, so the tier is known to have started.
func TestRunTests_TheOtherTiersNeitherLockNorCleanUp(t *testing.T) {
	for tier, tool := range map[string]string{
		"internal":     "go",
		"core":         "go",
		"adminconsole": "go",
		"modules":      "go",
		"setup":        "go",
		"lint":         "unparam",
	} {
		t.Run(tier, func(t *testing.T) {
			markers := t.TempDir()
			lockDir := t.TempDir()
			lock := filepath.Join(lockDir, "lock")

			status, stderr := runScript(t, scriptEnv(stubBin(t, markers), lockDir, stackVariables...), lock,
				"--type", tier, "--no-build")

			assert.Equal(t, 1, status, "the run did not stop on its stubbed %s: %s", tool, stderr)
			assert.NotContains(t, stderr, "another data or integration run")
			assert.Contains(t, toolsRun(t, markers), tool)
			assert.Empty(t, cleanupCalls(t, markers), "the run freed the ports or removed the SQLite files")
		})
	}
}

// TestRunTests_AStackRunCleansUpOnExit: a data run frees the ports and removes the SQLite files
// before its tier and again when it exits, here on its stubbed go test's failure, and records
// itself in the lock while it holds it.
func TestRunTests_AStackRunCleansUpOnExit(t *testing.T) {
	markers := t.TempDir()
	lockDir := t.TempDir()

	status, stderr := runScript(t, scriptEnv(stubBin(t, markers), lockDir, stackVariables...), "",
		"--type", "data", "--db", "sqlite", "--no-build")

	assert.Equal(t, 1, status, stderr)
	assert.Contains(t, toolsRun(t, markers), "go")
	assert.Equal(t, 2, cleanupCalls(t, markers)["rm"], "the SQLite files are removed before the tier and on exit")
	record, err := os.ReadFile(filepath.Join(lockDir, "lock"))
	require.NoError(t, err)
	assert.Contains(t, string(record), "(--type data --db sqlite), started ")
}
