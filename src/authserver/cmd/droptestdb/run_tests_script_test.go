package main

// run-tests.sh drops goiabada_data or goiabada_integration through this command, with the
// password the stack generated, and starts the data tier with the data key it generated. A
// container created before #627 carries neither, so the script refuses first, with one line naming
// the variable and the remedy (#501). These run it, with each variable unset in turn, against
// stubs first on PATH, so no database is dropped, no test runs, no listener is killed and no file
// under /tmp is removed. The script's lock and its exit cleanup are held here the same way, with
// the lock moved into the test's own directory so that a real run beside the tests is not met.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

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
		writeStub(t, bin, name, body)
	}
	return bin
}

// writeStub writes an executable shell script named name into bin, replacing any stub there.
func writeStub(t *testing.T, bin, name, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(bin, name), []byte(body), 0o600))
	require.NoError(t, os.Chmod(filepath.Join(bin, name), 0o700))
}

// holderRecord is the record run-tests.sh writes in the lock for the run holding it.
func holderRecord(pid int) string {
	return "pid " + strconv.Itoa(pid) + " (--type integration --db sqlite), started 2026-11-07 10:00:00"
}

// exitedPid is the pid of a process that has run and been reaped.
func exitedPid(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	require.NoError(t, cmd.Run())
	return cmd.Process.Pid
}

// namedRun is bash on a script of its own named run-tests.sh, so that the process's command line
// names run-tests.sh as a run's does, not yet started.
//
// Nothing these tests start leaves a child of its own running when it ends: a child whose parent
// dies is adopted by the container's PID 1, which in the dev container is sleep infinity and never
// reaps it, so it would stay there as a zombie. The one test that needs such a child reaps it
// itself (run_tests_script_linux_test.go).
func namedRun(t *testing.T, body string) *exec.Cmd {
	t.Helper()
	script := filepath.Join(t.TempDir(), "run-tests.sh")
	require.NoError(t, os.WriteFile(script, []byte(body), 0o600))
	return exec.Command("bash", script)
}

// liveRunPid is the pid of a process named as a run is, alive until the test ends. It waits in
// bash's own read on a pipe this test holds, and ends when the test closes it.
func liveRunPid(t *testing.T) int {
	t.Helper()
	cmd := namedRun(t, "read -r _\n")
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	return cmd.Process.Pid
}

// zombieRunPid is the pid of a process named as a run is that has exited and not been reaped, so
// that it is still in /proc, until the test ends.
func zombieRunPid(t *testing.T) int {
	t.Helper()
	cmd := namedRun(t, "exit 0\n")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Wait() })
	stat := filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "stat")
	require.Eventually(t, func() bool {
		content, err := os.ReadFile(stat)
		return err == nil && strings.Contains(string(content), ") Z ")
	}, 10*time.Second, 10*time.Millisecond, "the process did not become a zombie")
	return cmd.Process.Pid
}

// holdLock takes the lock file the way another run holds it, flock(2) on a descriptor of its own,
// from this process, and returns what frees it. The test's end frees it too.
func holdLock(t *testing.T, lock string) (release func()) {
	t.Helper()
	fd, err := syscall.Open(lock, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC, 0o600)
	require.NoError(t, err)
	require.NoError(t, syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB))
	var once sync.Once
	release = func() { once.Do(func() { _ = syscall.Close(fd) }) }
	t.Cleanup(release)
	return release
}

// releaseOnRequest frees a held lock once a stub asks for it, by creating requested, and then
// creates released, which the stub waits for. It gives up at the test's end.
func releaseOnRequest(t *testing.T, release func(), requested, released string) {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(10 * time.Millisecond):
			}
			if _, err := os.Stat(requested); err == nil {
				release()
				_ = os.WriteFile(released, nil, 0o600)
				return
			}
		}
	}()
}

// requestReleaseStub is a stub body that asks releaseOnRequest to free the lock, by its two files,
// waits until it has, and then runs then.
func requestReleaseStub(requested, released, then string) string {
	return "#!/bin/sh\ntouch '" + requested + "'\nwhile [ ! -e '" + released + "' ]; do :; done\n" + then
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

// cleanupLog is the housekeeping stubs' calls in the order they ran, from markers' cleanup file.
func cleanupLog(t *testing.T, markers string) []string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(markers, "cleanup"))
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	return strings.Fields(string(content))
}

// cleanupCalls is how many times each housekeeping stub ran.
func cleanupCalls(t *testing.T, markers string) map[string]int {
	t.Helper()
	calls := map[string]int{}
	for _, call := range cleanupLog(t, markers) {
		calls[call]++
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

// authserverDir is src/authserver, where run-tests.sh is and runs from.
func authserverDir(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	require.NoError(t, err)
	root, err := sourceroot.FindSourceRoot(cwd)
	require.NoError(t, err)
	return filepath.Join(root, "authserver")
}

// scriptCommand is run-tests.sh with args, run from dir. It runs in a process group of its own, and
// the end of ctx kills the whole group: killing only bash would leave a command it started, a stub
// that hung, running with the output pipes open, and Wait would block on them past any deadline.
// WaitDelay bounds what is left.
func scriptCommand(ctx context.Context, dir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "bash", append([]string{filepath.Join(dir, "run-tests.sh")}, args...)...)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

// runScript runs run-tests.sh with args, with heldLock, when it is not empty, held by this process
// as another run would hold it, and returns the exit status and the standard error. A run that has
// not ended within a minute is killed, with everything it started, and fails the test.
func runScript(t *testing.T, env []string, heldLock string, args ...string) (int, string) {
	t.Helper()
	if heldLock != "" {
		holdLock(t, heldLock)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := scriptCommand(ctx, authserverDir(t), args...)
	cmd.Env = env
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	require.NoError(t, ctx.Err(), "run-tests.sh %v did not end", args)

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

// TestRunTests_AFlagWithoutItsValueIsRefused: --type, --db and --run given last, with no value
// after them, exit 2 naming the flag, before any tier starts.
func TestRunTests_AFlagWithoutItsValueIsRefused(t *testing.T) {
	for _, args := range [][]string{
		{"--type"}, {"-t"}, {"--db"}, {"-d"}, {"--run"}, {"-r"},
		{"--no-build", "--type"}, {"--type", "core", "--run"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			markers := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := scriptCommand(ctx, authserverDir(t), args...)
			cmd.Env = scriptEnv(stubBin(t, markers), t.TempDir(), stackVariables...)
			out, err := cmd.Output()

			require.NoError(t, ctx.Err(), "run-tests.sh %v did not end", args)
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit)
			assert.Equal(t, 2, exit.ExitCode())
			assert.Contains(t, string(out), args[len(args)-1]+" needs a value.")
			assert.Empty(t, toolsRun(t, markers))
		})
	}
}

// TestRunTests_ASecondStackRunIsRefusedNamingTheFirst: while another run holds the lock, a run of
// the data or the integration tier exits 2 with the holder's record, before it builds, kills a
// listener or removes a file, and leaves the record as it found it. The record names a live process
// named as a run is.
func TestRunTests_ASecondStackRunIsRefusedNamingTheFirst(t *testing.T) {
	record := holderRecord(liveRunPid(t))
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

// TestRunTests_ARefusedRunReadsTheRecordUntilItsHolderIsAlive: the holder writes its record just
// after it takes the lock, so a run refused in between finds the file empty or holding the previous
// holder's record. The refused run reads it again until it names a live run; the sleep stub stands
// in for the holder, writing its record during the refused run's first wait. A pid that another
// program has now, or a zombie's, is not a live run, though both are in /proc. A record that never
// names a live run is reported for what it is.
func TestRunTests_ARefusedRunReadsTheRecordUntilItsHolderIsAlive(t *testing.T) {
	live := holderRecord(liveRunPid(t))
	exited := holderRecord(exitedPid(t))
	reused := holderRecord(os.Getpid())
	zombie := holderRecord(zombieRunPid(t))
	for _, tc := range []struct {
		name    string
		found   string
		written string
		want    string
	}{
		{"written while it waits, over an empty file", "", live, live + "."},
		{"written while it waits, over the previous holder's record", exited, live, live + "."},
		{"written while it waits, over a record whose pid another program now has", reused, live, live + "."},
		{"never written", "", "", "its pid is not recorded."},
		{"its holder has exited", exited, "", exited + ", which has exited while commands it started still hold the lock."},
		{"its holder has exited and is not reaped yet", zombie, "", zombie + ", which has exited while commands it started still hold the lock."},
		{"unreadable", "pid not-a-pid (--type data --db mysql)", "", "its pid is not recorded."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			markers := t.TempDir()
			lockDir := t.TempDir()
			lock := filepath.Join(lockDir, "lock")
			require.NoError(t, os.WriteFile(lock, []byte(tc.found), 0o600))
			bin := stubBin(t, markers)
			if tc.written != "" {
				writeStub(t, bin, "sleep", "#!/bin/sh\nprintf '%s\\n' '"+tc.written+"' > '"+lock+"'\n")
			}

			status, stderr := runScript(t, scriptEnv(bin, lockDir, stackVariables...), lock,
				"--type", "data", "--db", "sqlite", "--no-build")

			assert.Equal(t, 2, status)
			assert.Contains(t, stderr, "another data or integration run is using this container's test server and databases: "+tc.want)
			assert.Empty(t, toolsRun(t, markers))
		})
	}
}

// TestRunTests_ARunWhoseHolderFinishesWhileItWaitsGoesOn: a holder that finishes during the refused
// run's wait for its record frees the lock, and the run takes it and goes on rather than being
// refused. This process holds the lock, and the sleep stub has it freed during the run's first
// wait.
func TestRunTests_ARunWhoseHolderFinishesWhileItWaitsGoesOn(t *testing.T) {
	markers := t.TempDir()
	lockDir := t.TempDir()
	lock := filepath.Join(lockDir, "lock")
	release := holdLock(t, lock)
	requested, released := filepath.Join(markers, "requested"), filepath.Join(markers, "released")
	releaseOnRequest(t, release, requested, released)

	bin := stubBin(t, markers)
	writeStub(t, bin, "sleep", requestReleaseStub(requested, released, ""))
	status, stderr := runScript(t, scriptEnv(bin, lockDir, stackVariables...), "",
		"--type", "data", "--db", "sqlite", "--no-build")

	assert.Equal(t, 1, status, "the run did not stop on its stubbed go: %s", stderr)
	assert.NotContains(t, stderr, "another data or integration run")
	assert.Contains(t, toolsRun(t, markers), "go")
	record, err := os.ReadFile(lock)
	require.NoError(t, err)
	assert.Contains(t, string(record), "(--type data --db sqlite), started ")
}

// TestRunTests_ARunTakesALockFreedDuringItsLastRead: after its last read of the record, the tenth,
// the run tries the lock once more, so a holder that finishes during that read leaves the lock to
// it rather than to a refusal that says the holder's commands still hold it. The cat stub stands in
// for the read, and has the lock freed during its tenth call.
func TestRunTests_ARunTakesALockFreedDuringItsLastRead(t *testing.T) {
	markers := t.TempDir()
	lockDir := t.TempDir()
	lock := filepath.Join(lockDir, "lock")
	release := holdLock(t, lock)
	requested, released := filepath.Join(markers, "requested"), filepath.Join(markers, "released")
	releaseOnRequest(t, release, requested, released)

	bin := stubBin(t, markers)
	counter := filepath.Join(markers, "reads")
	writeStub(t, bin, "cat", "#!/bin/sh\n"+
		"n=$(( $(/bin/cat '"+counter+"' 2>/dev/null || echo 0) + 1 ))\necho \"$n\" > '"+counter+"'\n"+
		"if [ \"$n\" -eq 10 ]; then\n"+
		strings.TrimPrefix(requestReleaseStub(requested, released, ""), "#!/bin/sh\n")+
		"fi\nexec /bin/cat \"$@\"\n")
	status, stderr := runScript(t, scriptEnv(bin, lockDir, stackVariables...), "",
		"--type", "data", "--db", "sqlite", "--no-build")

	assert.Equal(t, 1, status, "the run did not stop on its stubbed go: %s", stderr)
	assert.NotContains(t, stderr, "another data or integration run")
	assert.Contains(t, toolsRun(t, markers), "go")
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
// itself in the lock while it holds it. Each cleanup checks the listeners with netstat and then
// removes the files, so the calls are two runs of netstat, each followed by rm.
func TestRunTests_AStackRunCleansUpOnExit(t *testing.T) {
	markers := t.TempDir()
	lockDir := t.TempDir()

	status, stderr := runScript(t, scriptEnv(stubBin(t, markers), lockDir, stackVariables...), "",
		"--type", "data", "--db", "sqlite", "--no-build")

	assert.Equal(t, 1, status, stderr)
	assert.Contains(t, toolsRun(t, markers), "go")
	calls := cleanupLog(t, markers)
	require.Equal(t, 2, cleanupCalls(t, markers)["rm"], "the SQLite files are removed before the tier and on exit: %v", calls)
	first := slices.Index(calls, "rm")
	assert.Positive(t, first, "the ports are freed before the tier: %v", calls)
	assert.Contains(t, calls[first+1:len(calls)-1], "netstat", "the ports are freed on exit: %v", calls)
	assert.Equal(t, "rm", calls[len(calls)-1], "the exit cleanup ends with the files: %v", calls)
	record, err := os.ReadFile(filepath.Join(lockDir, "lock"))
	require.NoError(t, err)
	assert.Contains(t, string(record), "(--type data --db sqlite), started ")
}
