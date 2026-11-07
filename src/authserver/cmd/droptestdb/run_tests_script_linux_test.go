package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// prSetChildSubreaper is prctl(2)'s PR_SET_CHILD_SUBREAPER, which the syscall package does not name.
const prSetChildSubreaper = 36

// TestScriptCommand_AHungRunEndsAtItsDeadlineWithWhatItStarted: the helper every script test runs
// the script through ends a run at its context's deadline together with what the run started,
// rather than waiting on an output pipe a command the run started still holds, as a stub that hung
// would. The script is a stand-in whose sleep keeps the pipe and outlives it.
//
// The kill leaves the sleep without a parent. This process adopts it as a child subreaper and
// reaps it, which is also how the test knows the sleep was killed: in the dev container the PID 1
// that would adopt it otherwise is sleep infinity, which never reaps, and it would stay a zombie.
func TestScriptCommand_AHungRunEndsAtItsDeadlineWithWhatItStarted(t *testing.T) {
	_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0)
	require.Zero(t, errno, "unable to become a child subreaper")
	t.Cleanup(func() { _, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 0, 0) })

	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pid")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "run-tests.sh"),
		[]byte("sleep 300 &\necho $! > \""+pidFile+"\"\nwait\n"), 0o600))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := scriptCommand(ctx, dir)
	var stderr strings.Builder
	cmd.Stderr = &stderr

	start := time.Now()
	require.Error(t, cmd.Run())

	assert.Less(t, time.Since(start), 4*time.Second, "the run outlived its deadline")
	content, err := os.ReadFile(pidFile)
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
	require.NoError(t, err)
	var status syscall.WaitStatus
	reaped, err := syscall.Wait4(pid, &status, 0, nil)
	require.NoError(t, err, "the run's sleep was not left to this process to reap")
	assert.Equal(t, pid, reaped)
	assert.True(t, status.Signaled() && status.Signal() == syscall.SIGKILL,
		"the run's sleep was not killed with the run: %v", status)
}
