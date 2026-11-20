//go:build linux

package guard

// The e2e suite reads the mail through an SSH tunnel to Mailpit on the VPS (e2e/test.sh). A network
// can drop a connection that has carried nothing for a few minutes without telling either end, and
// the tunnel sits idle between the tests that read mail. Once it is dropped every later read hangs, and
// ssh probing every 300 seconds, as one machine's own configuration had it, notices some 20 minutes
// later. So e2e/infra/lib.sh gives every connection the scripts open a keepalive every 15 seconds
// (SSH_OPTS), and keep_tunnel opens the tunnel again, on the same port, whenever its ssh exits.
//
// These tests source lib.sh with ssh and scp replaced by a stub that logs its arguments and then
// exits or stays up, as a plan the test writes says, call by call. They run on Linux, whose process
// groups and subreapers let a run end everything it started.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubSSH stands in for ssh and scp. It logs its name and arguments, then follows the plan's line for
// this call: "exit <code>", or "stay", which records its process ID and runs until it is killed.
const stubSSH = `#!/usr/bin/env bash
n=$(( $(cat "$STUB/count" 2>/dev/null || echo 0) + 1 ))
echo "$n" >"$STUB/count"
echo "$(basename "$0") $*" >>"$STUB/log"
action="$(sed -n "${n}p" "$STUB/plan")"
case "$action" in
  stay) echo $$ >"$STUB/staying"; exec sleep 300 ;;
  "exit "*) exit "${action#exit }" ;;
  *) echo "no plan for call $n" >&2; exit 99 ;;
esac
`

// keepaliveOptions are the options every connection the e2e scripts open carries, as the stub logs them.
const keepaliveOptions = "-o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4"

// e2eLibRun is what a script run over lib.sh printed, and what the stub logged.
type e2eLibRun struct {
	out   string
	calls []string
	stub  string
}

// runE2ELib sources e2e/infra/lib.sh and runs script after it, with ssh and scp the stub following
// plan, the VPS vps.example and its user root. The script and every job it starts run in a process
// group of their own. A run that times out is killed as a group, and whatever of the group outlives
// the script, a keeper the script never stopped or the stub it started, is killed and reaped when the
// run ends, however it ends.
func runE2ELib(t *testing.T, plan []string, script string) e2eLibRun {
	t.Helper()
	require.NoError(t, becomeSubreaper(), "making the test process the reaper of what the scripts leave")
	stub := t.TempDir()
	bin := filepath.Join(stub, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	for _, name := range []string{"ssh", "scp"} {
		require.NoError(t, os.WriteFile(filepath.Join(bin, name), []byte(stubSSH), 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(stub, "plan"), []byte(strings.Join(plan, "\n")+"\n"), 0o600))

	// A run whose tunnel is never stopped ends here rather than at the test binary's timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lib := filepath.Join(filepath.Dir(SourceRoot(t)), "e2e", "infra", "lib.sh")
	cmd := exec.CommandContext(ctx, "bash", "-c", `. "$1" || exit 1`+"\n"+script, "bash", lib)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	cmd.Env = []string{
		"PATH=" + bin + ":" + os.Getenv("PATH"), "STUB=" + stub, "HOME=" + stub,
		"E2E_VPS_HOST=vps.example", "E2E_VPS_USER=root",
	}
	out, err := cmd.CombinedOutput()
	endProcessGroup(cmd)
	require.NoError(t, err, "%s", out)
	run := e2eLibRun{out: string(out), stub: stub}
	if log, err := os.ReadFile(filepath.Join(stub, "log")); err == nil {
		run.calls = strings.Split(strings.TrimRight(string(log), "\n"), "\n")
	}
	return run
}

// prSetChildSubreaper is PR_SET_CHILD_SUBREAPER, from linux/prctl.h.
const prSetChildSubreaper = 36

// becomeSubreaper makes the test process the parent of every process orphaned below it, in place of
// the init of its PID namespace. The dev container's init is sleep (src/.devcontainer), which reaps
// nothing.
var becomeSubreaper = sync.OnceValue(func() error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0); errno != 0 {
		return errno
	}
	return nil
})

// endProcessGroup kills what is left of the process group cmd led and reaps it, once Wait has reaped
// cmd's own process. What that process left behind is then the test process's child (becomeSubreaper),
// and wait4 on the group returns ECHILD once none is left.
func endProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return // it never started
	}
	pgid := cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	for {
		if _, err := syscall.Wait4(-pgid, nil, 0, nil); err != nil && !errors.Is(err, syscall.EINTR) {
			return
		}
	}
}

// waitForStub waits, in the script, until the stub has been called n times, and stops the script if
// it never is.
func waitForStub(n int) string {
	calls := strconv.Itoa(n)
	return `for _ in $(seq 1 100); do [[ "$(cat "$STUB/count" 2>/dev/null)" == ` + calls + ` ]] && break; sleep 0.1; done
[[ "$(cat "$STUB/count" 2>/dev/null)" == ` + calls + ` ]] || { echo "the stub was called $(cat "$STUB/count" 2>/dev/null || echo 0) times, not ` + calls + `"; exit 1; }
`
}

func TestE2ELib_EveryConnectionCarriesTheKeepalives(t *testing.T) {
	run := runE2ELib(t, []string{"exit 0", "exit 0"}, `ssh_vps true
scp_vps local.txt root@vps.example:/tmp/`)

	assert.Equal(t, []string{
		"ssh " + keepaliveOptions + " root@vps.example true",
		"scp -q " + keepaliveOptions + " local.txt root@vps.example:/tmp/",
	}, run.calls)
}

// The tunnel's ssh exits twice at once, as when it cannot connect, and the third stays up. Each
// reopening is on the same port and reported with the wait before it, which doubles; a kill then ends
// the tunnel and its ssh.
func TestE2ELib_KeepTunnelOpensTheTunnelAgainOnItsPortUntilKilled(t *testing.T) {
	run := runE2ELib(t, []string{"exit 255", "exit 255", "stay"}, `keep_tunnel 4567 18025 2>"$STUB/stderr" &
keeper=$!
`+waitForStub(3)+`for _ in $(seq 1 50); do [[ -s "$STUB/staying" ]] && break; sleep 0.1; done
staying="$(cat "$STUB/staying")"
kill "$keeper"
wait "$keeper"
echo "keeper exited with $?"
for _ in $(seq 1 20); do kill -0 "$staying" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$staying" 2>/dev/null; then echo "its ssh still runs"; kill "$staying"; else echo "its ssh ended"; fi
`)

	tunnel := "ssh " + keepaliveOptions + " -o ExitOnForwardFailure=yes -N -L 127.0.0.1:4567:127.0.0.1:18025 root@vps.example"
	assert.Equal(t, []string{tunnel, tunnel, tunnel}, run.calls)
	assert.Equal(t, "keeper exited with 0\nits ssh ended\n", run.out)

	stderr, err := os.ReadFile(filepath.Join(run.stub, "stderr"))
	require.NoError(t, err)
	reopened := regexp.MustCompile(`(?m)^WARN \d\d:\d\d:\d\d the SSH tunnel to port 18025 on the VPS closed \(ssh exited with 255\): opening it again in (\d+)s$`)
	var delays []string
	for _, m := range reopened.FindAllStringSubmatch(string(stderr), -1) {
		delays = append(delays, m[1])
	}
	assert.Equal(t, []string{"1", "2"}, delays, "%s", stderr)
}

// A kill that comes while the tunnel waits to try again ends it then, not when the wait is over.
func TestE2ELib_KeepTunnelEndsAtOnceWhenKilledBetweenTries(t *testing.T) {
	// The third failure is followed by a wait of four seconds.
	run := runE2ELib(t, []string{"exit 255", "exit 255", "exit 255"}, `keep_tunnel 4567 18025 2>/dev/null &
keeper=$!
`+waitForStub(3)+`sleep 0.3
started=$EPOCHREALTIME
kill "$keeper"
wait "$keeper"
echo "keeper exited with $? after $(( (${EPOCHREALTIME/./} - ${started/./}) / 1000 ))ms"
`)

	m := regexp.MustCompile(`^keeper exited with 0 after (\d+)ms\n$`).FindStringSubmatch(run.out)
	require.NotNil(t, m, "%s", run.out)
	ms, err := strconv.Atoi(m[1])
	require.NoError(t, err)
	assert.Less(t, ms, 1000, "the kill waited out the four-second pause")
}
