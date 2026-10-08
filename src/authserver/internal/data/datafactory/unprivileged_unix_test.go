//go:build unix

package datafactory

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// nobody is the conventional unprivileged user and group, which owns no file a test writes.
const nobody = 65534

// unprivilegedChildEnv marks the child runAsUnprivileged starts. Its working directory holds the
// files the parent handed it, which unprivilegedChildFile reads.
const unprivilegedChildEnv = "GOIABADA_TEST_UNPRIVILEGED_CHILD"

// runAsUnprivileged runs this package's test named testName again, in a child process as nobody,
// and fails unless it passed there. It is for a test whose subject is a file permission: root
// writes a file whatever its mode, and the dev container and CI's test containers both run as
// root, so such a test skipped as root was checked by no automated run at all.
//
// The child reaches nothing of the parent's: a checkout under a private home directory, a private
// $TMPDIR and go test's own build directory are all closed to nobody. So everything it needs is
// put in one directory under /tmp, each mode set explicitly because the umask may have narrowed
// it: a copy of the test binary, the files the parent hands it, read by the parent as root and
// read back in the child through unprivilegedChildFile, and a temporary directory of its own. The
// child runs from that directory and never touches the checkout.
func runAsUnprivileged(t *testing.T, testName string, files map[string]string) {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "unprivileged-test-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	require.NoError(t, os.Chmod(dir, 0o755))

	self, err := os.Executable()
	require.NoError(t, err)
	binary := filepath.Join(dir, filepath.Base(self))
	copyFile(t, self, binary)
	require.NoError(t, os.Chmod(binary, 0o755))

	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		require.NoError(t, os.Chmod(path, 0o644))
	}

	tmp := filepath.Join(dir, "tmp")
	require.NoError(t, os.Mkdir(tmp, 0o700))
	require.NoError(t, os.Chown(tmp, nobody, nobody))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^"+testName+"$", "-test.v", "-test.count=1")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), unprivilegedChildEnv+"=1", "TMPDIR="+tmp)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nobody, Gid: nobody}}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output

	require.NoError(t, cmd.Run(), "the run as nobody failed:\n%s", output.String())
	// A -test.run that matched nothing exits 0 too, and so does a skip.
	require.Contains(t, output.String(), "--- PASS: "+testName, "the run as nobody did not pass it:\n%s", output.String())
}

// unprivilegedChildFile answers the file named name that runAsUnprivileged handed this process,
// and false when this process is not that child.
func unprivilegedChildFile(t *testing.T, name string) (string, bool) {
	t.Helper()
	if os.Getenv(unprivilegedChildEnv) != "1" {
		return "", false
	}
	content, err := os.ReadFile(name)
	require.NoError(t, err, "the parent hands the child %s", name)
	return string(content), true
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	src, err := os.Open(from)
	require.NoError(t, err)
	defer func() { _ = src.Close() }()
	dst, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	require.NoError(t, err)
	_, err = io.Copy(dst, src)
	require.NoError(t, err)
	require.NoError(t, dst.Close())
}
