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

// runAsUnprivileged runs this package's test named testName again, in a child process as nobody,
// and fails unless it passed there. It is for a test whose subject is a file permission: root
// writes a file whatever its mode, and the dev container and CI's test containers both run as
// root, so such a test skipped as root was checked by no automated run at all.
//
// The test binary is copied into a directory nobody can read, because go test builds it under one
// only its own user can enter. The child keeps the working directory, so it reads the source tree
// as the parent does, and makes its own temporary directories.
func runAsUnprivileged(t *testing.T, testName string) {
	t.Helper()

	self, err := os.Executable()
	require.NoError(t, err)
	dir, err := os.MkdirTemp("", "unprivileged-test-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	require.NoError(t, os.Chmod(dir, 0o755))

	binary := filepath.Join(dir, filepath.Base(self))
	src, err := os.Open(self)
	require.NoError(t, err)
	defer func() { _ = src.Close() }()
	dst, err := os.OpenFile(binary, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	require.NoError(t, err)
	_, err = io.Copy(dst, src)
	require.NoError(t, err)
	require.NoError(t, dst.Close())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^"+testName+"$", "-test.v", "-test.count=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nobody, Gid: nobody}}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output

	require.NoError(t, cmd.Run(), "the run as nobody failed:\n%s", output.String())
	// A -test.run that matched nothing exits 0 too, and so does a skip.
	require.Contains(t, output.String(), "--- PASS: "+testName, "the run as nobody did not pass it:\n%s", output.String())
}
