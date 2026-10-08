//go:build !unix

package datafactory

import "testing"

// runAsUnprivileged is unreachable off unix, where os.Geteuid answers -1 and no test runs as root.
func runAsUnprivileged(t *testing.T, testName string, _ map[string]string) {
	t.Skipf("%s needs a unix user to run as", testName)
}

// unprivilegedChildFile answers false off unix, where no process is runAsUnprivileged's child.
func unprivilegedChildFile(*testing.T, string) (string, bool) {
	return "", false
}
