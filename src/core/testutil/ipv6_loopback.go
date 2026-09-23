package testutil

import (
	"net"
	"testing"
)

// SkipWithoutIPv6Loopback skips the test when this machine cannot listen on ::1: a kernel booted
// with IPv6 off, or a container whose loopback carries no IPv6 address. Every test that listens
// on or dials an IPv6 literal calls it first, so such a machine reports a skip naming the reason
// rather than a failure that reads like the defect under test (#424).
//
// It probes with network "tcp6" on port 0, which binds nothing a test could collide with and is
// closed before the test runs.
func SkipWithoutIPv6Loopback(t *testing.T) {
	t.Helper()

	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("this machine has no IPv6 loopback: %v", err)
	}
	_ = ln.Close()
}
