// Package hostporttest holds the test helpers for code that listens on or dials an address
// hostport.Join builds. It is test support beside the package it concerns, compiled into no
// binary, and not in core/guard, which holds guards and nothing else (#442).
package hostporttest

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

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("this machine has no IPv6 loopback: %v", err)
	}
	_ = ln.Close()
}
