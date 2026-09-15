package testutil

import "testing"

// TestGeneratedMocksArePinned fails the core unit tier when the committed mocks and the
// mockery version versions.yaml pins have drifted apart, which is what #338 found sixteen
// files of. AssertGeneratedMocksArePinned carries the reasoning, including why this is worth
// a tier when CI's Lint job runs the generator itself. The auth server and the admin console
// call it from their own tiers.
func TestGeneratedMocksArePinned(t *testing.T) {
	AssertGeneratedMocksArePinned(t)
}
