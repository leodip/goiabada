package testutil

import "testing"

// TestGoSourcesAreGofmted fails the core unit tier when any Go file in the
// repository is not gofmt'd, which is what CI's Lint job checks per module
// before it runs vet, unparam or golangci-lint. AssertGofmted carries the
// reasoning, including why the scope is the whole tree rather than this module.
// The auth server and the admin console call it from their own tiers.
func TestGoSourcesAreGofmted(t *testing.T) {
	AssertGofmted(t)
}
