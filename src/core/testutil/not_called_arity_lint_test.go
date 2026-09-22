package testutil

import "testing"

// TestNotCalledArity fails the core unit tier when any test in the repository asserts a mock was
// not called with a matcher list that cannot match the method it names. AssertNotCalledArity
// carries the rule, the reasoning for each shape it refuses, and why the scope is the whole tree
// rather than this module. The auth server and the admin console call it from their own tiers.
func TestNotCalledArity(t *testing.T) {
	AssertNotCalledArity(t)
}
