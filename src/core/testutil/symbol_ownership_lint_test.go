package testutil

import "testing"

// TestCoreSymbolOwnershipHolds fails the core unit tier when src/core/OWNERSHIP.md has drifted from
// the tree: an exported symbol a core package declares with no row, a row for a symbol that is
// gone, a row claiming less than the reference graph backs, or an asserted row with no argument
// behind it. AssertSymbolOwnership carries the reasoning, and OWNERSHIP.md's own header carries the
// seven justifications. The auth server and the admin console call it from their own tiers.
func TestCoreSymbolOwnershipHolds(t *testing.T) {
	AssertSymbolOwnership(t)
}
