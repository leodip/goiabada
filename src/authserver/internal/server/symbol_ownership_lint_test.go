package server

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestCoreSymbolOwnershipHolds fails the authserver unit tier when src/core/OWNERSHIP.md has
// drifted from the tree: an exported symbol a core package declares with no row, a row for a
// symbol that is gone, a row claiming less than the reference graph backs, or an asserted row
// with no argument behind it. testutil.AssertSymbolOwnership carries the reasoning, and
// OWNERSHIP.md's own header carries the seven justifications. Core and the other application
// call it from their own tiers.
func TestCoreSymbolOwnershipHolds(t *testing.T) {
	testutil.AssertSymbolOwnership(t)
}
