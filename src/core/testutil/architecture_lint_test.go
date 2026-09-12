package testutil

import "testing"

// TestArchitectureBoundaryHolds fails the core unit tier when the tree has drifted from the module
// and package ownership rules recorded in ARCHITECTURE.md: an import the tables do not allow, an
// exception listed for an edge that no longer exists, a core package with no ownership row, or a
// third-party module reaching the admin console when the document says it does not.
// AssertArchitecture carries the reasoning, including why the rules live in the document rather
// than here. The auth server and the admin console call it from their own tiers.
func TestArchitectureBoundaryHolds(t *testing.T) {
	AssertArchitecture(t)
}
