package guard

import (
	"testing"

	"github.com/leodip/goiabada/core/internal/refgraph"
)

// AssertSymbolOwnership holds src/core/OWNERSHIP.md to the tree it describes, in both directions:
// every exported symbol a core package declares has exactly one row, every row names a symbol that
// still exists, and every row states the strongest justification the reference graph backs.
//
// All three module unit tiers call it, so it fires whichever tier runs, exactly as
// AssertArchitecture does. The census and the rules are refgraph's, and src/core/cmd/ownershipdump
// writes the computed rows from that same census, so the tool and the guard can never read the tree
// differently (#385, #431).
func AssertSymbolOwnership(t *testing.T) {
	t.Helper()

	assertSymbolOwnership(t, SourceRoot(t))
}

// assertSymbolOwnership is the reporting half, taking the root as a parameter and failing through
// a Reporter so a rule test can drive it against a fixture tree. See Reporter in guard.go.
func assertSymbolOwnership(r Reporter, root string) {
	r.Helper()

	check, err := refgraph.CheckOwnership(root)
	if err != nil {
		r.Fatalf("%v", err)
	}
	// The three ways this guard could pass by finding nothing. A census that read no package, no
	// declaration or no reference satisfies every rule over an empty set, which is the one failure
	// mode a clean tree cannot be told apart from a correct one.
	if check.Packages == 0 {
		r.Fatalf("found no core packages under %s", root)
	}
	if check.Declared == 0 {
		r.Fatalf("found no exported declarations in any core package under %s", root)
	}
	if check.Referenced == 0 {
		r.Fatalf("found no production reference to any core symbol under %s", root)
	}

	for _, f := range check.Findings {
		r.Errorf("%s", f)
	}
}
