package server

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestNoLegacyErrors fails the admin console unit tier when any production file under src/
// constructs an error outside core/errs. testutil.AssertNoLegacyErrors carries the rule and the
// reasoning for each of its three refused shapes.
//
// The scope is the whole source root rather than this module, for the reason the gofmt caller
// beside this one gives: the guard is about the source root, and a stale construction is worth
// catching in whichever tier runs first. Core and the auth server call it from their own tiers.
func TestNoLegacyErrors(t *testing.T) {
	testutil.AssertNoLegacyErrors(t)
}
