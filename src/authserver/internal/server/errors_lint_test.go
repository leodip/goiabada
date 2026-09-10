package server

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestNoLegacyErrors fails the authserver unit tier when any production file under the two swept
// modules constructs an error outside core/errs. testutil.AssertNoLegacyErrors carries the rule
// and the reasoning for each of its three refused shapes.
//
// The scope is named rather than left empty because the admin console has not moved yet and would
// fail on work that has not happened. Stage 5 of #279 drops the arguments here and in core's
// caller, and the guard then holds the whole tree from every tier, as the gofmt caller beside this
// one already does.
func TestNoLegacyErrors(t *testing.T) {
	testutil.AssertNoLegacyErrors(t, "core", "authserver")
}
