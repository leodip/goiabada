package server

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestNoLegacyErrors fails the authserver unit tier when any production file under src/
// constructs an error outside core/errs. testutil.AssertNoLegacyErrors carries the rule and the
// reasoning for each of its three refused shapes.
//
// The scope is the whole source root, which is what makes it the measurement of #279's first goal
// rather than a per-module habit: cmd/goiabada-setup has no tier of its own, so it is held here
// and by the two callers beside this one, exactly as the gofmt guard holds it.
func TestNoLegacyErrors(t *testing.T) {
	testutil.AssertNoLegacyErrors(t)
}
