package server

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestSlogConvention fails the authserver unit tier when any production file under src/ writes a
// record outside the logging convention. testutil.AssertSlogConvention carries the five rules and
// the reasoning for each.
//
// The scope is the whole source root, which is what makes it the measurement of #320's third goal
// rather than a per-module habit: cmd/goiabada-setup has no tier of its own, so it is held here
// and by the two callers beside this one, exactly as the gofmt and errs guards hold it.
func TestSlogConvention(t *testing.T) {
	testutil.AssertSlogConvention(t)
}
