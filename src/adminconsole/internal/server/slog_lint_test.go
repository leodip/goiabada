package server

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestSlogConvention fails the admin console unit tier when any production file under src/ writes
// a record outside the logging convention. testutil.AssertSlogConvention carries the five rules
// and the reasoning for each.
//
// The scope is the whole source root rather than this module, for the reason the errs caller
// beside this one gives: the guard is about the source root, and a stale record is worth catching
// in whichever tier runs first. Core and the auth server call it from their own tiers.
func TestSlogConvention(t *testing.T) {
	testutil.AssertSlogConvention(t)
}
