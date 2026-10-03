package server

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// TestNotCalledArity fails the adminconsole unit tier when any test under src/ asserts a mock was
// not called with a matcher list that cannot match the method it names.
// guard.AssertNotCalledArity carries the rule and the reasoning for each shape it refuses.
//
// The scope is the whole source root rather than this module, for the reason the gofmt and errs
// guards beside it carry: cmd/goiabada-setup's own tier calls none of the tree-wide guards, and
// the defect is one no compiler and no tier reports, so a module nobody thought to name is exactly
// where the next one would sit unseen (#421).
func TestNotCalledArity(t *testing.T) {
	guard.AssertNotCalledArity(t)
}
