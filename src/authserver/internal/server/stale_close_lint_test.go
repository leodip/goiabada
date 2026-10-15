package server

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// TestEachDeferredBodyCloseHoldsItsOwnResponse fails the authserver unit tier when any deferred
// func-literal close of a response body reads a variable a later statement of the same function
// reassigns, so that only the last response is closed. guard.AssertNoStaleDeferredBodyCloses
// carries the walk, the shapes it refuses and the reasoning, including why the scope is the
// whole tree rather than this module: the shape lives in the integration tier, and the admin
// console and core tiers read the same tree through their own guards when they run.
func TestEachDeferredBodyCloseHoldsItsOwnResponse(t *testing.T) {
	guard.AssertNoStaleDeferredBodyCloses(t)
}
