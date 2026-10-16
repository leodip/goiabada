package server

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// TestEachDeferredBodyCloseHoldsItsOwnResponse fails the authserver unit tier when any deferred
// func-literal close of a response body anywhere in the repository reads a variable the same
// function reassigns after the defer is registered, so that only the last response is closed.
// guard.AssertNoStaleDeferredBodyCloses carries the walk, the shapes it refuses and the
// reasoning. Core and the admin console call it from their own tiers.
func TestEachDeferredBodyCloseHoldsItsOwnResponse(t *testing.T) {
	guard.AssertNoStaleDeferredBodyCloses(t)
}
