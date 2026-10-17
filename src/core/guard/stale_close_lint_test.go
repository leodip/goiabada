package guard

import "testing"

// TestEachDeferredBodyCloseHoldsItsOwnResponse fails the core unit tier when any deferred
// func-literal close of a response body anywhere in the repository reads a variable the same
// function reassigns after the defer is registered, so that only the last response is closed.
// AssertNoStaleDeferredBodyCloses carries the walk, the shapes it refuses and the reasoning. The
// auth server and the admin console call it from their own tiers.
func TestEachDeferredBodyCloseHoldsItsOwnResponse(t *testing.T) {
	AssertNoStaleDeferredBodyCloses(t)
}
