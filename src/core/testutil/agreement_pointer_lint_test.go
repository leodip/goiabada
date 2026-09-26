package testutil

import "testing"

// TestNoAgreementPointers fails the core unit tier when a Go comment anywhere in the repository
// points at an issue's agreement or a probe file instead of stating the fact.
// AssertNoAgreementPointers carries the reasoning. The auth server and the admin console call it
// from their own tiers.
func TestNoAgreementPointers(t *testing.T) {
	AssertNoAgreementPointers(t)
}
