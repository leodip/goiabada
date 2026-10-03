package server

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// TestNoAgreementPointers fails the admin console unit tier when a Go comment anywhere in the
// repository points at an issue's agreement or a probe file instead of stating the fact.
// guard.AssertNoAgreementPointers carries the reasoning. Core and the auth server call it from
// their own tiers.
func TestNoAgreementPointers(t *testing.T) {
	guard.AssertNoAgreementPointers(t)
}
