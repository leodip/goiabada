package server

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// TestNoLiteralStackSecrets fails the authserver unit tier when a runnable file anywhere in the
// repository supplies a data key or a database password by literal, or a file spells one the
// Compose samples published (#501). guard.AssertNoLiteralStackSecrets carries the reasoning.
// Core and the admin console call it from their own tiers.
func TestNoLiteralStackSecrets(t *testing.T) {
	guard.AssertNoLiteralStackSecrets(t)
}
