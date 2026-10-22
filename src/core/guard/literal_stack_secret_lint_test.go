package guard

import "testing"

// TestNoLiteralStackSecrets fails the core unit tier when a runnable file anywhere in the
// repository supplies a data key or a database password by literal, or a file spells one the
// Compose samples published (#501). AssertNoLiteralStackSecrets carries the reasoning. The auth
// server and the admin console call it from their own tiers.
func TestNoLiteralStackSecrets(t *testing.T) {
	AssertNoLiteralStackSecrets(t)
}
