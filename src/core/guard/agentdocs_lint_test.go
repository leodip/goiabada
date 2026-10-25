package guard

import "testing"

// TestAgentDocsAreCurrent checks the canonical instructions, matching Claude copy, root budgets and
// references, and the authentication guide's state roster against auth_context.go. The core and
// both server tiers run the same guard; its own rule tests exercise the failure paths.
func TestAgentDocsAreCurrent(t *testing.T) {
	AssertAgentDocs(t)
}
