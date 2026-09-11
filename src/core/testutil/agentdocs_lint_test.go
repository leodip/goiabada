package testutil

import "testing"

// TestAgentDocsAreCurrent fails the core unit tier when CLAUDE.md and AGENTS.md
// have drifted apart, or when the states CLAUDE.md's "Auth States" section lists
// are not exactly the ones src/core/oauth/auth_context.go declares.
// AssertAgentDocs carries the reasoning, including why the roster is checked and
// the transitions are not. The auth server and the admin console call it from
// their own tiers.
func TestAgentDocsAreCurrent(t *testing.T) {
	AssertAgentDocs(t)
}
