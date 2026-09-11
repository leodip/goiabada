package server

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestAgentDocsAreCurrent fails the adminconsole unit tier when CLAUDE.md and
// AGENTS.md have drifted apart, or when the states CLAUDE.md's "Auth States"
// section lists are not exactly the ones src/core/oauth/auth_context.go
// declares. testutil.AssertAgentDocs carries the reasoning, including why the
// roster is checked and the transitions are not. Core and the auth server call
// it from their own tiers.
func TestAgentDocsAreCurrent(t *testing.T) {
	testutil.AssertAgentDocs(t)
}
