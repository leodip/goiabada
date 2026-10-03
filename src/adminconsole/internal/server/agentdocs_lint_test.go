package server

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// TestAgentDocsAreCurrent fails the adminconsole unit tier when CLAUDE.md and
// AGENTS.md have drifted apart, or when the states CLAUDE.md's "Auth States"
// section lists are not exactly the ones src/authserver/internal/ceremony/auth_context.go
// declares. guard.AssertAgentDocs carries the reasoning, including why the
// roster is checked and the transitions are not. Core and the auth server call
// it from their own tiers.
func TestAgentDocsAreCurrent(t *testing.T) {
	guard.AssertAgentDocs(t)
}
