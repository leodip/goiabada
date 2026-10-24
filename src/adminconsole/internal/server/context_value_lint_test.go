package server

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// TestContextValuesThroughAccessors fails the admin console unit tier when a production file reads
// or writes a request context value outside internal/reqctx, whose typed accessors are the one
// channel for the token set and the settings (#440). It is the auth server's call, made here for
// the twin. guard.AssertContextValuesThroughAccessors carries the rule and the shapes it
// resolves.
func TestContextValuesThroughAccessors(t *testing.T) {
	guard.AssertContextValuesThroughAccessors(t, "adminconsole", "internal/reqctx")
}
