package server

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// TestContextValuesThroughAccessors fails the authserver unit tier when a production file reads or
// writes a request context value outside internal/reqctx, whose typed accessors are the one channel
// for the settings, the session identifier, the two tokens and the credential reservation (#433).
// It names no exemption: the reservation was the last value outside reqctx, and #439 moved it in.
// guard.AssertContextValuesThroughAccessors carries the rule and the shapes it resolves.
func TestContextValuesThroughAccessors(t *testing.T) {
	guard.AssertContextValuesThroughAccessors(t, "authserver", "internal/reqctx")
}
