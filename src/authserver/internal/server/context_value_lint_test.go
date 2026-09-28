package server

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestContextValuesThroughAccessors fails the authserver unit tier when a production file reads or
// writes a request context value outside internal/reqctx, whose typed accessors are the one channel
// for the settings, the session identifier and the two tokens (#433).
// testutil.AssertContextValuesThroughAccessors carries the rule and the shapes it resolves.
func TestContextValuesThroughAccessors(t *testing.T) {
	testutil.AssertContextValuesThroughAccessors(t, "authserver", "internal/reqctx",
		testutil.ContextValueExemption{
			File: "internal/middleware/middleware_ratelimiter.go",
			Reason: "the credential reservation key is private to the limiter: written and read " +
				"in this one file behind an unexported key and a checked read, and #439 moves it",
		},
	)
}
