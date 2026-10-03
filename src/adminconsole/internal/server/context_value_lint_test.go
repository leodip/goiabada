package server

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestContextValuesThroughAccessors fails the admin console unit tier when a production file reads
// or writes a request context value outside internal/reqctx, whose typed accessors are the one
// channel for the token set and the settings (#440). It is the auth server's call, made here for
// the twin. testutil.AssertContextValuesThroughAccessors carries the rule and the shapes it
// resolves.
func TestContextValuesThroughAccessors(t *testing.T) {
	testutil.AssertContextValuesThroughAccessors(t, "adminconsole", "internal/reqctx",
		testutil.ContextValueExemption{
			File: "internal/handlertest/request.go",
			Reason: "writes chi's route context under chi.RouteCtxKey, the only way chi offers to " +
				"give a handler called directly its URL parameters; the key is chi's, so no " +
				"accessor in reqctx could carry it. Replacing chi (#462) leaves this exemption " +
				"stale, and the guard then says so",
		},
	)
}
