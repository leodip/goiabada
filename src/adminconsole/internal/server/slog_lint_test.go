package server

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestSlogConvention fails the admin console unit tier when any production file under src/ writes
// a record outside the part of the logging convention sloglint cannot express.
// testutil.AssertSlogConvention carries those rules and the reasoning for each; sloglint, run by
// run-tests.sh's lint tier and CI's Lint job, carries the rest.
//
// The scope is the whole source root rather than this module, for the reason the errs caller
// beside this one gives: the guard is about the source root, and a stale record is worth catching
// in whichever tier runs first. Core and the auth server call it from their own tiers.
func TestSlogConvention(t *testing.T) {
	testutil.AssertSlogConvention(t)
}

// TestAuditLogContext fails the tier when a .Log call in a request-path package passes a context
// carrying nothing. The compiler forces AuditLogger.Log's callers to pass a context; this is what
// forces it to be the request's, so the audit record an operator filters by request_id is the one
// the request actually raised (#328 decision 3).
func TestAuditLogContext(t *testing.T) {
	testutil.AssertAuditLogContext(t)
}
