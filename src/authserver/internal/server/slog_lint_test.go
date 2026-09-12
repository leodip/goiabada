package server

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestSlogConvention fails the authserver unit tier when any production file under src/ writes a
// record outside the part of the logging convention sloglint cannot express.
// testutil.AssertSlogConvention carries those rules and the reasoning for each; sloglint, run by
// run-tests.sh's lint tier and CI's Lint job, carries the rest.
//
// The scope is the whole source root, which is what makes it the measurement of #320's third goal
// rather than a per-module habit: cmd/goiabada-setup has no tier of its own, so it is held here
// and by the two callers beside this one, exactly as the gofmt and errs guards hold it.
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
