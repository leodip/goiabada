package handlers

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestHandlers_NoDeadInterfaces fails the auth server unit tier when any interface declared under
// internal/handlers has no reference anywhere in this module, production or test.
// testutil.AssertNoDeadInterfaces carries the rule and the reasoning for each shape it refuses.
//
// This half is green on arrival and is here for that reason rather than in spite of it. The census
// behind #333 resolved all sixteen of this package's interfaces as live, the thinnest of them --
// AuthorizeValidator, CodeIssuer and TokenValidator -- at a single same-package use each, so it is
// also the larger of the two files and the one where a tenth thin interface would be hardest to
// notice going dead. Guarding only the module that had the defect would leave that file to be
// caught by the next census somebody happened to run, which is how the admin console's nine
// survived (#333).
//
// The scope is this module, not the source root: an interface under internal/ is unreferenceable
// from outside the module that declares it.
func TestHandlers_NoDeadInterfaces(t *testing.T) {
	testutil.AssertNoDeadInterfaces(t, "authserver/internal/handlers")
}
