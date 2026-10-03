package handlers

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// TestHandlers_NoDeadInterfaces fails the auth server unit tier when any interface declared under
// internal/handlers has no reference anywhere in this module, production or test.
// guard.AssertNoDeadInterfaces carries the rule and the reasoning for each shape it refuses.
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
//
// The walk is recursive, so apihandlers and accounthandlers have always been covered by the first
// entry. A new top-level package is not, which is why #387 names each capability package it lifts
// out of here as it lands: the interfaces leaving this directory would otherwise stop being
// guarded by the move itself, which is the silent-unguarding shape #333 exists to refuse. bootstrap
// is named for the same reason: it declares the seed's ports, and #424 created it. userconsent too:
// its port left handler_consent.go with the consent writer (#437). And authorizerequest, whose two
// ports the authorization handlers embed (#437).
func TestHandlers_NoDeadInterfaces(t *testing.T) {
	guard.AssertNoDeadInterfaces(t, "authserver/internal/handlers", "authserver/internal/revocation",
		"authserver/internal/emaillinks", "authserver/internal/otpcredential",
		"authserver/internal/userclaims", "authserver/internal/userconsent", "authserver/internal/authorizerequest",
		"authserver/internal/bootstrap")
}
