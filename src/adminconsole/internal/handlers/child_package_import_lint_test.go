package handlers

// The one place the admin console's six child handler packages are held to "a child does not
// import the parent". Each declares the ports it calls in its own interfaces.go since #440; the
// rule, its reasoning and its rule tests are core/testutil.AssertNoParentImport's, written once for
// both applications' handler children.

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestHandlers_ChildPackagesDoNotImportTheParent holds the real tree to the rule. handlers/mocks is
// not named: it is the parent's generated double, which the children's tests use.
func TestHandlers_ChildPackagesDoNotImportTheParent(t *testing.T) {
	testutil.AssertNoParentImport(t, "github.com/leodip/goiabada/adminconsole/internal/handlers",
		"adminconsole/internal/handlers/accounthandlers",
		"adminconsole/internal/handlers/adminclienthandlers",
		"adminconsole/internal/handlers/admingrouphandlers",
		"adminconsole/internal/handlers/adminresourcehandlers",
		"adminconsole/internal/handlers/adminsettingshandlers",
		"adminconsole/internal/handlers/adminuserhandlers",
	)
}
