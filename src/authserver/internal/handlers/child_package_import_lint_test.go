package handlers

// The one place the auth server's two child handler packages are held to "a child does not import
// the parent". apihandlers and accounthandlers each declare the ports they call in their own
// interfaces.go since #387; the rule, its reasoning and its rule tests are
// core/guard.AssertNoParentImport's, written once for both applications' handler children.

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// TestHandlers_ChildPackagesDoNotImportTheParent holds the real tree to the rule. It is acceptance
// bullet 5 of #387 in its checkable form.
func TestHandlers_ChildPackagesDoNotImportTheParent(t *testing.T) {
	guard.AssertNoParentImport(t, "github.com/leodip/goiabada/authserver/internal/handlers",
		"authserver/internal/handlers/apihandlers",
		"authserver/internal/handlers/accounthandlers",
	)
}
