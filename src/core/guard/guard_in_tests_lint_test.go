package guard

import "testing"

// TestSetupWizard_NoTestItReachesImportsCoreGuard holds the setup wizard's go.sum to the modules its
// packages use. The wizard is the one module whose tier calls none of the tree-wide guards, so it is
// the one a test importing core/guard leaks into; AssertNoGuardInTestsReachedFrom carries the
// reasoning (#500). Only the core tier calls it: it reads the whole source root, so a test added in
// the wizard is caught here as well as one added in core.
func TestSetupWizard_NoTestItReachesImportsCoreGuard(t *testing.T) {
	AssertNoGuardInTestsReachedFrom(t, "cmd/goiabada-setup")
}
