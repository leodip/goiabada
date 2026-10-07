package guard

import "testing"

// TestAdminPassword_ImportsNothingButErrsAndTheStandardLibrary holds core/adminpassword to being a
// leaf. The setup wizard calls its one function and links whatever it imports: in
// core/inputvalidation, the rule brought core/i18n, core/oauth, a TOML parser and a JWT library into
// a binary that uses none of them (#500).
//
// The call is made here rather than beside the package, as record's is, because go mod tidy reads
// the tests of every package a module imports. A test in core/adminpassword importing this package
// put this package's own dependencies, chi through core/metrics and TOML, into the wizard's go.sum,
// which is the leak the rule exists to stop, one level down. No test in a core package the wizard
// imports may import core/guard, which AssertNoGuardInTestsReachedFrom holds.
func TestAdminPassword_ImportsNothingButErrsAndTheStandardLibrary(t *testing.T) {
	AssertImportsOnly(t, "core/adminpassword", map[string]string{
		"github.com/leodip/goiabada/core/errs": "the error constructor pattern 7 requires",
	}, "The setup wizard links whatever this package imports, and it calls one function there. "+
		"A refusal message that needs localizing, or anything else that needs a dependency, belongs "+
		"with the caller that renders it, not in the rule both callers share (#500).")
}
