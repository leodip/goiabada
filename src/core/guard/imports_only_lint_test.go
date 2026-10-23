package guard

import "testing"

// TestAdminPassword_ImportsNothingButErrsTheBlocklistAndTheStandardLibrary holds
// core/adminpassword to being a leaf. The setup wizard calls its one function and links whatever it
// imports: in core/inputvalidation, the rule brought core/i18n, core/oauth, a TOML parser and a JWT
// library into a binary that uses none of them (#500). core/passwordblocklist, which the rule reads
// the nist policy's two checks from, is a leaf of the standard library alone, held there below
// (#550 decision 7).
//
// The call is made here rather than beside the package, as record's is, because go mod tidy reads
// the tests of every package a module imports. A test in core/adminpassword importing this package
// put this package's own dependencies, chi through core/metrics and TOML, into the wizard's go.sum,
// which is the leak the rule exists to stop, one level down. No test in a core package the wizard
// imports may import core/guard, which AssertNoGuardInTestsReachedFrom holds.
func TestAdminPassword_ImportsNothingButErrsTheBlocklistAndTheStandardLibrary(t *testing.T) {
	AssertImportsOnly(t, "core/adminpassword", map[string]string{
		"github.com/leodip/goiabada/core/errs":              "the error constructor pattern 7 requires",
		"github.com/leodip/goiabada/core/passwordblocklist": "the nist policy's list of commonly used passwords and its context-word check, a standard-library leaf (#550)",
	}, "The setup wizard links whatever this package imports, and it calls one function there. "+
		"A refusal message that needs localizing, or anything else that needs a dependency, belongs "+
		"with the caller that renders it, not in the rule both callers share (#500).")
}

// TestDocsReader_ImportsNothingButErrsAndTheStandardLibrary holds core/docsreader to being a leaf.
// The setup wizard's docs tests read the site through it, and go mod tidy reads the tests of every
// package a module imports, so whatever this package reaches lands in the wizard's go.sum. A test
// the wizard reaches may not import core/guard, whose own dependencies, chi and TOML among them,
// would arrive that way (#500); the section and table readers the docs tests share reach this
// package instead, so it stays importable from every module's tests (#536).
func TestDocsReader_ImportsNothingButErrsAndTheStandardLibrary(t *testing.T) {
	AssertImportsOnly(t, "core/docsreader", map[string]string{
		"github.com/leodip/goiabada/core/errs": "the error constructor pattern 7 requires",
	}, "The setup wizard's docs tests read the site through this package, and go mod tidy reads "+
		"the tests of every package a module imports, so a dependency reached from here lands in "+
		"the wizard's go.sum (#500, #536).")
}

// TestIssuerLength_ImportsNothingButErrsAndTheStandardLibrary holds core/issuerlength to being a
// leaf, for core/adminpassword's reason: the setup wizard calls its one function on the auth server
// URL it writes, and links whatever it imports (#615).
func TestIssuerLength_ImportsNothingButErrsAndTheStandardLibrary(t *testing.T) {
	AssertImportsOnly(t, "core/issuerlength", map[string]string{
		"github.com/leodip/goiabada/core/errs": "the error constructor pattern 7 requires",
	}, "The setup wizard links whatever this package imports, and it calls one function there. "+
		"A refusal message that needs localizing, or anything else that needs a dependency, belongs "+
		"with the caller that renders it, not in the bound the start, the save and the wizard share (#615).")
}

// TestPasswordBlocklist_ImportsNothingButTheStandardLibrary holds core/passwordblocklist to being
// a leaf, for core/adminpassword's reason: the first administrator's rule the setup wizard calls
// reads the blocklist, so the wizard links whatever this package imports (#550 decision 7).
func TestPasswordBlocklist_ImportsNothingButTheStandardLibrary(t *testing.T) {
	AssertImportsOnly(t, "core/passwordblocklist", map[string]string{},
		"The setup wizard links whatever this package imports, through the first administrator's "+
			"rule. The two checks are comparisons over strings and need nothing more; a refusal "+
			"message, or anything else that needs a dependency, belongs with the caller that "+
			"renders it (#550).")
}
