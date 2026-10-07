package adminpassword

// The one place this package is held to being a leaf.
//
// The setup wizard calls Check and links whatever this package imports. The rule started in
// core/inputvalidation, beside the identifier validator's localized refusal, and through that
// package's core/i18n import it brought the message catalogs, the locale middleware, core/oauth, a
// TOML parser and a JWT library into a binary that uses none of them (#500). Moving the rule here
// removed them, and nothing but this test keeps them out: a later import would show only as new
// indirect requirements in the wizard's go.mod.

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// TestAdminPassword_ImportsNothingButErrsAndTheStandardLibrary holds the real package to the rule.
func TestAdminPassword_ImportsNothingButErrsAndTheStandardLibrary(t *testing.T) {
	guard.AssertImportsOnly(t, "core/adminpassword", map[string]string{
		"github.com/leodip/goiabada/core/errs": "the error constructor pattern 7 requires",
	}, "The setup wizard links whatever this package imports, and it calls one function here. "+
		"A refusal message that needs localizing, or anything else that needs a dependency, belongs "+
		"with the caller that renders it, not in the rule both callers share (#500).")
}
