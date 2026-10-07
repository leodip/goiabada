package record

// The one place this package is held to "a persistence record imports nothing that does anything".
//
// record is the rows as they are stored, and every other package in the auth server names it: the
// data layer, the handlers, the services, the issuer. That makes it the cheapest place in the tree
// to put a capability and the worst -- whatever it imports, everything above it compiles against.
// Two methods had already been put there. User.SetOTPSecret and GetOTPSecret encrypted and
// decrypted a TOTP seed, so a cipher sat behind every package naming a stored user; KeyPair's
// ParsePrivateKey decrypted and parsed a signing key, so a JWT library did too. Neither is a fact
// about a row. Both were reachable only as methods on the record, which is why both were written
// there rather than beside the code that owns the capability (#387).
//
// The rule is therefore about the import list and not about any one method: a record that can name
// no cipher, no parser, no database and no service cannot grow a third such method without this
// going red first. Two paths are allowed beside the standard library. The rule was this package's
// own lint until #500 moved it to core/guard as AssertImportsOnly, when core/adminpassword became
// the second package held to an import list; its rule tests went with it.

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// recordDir is the package the rule covers, relative to the source root, forward slashes.
const recordDir = "authserver/internal/record"

// recordAllowedImports is every non-standard-library path a production file here may name.
//
// core/builtin carries the permission identifiers Client and Resource name, and core/errs is
// this tree's one error constructor, which the four enumerations #385 moved in here -- AcrLevel,
// KeyState, PasswordPolicy and ThreeStateSetting -- raise their refusals through, and which
// CLAUDE.md pattern 7 requires of every error this tree constructs. Both are declarations and
// values rather than behaviour, which is the test for anything that would be added here: a path
// that makes this package able to *do* something belongs on the other side of the call, not in
// this list.
//
// The standard library is allowed and is not listed. database/sql is the load-bearing one --
// sql.NullTime and sql.NullString are half the fields in this package -- and it is types only; the
// data layer holds the *sql.DB and every statement.
var recordAllowedImports = map[string]string{
	"github.com/leodip/goiabada/core/builtin": "the permission identifiers Client and Resource name",
	"github.com/leodip/goiabada/core/errs":    "the error constructor pattern 7 requires",
}

// recordImportsWhy is what a failure tells the reader, after the imports it found.
const recordImportsWhy = "A persistence record may not name these. This package is the rows as they are stored, and " +
	"everything above it compiles against whatever it imports. Everything else is a capability, and " +
	"a capability belongs in the package that owns it -- encrypting a TOTP seed in otpcredential, " +
	"decrypting and parsing a signing key in signingkeys, building an OIDC claim in userclaims, all " +
	"three of which were methods on a record until #387."

// TestRecord_ImportsNothingButValuesAndTheStandardLibrary holds the real tree to the rule. It is
// acceptance bullet 3 of #387 in its checkable form, which is stronger than the bullet as worded:
// the bullet names two methods, and an import list names every way back in.
func TestRecord_ImportsNothingButValuesAndTheStandardLibrary(t *testing.T) {
	guard.AssertImportsOnly(t, recordDir, recordAllowedImports, recordImportsWhy)
}
