// Package issuerlength holds Check, the one bound on an issuer's length, which the general
// settings save holds every issuer to, the auth server's start holds the base URL to, since the
// first start seeds the base URL as the issuer, and the setup wizard holds the auth server URL it
// writes to, so the three cannot disagree on which base URLs start (#615). It is a package of its
// own, importing nothing beyond the standard library and core/errs, for core/adminpassword's
// reason: the wizard links whatever its home imports, and core/inputvalidation, where TextLength
// counts the same unit, brings core/i18n, core/oauth, a TOML parser and a JWT library with it.
// core/guard's imports_only_lint_test.go holds it to that, from there and not from a test here,
// for the reason core/adminpassword's doc gives (#500).
package issuerlength

import (
	"unicode/utf16"

	"github.com/leodip/goiabada/core/errs"
)

// Max is the longest issuer, in UTF-16 code units, the unit inputvalidation.TextLength counts
// every bound on typed text in. It sits under the 64 of the settings row's issuer column on the
// three engines that bound it: MySQL's and PostgreSQL's varchar(64), which count code points,
// never more than code units, and SQL Server's nvarchar(64), which counts UTF-16 code units.
// SQLite's TEXT has no bound.
const Max = 60

// Check answers why issuer is longer than Max, or nil when it is not. The reason names no variable,
// flag or field: each caller knows which one the issuer came from and says so.
func Check(issuer string) error {
	n := 0
	for _, r := range issuer {
		n += utf16.RuneLen(r)
	}
	if n > Max {
		return errs.Errorf("it is %d characters long, and the issuer allows at most %d characters", n, Max)
	}
	return nil
}
