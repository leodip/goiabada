package testutil

import "testing"

// TestErrorCodeDocMatchesTheCatalog fails the core unit tier when
// src/core/i18n/error_codes.md and catalogs/active.en.toml disagree: a code with
// no row, a row for a code the catalog does not declare, a duplicate row, or a
// documented sentence the server does not render. AssertErrorCodeDoc carries the
// reasoning, including why a second uncontrolled copy of every user-visible
// error message is worth a guard. The auth server and the admin console call it
// from their own tiers.
func TestErrorCodeDocMatchesTheCatalog(t *testing.T) {
	AssertErrorCodeDoc(t)
}
