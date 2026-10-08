package i18n

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadCatalogFlat parses an embedded catalog TOML into a flat key->value map,
// through the loader's own parser, so the assertions below hold the embedded
// catalogs to exactly the rules LoadBundle enforces at startup. The catalogs
// use quoted dotted keys (e.g. "auth.pwd.title"), which TOML treats as literal
// single keys, so a flat map[string]string is correct.
func loadCatalogFlat(t *testing.T, name string) map[string]string {
	t.Helper()
	data, err := embeddedCatalogs.ReadFile("catalogs/" + name)
	require.NoError(t, err, "reading %s", name)
	_, m, err := parseCatalog(name, data)
	require.NoError(t, err, "parsing %s", name)
	require.NotEmpty(t, m, "%s parsed to zero keys", name)
	return m
}

// TestParseCatalog_RefusesATableValue pins decision 3 of #273: a [table]
// section, which is how go-i18n spelled plural forms, fails the load naming
// the file and the key rather than being tolerated into one form rendered for
// every count.
func TestParseCatalog_RefusesATableValue(t *testing.T) {
	const table = `[greeting]
other = "hi"
`
	_, _, err := parseCatalog("active.xx.toml", []byte(table))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "active.xx.toml")
	assert.Contains(t, err.Error(), `"greeting"`)
}

// TestCatalog_NoEmptyValues guards against the "empty_prefix" class of bug: an
// empty value means "no translation here", so the loader removes the key from
// that locale and T() renders English. In the English catalog itself that
// leaves nothing to render but the key. An intentionally-empty slot can
// therefore never work.
func TestCatalog_NoEmptyValues(t *testing.T) {
	for _, name := range []string{"active.en.toml", "active.pt-BR.toml"} {
		for k, v := range loadCatalogFlat(t, name) {
			assert.NotEmptyf(t, v, "%s: key %q has an empty value; the loader treats it as absent, so the key renders English or leaks into the UI", name, k)
		}
	}
}

// TestCatalog_ParityEnPtBR asserts the English source of truth and pt-BR
// translation have identical key sets. A key present in only one locale means
// either an untranslated string (leaks English or the raw key) or an orphan.
func TestCatalog_ParityEnPtBR(t *testing.T) {
	en := loadCatalogFlat(t, "active.en.toml")
	pt := loadCatalogFlat(t, "active.pt-BR.toml")

	for k := range en {
		_, ok := pt[k]
		assert.Truef(t, ok, "key %q is in active.en.toml but missing from active.pt-BR.toml", k)
	}
	for k := range pt {
		_, ok := en[k]
		assert.Truef(t, ok, "key %q is in active.pt-BR.toml but missing from active.en.toml (orphan)", k)
	}
}

// logInOrOut matches login, logout, log in, log out, log-in, logged out,
// logging in and logged you out as words, but not a protocol value such as
// prompt=login, nor login_hint, whose spelling is the protocol's.
var logInOrOut = regexp.MustCompile(`(?i)(?:^|[^=\w])log(?:ged|ging)?(?:[ -]?|\s+(?:you|them|me|us)\s+)(?:in|out)\b`)

// TestCatalog_EnglishSaysSignInAndSignOut holds the English catalog to the
// glossary's words (#519): "sign in" and "sign out" as verbs, "sign-in" as the
// noun, never login or logout, and "signed out" for what a sign-out leaves.
// Keys are not values, so translation overrides keyed on the old spelling keep
// working.
func TestCatalog_EnglishSaysSignInAndSignOut(t *testing.T) {
	for k, v := range loadCatalogFlat(t, "active.en.toml") {
		assert.Falsef(t, logInOrOut.MatchString(v), "active.en.toml: key %q says %q; the UI says sign in, sign out and sign-in", k, v)
	}
}

func TestCatalog_LogInOrOutMatchesOnlyTheWords(t *testing.T) {
	for _, v := range []string{"Login", "Logout", "Are you sure you want to logout?", "shown on login and consent screens", "Log in", "log-in page",
		"Log out now", "Logged out", "You have been logged out.", "while logging in", "the application that logged you out"} {
		assert.Truef(t, logInOrOut.MatchString(v), "%q should match", v)
	}
	for _, v := range []string{"Sign in", "Sign out", "the sign-in page", "You have been signed out.", "prompt=login", "login_hint", "catalogue",
		"logo uploads", "the audit log is", "logged into the audit log"} {
		assert.Falsef(t, logInOrOut.MatchString(v), "%q should not match", v)
	}
}

// otherConceptNames matches the names the English catalog used for a concept
// the glossary names otherwise (#519): 2FA, 2-factor and two-factor alone for
// two-factor authentication, and authorization server for the auth server.
var otherConceptNames = regexp.MustCompile(`(?i)\b(?:2fa|2-factor|two-factor|authorization server)\b`)

// glossaryConceptNames is what otherConceptNames leaves alone: the glossary's
// own name for the concept.
var glossaryConceptNames = regexp.MustCompile(`(?i)two-factor authentication`)

// TestCatalog_EnglishNamesEachConceptAsTheGlossaryDoes holds the English
// catalog to one name per concept, the glossary's: "two-factor authentication"
// and "auth server".
func TestCatalog_EnglishNamesEachConceptAsTheGlossaryDoes(t *testing.T) {
	for k, v := range loadCatalogFlat(t, "active.en.toml") {
		other := otherConceptNames.FindString(glossaryConceptNames.ReplaceAllString(v, ""))
		assert.Emptyf(t, other, "active.en.toml: key %q says %q; the glossary says two-factor authentication and auth server", k, v)
	}
}

func TestCatalog_OtherConceptNamesMatchesOnlyTheOtherNames(t *testing.T) {
	for _, v := range []string{"2-factor auth (OTP)", "Users with 2FA enabled", "Your two-factor settings changed", "with the authorization server."} {
		assert.NotEmptyf(t, otherConceptNames.FindString(glossaryConceptNames.ReplaceAllString(v, "")), "%q should match", v)
	}
	for _, v := range []string{"Two-factor authentication", "Your two-factor authentication settings changed", "with the auth server.", "authorization code"} {
		assert.Emptyf(t, otherConceptNames.FindString(glossaryConceptNames.ReplaceAllString(v, "")), "%q should not match", v)
	}
}
