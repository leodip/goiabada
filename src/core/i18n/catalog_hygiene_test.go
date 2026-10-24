package i18n

import (
	"io/fs"
	"regexp"
	"slices"
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
	for _, name := range catalogNames(t) {
		for k, v := range loadCatalogFlat(t, name) {
			assert.NotEmptyf(t, v, "%s: key %q has an empty value; the loader treats it as absent, so the key renders English or leaks into the UI", name, k)
		}
	}
}

// catalogNames reads the same embedded set startup loads, so adding a language
// automatically adds it to every catalog check below.
func catalogNames(t *testing.T) []string {
	t.Helper()
	names, err := fs.Glob(embeddedCatalogs, "catalogs/*.toml")
	require.NoError(t, err)
	require.NotEmpty(t, names)
	for i := range names {
		names[i] = names[i][len("catalogs/"):]
	}
	return names
}

// Every built-in translation has exactly English's keys and placeholder names.
// The dotted Go placeholders and bare JavaScript placeholders are distinct:
// changing {{.count}} to {{count}} changes who substitutes it.
func TestCatalog_TranslationsMatchEnglish(t *testing.T) {
	en := loadCatalogFlat(t, "active.en.toml")
	for _, name := range catalogNames(t) {
		t.Run(name, func(t *testing.T) {
			translated := loadCatalogFlat(t, name)
			for key, value := range en {
				got, ok := translated[key]
				if assert.Truef(t, ok, "%s is missing %q", name, key) {
					assert.Equalf(t, catalogPlaceholders(value), catalogPlaceholders(got), "%s: %q changed placeholders", name, key)
				}
			}
			for key := range translated {
				_, ok := en[key]
				assert.Truef(t, ok, "%s has orphan key %q", name, key)
			}
		})
	}
}

var catalogPlaceholder = regexp.MustCompile(`{{\s*(\.?[A-Za-z_][A-Za-z0-9_]*)\s*}}`)

func catalogPlaceholders(value string) []string {
	var names []string
	for _, match := range catalogPlaceholder.FindAllStringSubmatch(value, -1) {
		names = append(names, match[1])
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func TestCatalogPlaceholders(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        []string
	}{
		{"plain", "No parameters.", nil},
		{"Go", "Hello {{.name}}, {{.count}} times", []string{".count", ".name"}},
		{"JavaScript", "{{count}} matches ({{detail}})", []string{"count", "detail"}},
		{"reordered and repeated", "{{.name}} {{ .count }} {{.name}}", []string{".count", ".name"}},
	} {
		t.Run(tc.name, func(t *testing.T) { assert.Equal(t, tc.want, catalogPlaceholders(tc.value)) })
	}
	for _, value := range []string{"{{.renamed}}", "No value", "{{count}}", "{{.count}"} {
		assert.NotEqual(t, catalogPlaceholders("{{.count}}"), catalogPlaceholders(value), "a renamed, dropped or broken placeholder must differ")
	}
}

// logInOrOut matches login, logout, log in, log out, log-in, logged out,
// logging in and logged you out as words, but not a protocol value such as
// prompt=login, nor login_hint, whose spelling is the protocol's.
var logInOrOut = regexp.MustCompile(`(?i)(?:^|[^=\w])log(?:ged|ging)?(?:[ -]?|\s+(?:you|them|me|us)\s+)(?:in|out)\b`)

// smtpMechanisms matches the SMTP authentication mechanisms a refusal names, in the capitals RFC 4954
// and the SASL registry spell them. LOGIN there is a protocol value, as prompt=login is, and not the
// UI's word for signing in.
var smtpMechanisms = regexp.MustCompile(`\b(?:PLAIN|LOGIN|CRAM-MD5)\b`)

// saysLogInOrOut reports whether v says login or logout as a word, once the protocol values above
// are taken out.
func saysLogInOrOut(v string) bool {
	return logInOrOut.MatchString(smtpMechanisms.ReplaceAllString(v, ""))
}

// TestCatalog_EnglishSaysSignInAndSignOut holds the English catalog to the
// glossary's words (#519): "sign in" and "sign out" as verbs, "sign-in" as the
// noun, never login or logout, and "signed out" for what a sign-out leaves.
// Keys are not values, so translation overrides keyed on the old spelling keep
// working.
func TestCatalog_EnglishSaysSignInAndSignOut(t *testing.T) {
	for k, v := range loadCatalogFlat(t, "active.en.toml") {
		assert.Falsef(t, saysLogInOrOut(v), "active.en.toml: key %q says %q; the UI says sign in, sign out and sign-in", k, v)
	}
}

func TestCatalog_LogInOrOutMatchesOnlyTheWords(t *testing.T) {
	for _, v := range []string{"Login", "Logout", "Are you sure you want to logout?", "shown on login and consent screens", "Log in", "log-in page",
		"Log out now", "Logged out", "You have been logged out.", "while logging in", "the application that logged you out"} {
		assert.Truef(t, saysLogInOrOut(v), "%q should match", v)
	}
	for _, v := range []string{"Sign in", "Sign out", "the sign-in page", "You have been signed out.", "prompt=login", "login_hint", "catalogue",
		"logo uploads", "the audit log is", "logged into the audit log", "The SMTP server offers none of PLAIN, LOGIN or CRAM-MD5."} {
		assert.Falsef(t, saysLogInOrOut(v), "%q should not match", v)
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
