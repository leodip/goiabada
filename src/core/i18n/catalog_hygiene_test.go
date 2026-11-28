package i18n

import (
	"io/fs"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadCatalogFlat parses an embedded catalog TOML into a flat key->value map,
// through the loader's own parser, so the assertions below hold the embedded
// catalogs to exactly the rules the built-in bundle is built by. The catalogs
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
// empty value renders as nothing, a label, heading or button with no text, in
// that language. An intentionally-empty slot is never what a screen wants.
func TestCatalog_NoEmptyValues(t *testing.T) {
	for _, name := range catalogNames(t) {
		for k, v := range loadCatalogFlat(t, name) {
			assert.NotEmptyf(t, v, "%s: key %q has an empty value; the UI would show nothing where its text belongs", name, k)
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
				if _, _, ok := countedForm(key); ok {
					continue // TestCatalog_CountedKeysHaveTheirLanguagesCategories holds the forms.
				}
				got, ok := translated[key]
				if assert.Truef(t, ok, "%s is missing %q", name, key) {
					assert.Equalf(t, catalogPlaceholders(value), catalogPlaceholders(got), "%s: %q changed placeholders", name, key)
				}
			}
			for key := range translated {
				if _, _, ok := countedForm(key); ok {
					continue
				}
				_, ok := en[key]
				assert.Truef(t, ok, "%s has orphan key %q", name, key)
			}
		})
	}
}

// pluralCategories is the roster of CLDR cardinal categories each built-in language's counted keys
// carry, one key per category: the categories the pinned golang.org/x/text's rules (CLDR 32) give
// the language's whole counts, with other, the form a category without its own key renders. A
// browser's newer rules are not its source, so a language gains no form when they change.
var pluralCategories = map[string][]string{
	"de":      {"one", "other"},
	"en":      {"one", "other"},
	"es":      {"one", "other"},
	"fr":      {"one", "other"},
	"id":      {"other"},
	"it":      {"one", "other"},
	"ja":      {"other"},
	"pl":      {"one", "few", "many", "other"},
	"ru":      {"one", "few", "many", "other"},
	"pt-BR":   {"one", "other"},
	"zh-Hans": {"other"},
}

// countedForm splits a counted key's form, such as "common.since.minute.few", into its family and
// its CLDR category. A sentence for nothing (".none") is not a plural form, so it is an ordinary key.
func countedForm(key string) (family, category string, ok bool) {
	dot := strings.LastIndexByte(key, '.')
	if dot <= 0 || !slices.Contains([]string{"zero", "one", "two", "few", "many", "other"}, key[dot+1:]) {
		return "", "", false
	}
	return key[:dot], key[dot+1:], true
}

func TestCountedForm(t *testing.T) {
	for key, want := range map[string][2]string{
		"common.since.minute.few":                       {"common.since.minute", "few"},
		"adminconsole.admin_branding.list.warnings.one": {"adminconsole.admin_branding.list.warnings", "one"},
		"a.other": {"a", "other"},
	} {
		family, category, ok := countedForm(key)
		assert.Truef(t, ok, "%q is a counted form", key)
		assert.Equal(t, want, [2]string{family, category})
	}
	for _, key := range []string{"adminconsole.account.otp.recovery_codes.remaining.none", "adminconsole.account.profile.gender_other",
		"other", ".other", "js.combobox.no_matches", "a.others"} {
		_, _, ok := countedForm(key)
		assert.Falsef(t, ok, "%q is not a counted form", key)
	}
}

// Every counted key carries exactly its language's categories, from the roster above, and every form
// carries the placeholders of English's other form, so each form writes its count: a one form that
// spelt a literal "1" would be wrong in a language whose one also covers 21.
func TestCatalog_CountedKeysHaveTheirLanguagesCategories(t *testing.T) {
	en := loadCatalogFlat(t, "active.en.toml")
	families := map[string][]string{} // English's families, to the placeholders of their other forms.
	for key := range en {
		if family, _, ok := countedForm(key); ok {
			other, ok := en[family+".other"]
			if assert.Truef(t, ok, "active.en.toml: %q has no other form", family) {
				families[family] = catalogPlaceholders(other)
			}
		}
	}
	require.NotEmpty(t, families)
	for _, name := range catalogNames(t) {
		t.Run(name, func(t *testing.T) {
			roster, ok := pluralCategories[localeFromCatalogFile(name)]
			require.Truef(t, ok, "%s's language has no entry in the roster of plural categories", name)
			got := map[string][]string{}
			for key, value := range loadCatalogFlat(t, name) {
				family, category, ok := countedForm(key)
				if !ok {
					continue
				}
				got[family] = append(got[family], category)
				if placeholders, ok := families[family]; assert.Truef(t, ok, "%s has orphan counted key %q", name, key) {
					assert.Equalf(t, placeholders, catalogPlaceholders(value), "%s: %q does not carry the placeholders of English's %s.other", name, key, family)
				}
				assert.Falsef(t, scriptFormLacksCount(key, value), "%s: %q, a form the console's script fills, does not spell its count {{count}}", name, key)
			}
			for family := range families {
				slices.Sort(got[family])
				assert.Equalf(t, sortedCopy(roster), got[family], "%s: %q has the wrong categories for its language", name, family)
			}
		})
	}
}

// scriptFormLacksCount reports whether key is a counted form the console's script fills, a "js." key,
// whose value lacks the exact {{count}} that tCount replaces. The script splits on that spelling
// alone, so a form spelling "{{ count }}" would show the placeholder itself, though its name matches
// English's.
func scriptFormLacksCount(key, value string) bool {
	return strings.HasPrefix(key, "js.") && !strings.Contains(value, "{{count}}")
}

func TestScriptFormLacksCount(t *testing.T) {
	assert.False(t, scriptFormLacksCount("js.combobox.results.many", "{{count}} wyników"))
	assert.True(t, scriptFormLacksCount("js.combobox.results.other", "{{ count }} wyniku"))
	assert.True(t, scriptFormLacksCount("js.combobox.results.one", "{{.count}} match"))
	assert.True(t, scriptFormLacksCount("js.combobox.results.one", "one match"))
	// A form Go renders spells its count {{.count}}, which Go's templates read with or without spaces.
	assert.False(t, scriptFormLacksCount("common.since.minute.few", "{{ .count }} minuty temu"))
}

// The roster names every built-in language, with the categories the chooser reaches for its whole
// counts and other: a category it reaches without a key would render the other form for it.
func TestCatalog_TheRosterIsTheCategoriesWholeCountsReach(t *testing.T) {
	var tags []string
	for _, name := range catalogNames(t) {
		tags = append(tags, localeFromCatalogFile(name))
	}
	slices.Sort(tags)
	var rostered []string
	for tag, roster := range pluralCategories {
		rostered = append(rostered, tag)
		reached := []string{"other"}
		for count := 0; count <= 1000; count++ {
			reached = append(reached, PluralCategory(tag, count))
		}
		slices.Sort(reached)
		assert.Equalf(t, sortedCopy(roster), slices.Compact(reached), "%s's roster", tag)
	}
	slices.Sort(rostered)
	assert.Equal(t, tags, rostered, "the roster names exactly the built-in languages")
}

func sortedCopy(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)
	return c
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

// backchannelLogout matches the name of OpenID Connect Back-Channel Logout 1.0, the protocol a
// client's back-channel logout URI and its logout tokens belong to (#784). Like LOGIN above, it is
// the protocol's spelling, not the UI's word for signing out.
var backchannelLogout = regexp.MustCompile(`(?i)\bback-channel logout\b`)

// urlPaths matches a URL path, such as /auth/logout, the endpoint's own spelling, which the glossary
// keeps among the protocol names. A path starts after a space, a bracket or a quote, or at the start.
var urlPaths = regexp.MustCompile(`(?:^|[\s("'])/[\w.-]+(?:/[\w.-]+)*`)

// saysLogInOrOut reports whether v says login or logout as a word, once the protocol values above
// are taken out.
func saysLogInOrOut(v string) bool {
	v = urlPaths.ReplaceAllString(v, " ")
	return logInOrOut.MatchString(backchannelLogout.ReplaceAllString(smtpMechanisms.ReplaceAllString(v, ""), ""))
}

// TestCatalog_EnglishSaysSignInAndSignOut holds the English catalog to the
// glossary's words (#519): "sign in" and "sign out" as verbs, "sign-in" as the
// noun, never login or logout, and "signed out" for what a sign-out leaves.
func TestCatalog_EnglishSaysSignInAndSignOut(t *testing.T) {
	for k, v := range loadCatalogFlat(t, "active.en.toml") {
		assert.Falsef(t, saysLogInOrOut(v), "active.en.toml: key %q says %q; the UI says sign in, sign out and sign-in", k, v)
	}
}

func TestCatalog_LogInOrOutMatchesOnlyTheWords(t *testing.T) {
	for _, v := range []string{"Login", "Logout", "Are you sure you want to logout?", "shown on login and consent screens", "Log in", "log-in page",
		"Log out now", "Logged out", "You have been logged out.", "while logging in", "the application that logged you out",
		"the back-channel logout URI, then logout", "a channel logout", "Log out, then call /auth/logout", "sign in/logout"} {
		assert.Truef(t, saysLogInOrOut(v), "%q should match", v)
	}
	for _, v := range []string{"Sign in", "Sign out", "the sign-in page", "You have been signed out.", "prompt=login", "login_hint", "catalogue",
		"logo uploads", "the audit log is", "logged into the audit log", "The SMTP server offers none of PLAIN, LOGIN or CRAM-MD5.",
		"Back-channel logout URI must use https or http", "the client's back-channel logout settings",
		"calls /auth/token, /auth/revoke, /auth/logout or /userinfo", "(/auth/logout)"} {
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

// TestCatalog_RussianWritesENeverYo holds the Russian catalog to е (#666 decision 4): a value that
// spells ё or Ё, though correct Russian, would make the same word read two ways across the pages.
func TestCatalog_RussianWritesENeverYo(t *testing.T) {
	for k, v := range loadCatalogFlat(t, "active.ru.toml") {
		assert.Falsef(t, spellsYo(v), "active.ru.toml: key %q says %q; the Russian catalog writes е, never ё", k, v)
	}
}

// spellsYo reports whether s holds ё or Ё, written as one character or as е and its combining
// diaeresis.
func spellsYo(s string) bool {
	return strings.ContainsAny(s, "ёЁ") || strings.Contains(s, "ё") || strings.Contains(s, "Ё")
}

func TestSpellsYo(t *testing.T) {
	for _, v := range []string{"Срок истёк.", "ЁЛКА", "Ещё раз", "ёще"} {
		assert.Truef(t, spellsYo(v), "%q spells ё", v)
	}
	for _, v := range []string{"Срок истек.", "Еще раз", "Sign in", "Ее"} {
		assert.Falsef(t, spellsYo(v), "%q does not spell ё", v)
	}
}

// TestCatalog_PhoneRefusalNamesTheBlankCountryOption holds every catalog's phone refusal to the
// label of the Country select's blank option on both Phone pages: the refusal tells the reader to
// choose that option to remove the number, so a label the select does not show sends them looking
// for an option that is not there.
func TestCatalog_PhoneRefusalNamesTheBlankCountryOption(t *testing.T) {
	for _, name := range catalogNames(t) {
		m := loadCatalogFlat(t, name)
		refusal := m["validator.phone.number_required"]
		for _, key := range []string{"adminconsole.account.phone.country_blank", "adminconsole.admin_users.phone.country_blank"} {
			assert.Containsf(t, refusal, m[key], "%s: validator.phone.number_required says %q, which does not name %s, %q", name, refusal, key, m[key])
		}
	}
}

// russianOtherNames matches the words the Russian catalog's refusals once used beside other words
// on the pages they refuse (#666 decision 3): краткое имя for a legal document's короткое имя,
// выведен из действия for отозван, подвал for a brand's нижний колонтитул, and замостить and
// полностью скругленные for the Плитка and Овальные options.
var russianOtherNames = regexp.MustCompile(`(?i)кратк|выв\p{L}*(?: его)? из действия|подвал|замост|полностью скругл`)

// TestCatalog_RussianNamesEachConceptAsItsPagesDo holds the Russian catalog to one word per
// concept where a refusal names a field, an action or an option its page labels.
func TestCatalog_RussianNamesEachConceptAsItsPagesDo(t *testing.T) {
	for k, v := range loadCatalogFlat(t, "active.ru.toml") {
		other := russianOtherNames.FindString(v)
		assert.Emptyf(t, other, "active.ru.toml: key %q says %q; its page says короткое имя, отозван, нижний колонтитул, плитка and овальные", k, v)
	}
}

func TestCatalog_RussianOtherNamesMatchesOnlyTheOtherNames(t *testing.T) {
	for _, v := range []string{"Введите краткое имя.", "Документ выведен из действия.", "Вывести из действия можно", "Выведите его из действия.", "в подвале бренда", "или замостить.", "или полностью скругленные."} {
		assert.NotEmptyf(t, russianOtherNames.FindString(v), "%q should match", v)
	}
	for _, v := range []string{"Введите короткое имя.", "Документ отозван.", "Записывать события аудита в вывод сервера", "Все остальное выводится как введено.", "в нижнем колонтитуле бренда", "«Плитка»", "Скругленные", "Овальные"} {
		assert.Emptyf(t, russianOtherNames.FindString(v), "%q should not match", v)
	}
}

// TestCatalog_NameOrderIsOneTheFormsKnow holds each catalog's name order, the format that says which
// name the console's three name forms ask for first, to one of the two values the forms draw:
// family name first in Japanese and Simplified Chinese, given name first in every other built-in
// language (#662 decision 11, #663 decision 2). Any other value would draw the forms given name first
// while the catalog meant otherwise.
func TestCatalog_NameOrderIsOneTheFormsKnow(t *testing.T) {
	want := map[string]string{
		"active.de.toml":      "given_first",
		"active.en.toml":      "given_first",
		"active.es.toml":      "given_first",
		"active.fr.toml":      "given_first",
		"active.id.toml":      "given_first",
		"active.it.toml":      "given_first",
		"active.ja.toml":      "family_first",
		"active.pl.toml":      "given_first",
		"active.pt-BR.toml":   "given_first",
		"active.ru.toml":      "given_first",
		"active.zh-Hans.toml": "family_first",
	}
	assert.ElementsMatch(t, slices.Collect(maps.Keys(want)), catalogNames(t), "every built-in catalog has its order here")
	for _, name := range catalogNames(t) {
		got, ok := loadCatalogFlat(t, name)["common.name_order"]
		if assert.Truef(t, ok, "%s carries no common.name_order", name) {
			assert.Containsf(t, []string{"given_first", "family_first"}, got, "%s: common.name_order is %q, which no form draws", name, got)
			assert.Equalf(t, want[name], got, "%s: common.name_order", name)
		}
	}
}
