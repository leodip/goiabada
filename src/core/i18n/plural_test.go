package i18n

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
)

// pluralCounts are the counts the issue lists for the three languages that share the chooser (#665,
// #666, #667): each category's first counts, the teens, and the return of a category past 20 and 100.
var pluralCounts = []int{0, 1, 2, 3, 4, 5, 11, 12, 14, 21, 22, 25, 100, 101, 102}

// The categories CLDR's cardinal rules give each of pluralCounts, written out from CLDR's tables
// rather than read from the library the chooser calls.
func TestPluralCategory_CLDRCardinalRules(t *testing.T) {
	for lang, want := range map[string][]string{
		"pl": {"many", "one", "few", "few", "few", "many", "many", "many", "many", "many", "few", "many", "many", "many", "few"},
		"ru": {"many", "one", "few", "few", "few", "many", "many", "many", "many", "one", "few", "many", "many", "one", "few"},
		"ar": {"zero", "one", "two", "few", "few", "few", "many", "many", "many", "many", "many", "many", "other", "other", "other"},
		// Indonesian has one category, other, for every count.
		"id": {"other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other"},
		// Japanese, too, has one category, other, for every count.
		"ja": {"other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other"},
		// And Simplified Chinese.
		"zh-Hans": {"other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other"},
		"en":      {"other", "one", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other"},
		// Zero takes the one form in French and Portuguese (Brazil).
		"fr":    {"one", "one", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other"},
		"pt-BR": {"one", "one", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other", "other"},
	} {
		for i, count := range pluralCounts {
			assert.Equalf(t, want[i], PluralCategory(lang, count), "%s, %d", lang, count)
		}
	}
}

// A regional tag reads its language's rules, as a recipient's language and region does.
func TestPluralCategory_ARegionalTagReadsItsLanguage(t *testing.T) {
	assert.Equal(t, "few", PluralCategory("pl-PL", 22))
	assert.Equal(t, "many", PluralCategory("pl-PL", 25))
	assert.Equal(t, "one", PluralCategory("ru-RU", 21))
}

// A count's sign does not choose its form, as CLDR's operand n is the number's absolute value, and a
// tag that does not parse reads English's rules, the language every miss falls back to.
func TestPluralCategory_NegativeCountsAndUnparseableTags(t *testing.T) {
	assert.Equal(t, "one", PluralCategory("en", -1))
	assert.Equal(t, "few", PluralCategory("pl", -22))
	// A large count keeps its magnitude whatever its sign: CLDR's rules compare the whole value, so
	// 10,000,001 is not 1 in Polish and 10,000,002 is not 2 in Arabic.
	assert.Equal(t, "many", PluralCategory("pl", 10_000_001))
	assert.Equal(t, "many", PluralCategory("pl", -10_000_001))
	assert.Equal(t, "other", PluralCategory("ar", 10_000_002))
	assert.Equal(t, "other", PluralCategory("ar", -10_000_002))
	// The most negative int, whose absolute value 9,223,372,036,854,775,808 does not fit in an int,
	// still reads its last digits: 8 in Polish is "many", and 08 in Arabic is "few".
	assert.Equal(t, "many", PluralCategory("pl", math.MinInt))
	assert.Equal(t, "few", PluralCategory("ar", math.MinInt))
	assert.Equal(t, "one", PluralCategory("not a tag!", 1))
	assert.Equal(t, "other", PluralCategory("not a tag!", 2))
}

// counted is a bundle of the given catalogs, keyed by language tag, for the chooser's fallbacks: a
// built-in catalog cannot miss a form, which the catalog check stops.
func counted(catalogs map[string]map[string]string) *bundle {
	var files []catalogFile
	for tag, messages := range catalogs {
		files = append(files, catalogFile{tag: language.Make(tag), messages: messages})
	}
	return build(files)
}

func TestTCount_ChoosesTheFormOfTheCountsCategory(t *testing.T) {
	b := counted(map[string]map[string]string{
		"en": {"since.minute.one": "{{.count}} minute ago", "since.minute.other": "{{.count}} minutes ago"},
		"pl": {
			"since.minute.one":   "{{.count}} minutę temu",
			"since.minute.few":   "{{.count}} minuty temu",
			"since.minute.many":  "{{.count}} minut temu",
			"since.minute.other": "{{.count}} minuty temu",
		},
	})
	en, pl := ctxForBundle(b, "en"), ctxForBundle(b, "pl")
	for count, want := range map[int]string{1: "1 minute ago", 2: "2 minutes ago", 5: "5 minutes ago", 22: "22 minutes ago"} {
		assert.Equal(t, want, TCount(en, "since.minute", count))
	}
	for count, want := range map[int]string{1: "1 minutę temu", 2: "2 minuty temu", 5: "5 minut temu", 22: "22 minuty temu", 25: "25 minut temu"} {
		assert.Equal(t, want, TCount(pl, "since.minute", count))
	}
}

// A category the page's catalog has no key for renders that catalog's other form, even where English
// has a key for the category, and a catalog without the family at all renders English's other form,
// by the ordinary fallback.
func TestTCount_FallsBackToTheCatalogsOwnOtherFormThenToEnglish(t *testing.T) {
	b := counted(map[string]map[string]string{
		"en": {
			"pairs.one":     "{{.count}} pair",
			"pairs.many":    "{{.count}} pairs (en many)",
			"pairs.other":   "{{.count}} pairs",
			"clients.one":   "{{.count}} client",
			"clients.other": "{{.count}} clients",
		},
		"pl": {"pairs.one": "{{.count}} para", "pairs.other": "{{.count}} pary (pl other)", "title": "Tytuł"},
	})
	pl := ctxForBundle(b, "pl")
	assert.Equal(t, "1 para", TCount(pl, "pairs", 1))
	assert.Equal(t, "5 pary (pl other)", TCount(pl, "pairs", 5), "pl has no many form, and English's is never taken while pl has other")
	assert.Equal(t, "2 pary (pl other)", TCount(pl, "pairs", 2), "pl has no few form")
	assert.Equal(t, "5 clients", TCount(pl, "clients", 5), "pl has no form of the family, so English's other renders")
	assert.Equal(t, "1 clients", TCount(pl, "clients", 1), "the ordinary fallback reads English's other, not English's category for the count")
	assert.Equal(t, "nothing.other", TCount(pl, "nothing", 3), "a family no catalog has renders its other form's key, the visible miss")
}

// The count fills {{.count}}, and the caller's other values fill theirs; the count wins over a
// value the caller named count.
func TestTCount_FillsTheCountAndTheCallersValues(t *testing.T) {
	b := counted(map[string]map[string]string{
		"en": {
			"moved.one":   "{{.count}} client moves to {{.brand}}.",
			"moved.other": "{{.count}} clients move to {{.brand}}.",
		},
	})
	en := ctxForBundle(b, "en")
	assert.Equal(t, "3 clients move to Acme.", TCount(en, "moved", 3, map[string]any{"brand": "Acme"}))
	assert.Equal(t, "1 client moves to Acme.", TCount(en, "moved", 1, map[string]any{"brand": "Acme", "count": 9}))
	assert.Equal(t, "2 clients move to <no value>.", TCount(en, "moved", 2), "no values but the count")
}

// The built-in catalogs answer through the chooser in each shipped language.
func TestTCount_TheBuiltInCatalogs(t *testing.T) {
	for _, tc := range []struct {
		tag   string
		count int
		want  string
	}{
		{"en", 1, "1 minute ago"},
		{"en", 22, "22 minutes ago"},
		{"pt-BR", 1, "há 1 minuto"},
		{"pt-BR", 2, "há 2 minutos"},
		{"de", 1, "vor 1 Minute"},
		{"de", 5, "vor 5 Minuten"},
	} {
		t.Run(tc.tag+"/"+strconv.Itoa(tc.count), func(t *testing.T) {
			assert.Equal(t, tc.want, TCount(ctxFor(tc.tag), "common.since.minute", tc.count))
		})
	}
}
