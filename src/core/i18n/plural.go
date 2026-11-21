package i18n

import (
	"context"

	"golang.org/x/text/feature/plural"
	"golang.org/x/text/language"
)

// A counted phrase is a family of flat catalog keys, one per CLDR cardinal category its language's
// whole counts reach: "<key>.one" and "<key>.other" in English, "<key>.one", ".few", ".many" and
// ".other" in Polish. TCount chooses among them by PluralCategory, so the rule for which form a
// count takes lives here alone, for every caller and every language (#665 decision 1). A sentence
// for nothing, such as "<key>.none", is not a plural form: the caller chooses it for zero.

// pluralCategoryNames are the names CLDR gives the cardinal categories, which are the last segment
// of a counted key's forms.
var pluralCategoryNames = map[plural.Form]string{
	plural.Zero:  "zero",
	plural.One:   "one",
	plural.Two:   "two",
	plural.Few:   "few",
	plural.Many:  "many",
	plural.Other: "other",
}

// PluralCategory returns the CLDR cardinal category, "zero", "one", "two", "few", "many" or
// "other", that a whole count takes in the language of tag, by the rules of the pinned
// golang.org/x/text (CLDR 32): in Polish 1 is "one", 2 to 4 and 22 "few", and 5 to 21 and 25 "many".
// A regional tag reads its language's rules, and a tag that does not parse reads English's. The
// count's sign does not matter, as CLDR's operand is the number's absolute value.
//
// It is TCount's rule, exported for a caller whose forms are not catalog keys.
func PluralCategory(tag string, count int) string {
	t, err := language.Parse(tag)
	if err != nil {
		t = language.English
	}
	return pluralCategory(t, count)
}

func pluralCategory(tag language.Tag, count int) string {
	if count < 0 {
		// x/text takes an operand too large for an int modulo 10,000,000, which also keeps the
		// most negative int from staying negative when its sign is dropped.
		count = -(count % 10_000_000)
	}
	return pluralCategoryNames[plural.Cardinal.MatchPlural(tag, count, 0, 0, 0, 0)]
}

// TCount translates the counted phrase key for count against the localizer carried on ctx: the form
// "<key>.<category>" of count's plural category in the page's catalog. A category the page's catalog
// has no key for renders that catalog's "<key>.other", and a catalog without its own other form
// renders "<key>.other" by T's ordinary fallback to English. A form is never taken from English
// while the page's catalog has its own other form.
//
// count fills the form's {{.count}}. args[0], when present, is a map[string]any of the form's other
// values, as T takes; a "count" in it is overridden by count.
func TCount(ctx context.Context, key string, count int, args ...any) string {
	data := map[string]any{}
	if len(args) > 0 {
		if td, ok := args[0].(map[string]any); ok {
			for k, v := range td {
				data[k] = v
			}
		}
	}
	data["count"] = count
	l := localizer(ctx)
	form := key + "." + pluralCategory(l.tag, count)
	if !l.owns(form) {
		form = key + ".other"
	}
	return l.render(form, data)
}

// owns reports whether the translator's own catalog, not English by fallback, holds key.
func (l *translator) owns(key string) bool {
	if l == nil || l.bundle == nil {
		return false
	}
	_, ok := l.bundle.messages[l.tag][key]
	return ok
}
