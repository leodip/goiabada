package render

import (
	"context"
	"time"

	"github.com/leodip/goiabada/core/i18n"
)

// The DateTime and Since template functions' formatters. They were
// core/i18n.FormatDateTime and FormatSince until #442, which moved them here
// with their one caller: they read the catalogs through i18n.T alone, and the
// auth server's pages render no dates. The keys stay in core/i18n's catalogs,
// which both processes compile.
//
// The layout key holds a Go reference-time layout carrying no English, which
// is what makes the format itself translatable: time.Format has no locale of
// its own, and its month and weekday names come from a package-level English
// table, so a layout naming either renders English under every locale. Only a
// numeric layout escapes that, and the numeric layout differs per locale —
// which is exactly a translatable string (#373).
const (
	keyDateTimeLayout = "common.datetime.layout"
	keySinceJustNow   = "common.since.just_now"
	keySincePrefix    = "common.since."
)

// fallbackDateTimeLayout renders when the layout key is missing from the
// catalogs, or is present but unrenderable. i18n's visible-miss policy would
// otherwise hand time.Format the key itself, and time.Format substitutes
// whatever reference-time tokens it finds inside the key rather than
// rejecting it — so a catalog gap would put a mangled key string in a table
// cell rather than a date (#373).
const fallbackDateTimeLayout = "2006-01-02 15:04"

// formatDateTime renders t in the active locale's numeric date and time
// layout, in whatever zone t carries; every caller today passes UTC, which is
// what the pages have always shown.
//
// A nil or zero instant renders the empty string, so a column that was never
// set renders blank rather than year 1.
func formatDateTime(ctx context.Context, t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return formatDateTimeIn(i18n.T(ctx, keyDateTimeLayout), *t)
}

// formatDateTimeIn renders t in the layout formatDateTime looked up, which is
// the key itself when no catalog carries it: i18n.T answers a miss with the
// key. Taking the looked-up layout as a parameter is what lets a test reach
// the fallback without a catalog that lacks the key.
func formatDateTimeIn(layout string, t time.Time) string {
	if layout == keyDateTimeLayout {
		layout = fallbackDateTimeLayout
	}
	return t.Format(layout)
}

// formatSince renders how long ago t was as a whole phrase read from the
// catalog, rather than a number with a translated suffix glued to it: the
// count sits inside the translated string, so word order belongs to the
// translator and pt-BR gives "há 3 dias" where en gives "3 days ago" (#373).
//
// now is a parameter rather than time.Now() so the table beside this can pin
// an instant; the Since template function supplies time.Now().UTC().
//
// A nil or zero instant renders the empty string. An instant under a second
// old renders "just now", and so does one in the future, which is what clock
// skew between a database server and this one produces — a negative count
// would be the alternative.
func formatSince(ctx context.Context, t *time.Time, now time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	elapsed := now.Sub(*t)
	if elapsed < time.Second {
		return i18n.T(ctx, keySinceJustNow)
	}

	// ceiling: day is the largest unit, so a year-old consent reads "412 days
	// ago". Acceptable because every page showing this phrase shows the
	// absolute date beside it, and because a session's age is bounded by the
	// max lifetime setting. Revisit when a page shows the relative line alone;
	// month and year keys beside these are the next shape (#373).
	unit, count := "second", int64(elapsed/time.Second)
	switch {
	case elapsed >= 24*time.Hour:
		unit, count = "day", int64(elapsed/(24*time.Hour))
	case elapsed >= time.Hour:
		unit, count = "hour", int64(elapsed/time.Hour)
	case elapsed >= time.Minute:
		unit, count = "minute", int64(elapsed/time.Minute)
	}

	// ceiling: the plural form is chosen by count == 1, which is the rule for
	// both locales this tree ships, en and pt-BR. A locale with a few or many
	// form — ru, pl, ar — would take the "other" key for counts its grammar
	// treats differently. Revisit when a third locale is added; CLDR plural
	// rules keyed by the locale tag are the next shape (#373).
	form := "other"
	if count == 1 {
		form = "one"
	}
	return i18n.T(ctx, keySincePrefix+unit+"."+form, map[string]any{"count": count})
}
