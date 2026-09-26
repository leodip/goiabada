package i18n

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
)

// timeFmtLocale builds a context carrying the translator for tag, the same way
// the locale middleware does, so the assertions below read the real embedded
// catalogs rather than a stub.
func timeFmtLocale(tag string) context.Context {
	return context.WithValue(context.Background(), ctxKeyLocalizer, defaultBundle.localizerFor([]string{tag}))
}

// timeFmtInstant is the instant every absolute-format case below renders:
// 2026-09-14 21:03:07 UTC, a date whose day and month cannot be confused
// (14 is not a month) so a layout rendering them the wrong way round fails
// rather than looking plausible.
var timeFmtInstant = time.Date(2026, 9, 14, 21, 3, 7, 0, time.UTC)

func TestFormatDateTime_PerLocale(t *testing.T) {
	cases := []struct {
		locale string
		want   string
	}{
		// en: month first, 12-hour clock. 21:03 is 9:03 PM.
		{locale: "en", want: "09/14/2026 9:03 PM"},
		// pt-BR: day first, 24-hour clock.
		{locale: "pt-BR", want: "14/09/2026 21:03"},
		// An unknown locale matches English, as every other i18n helper does.
		{locale: "xx", want: "09/14/2026 9:03 PM"},
	}
	for _, c := range cases {
		t.Run(c.locale, func(t *testing.T) {
			instant := timeFmtInstant
			assert.Equal(t, c.want, FormatDateTime(timeFmtLocale(c.locale), &instant))
		})
	}
}

// TestFormatDateTime_LayoutCarriesNoEnglish pins decision 3 directly: the
// month and weekday names Go would substitute come from an English table, so
// a layout regressing to RFC1123 (or to any layout naming a month) would put
// "Sep" in front of a pt-BR reader. Asserting the absence of the English
// names is what makes that a failure rather than a cosmetic difference.
func TestFormatDateTime_LayoutCarriesNoEnglish(t *testing.T) {
	english := []string{
		"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
		"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun",
	}
	for _, locale := range []string{"en", "pt-BR"} {
		t.Run(locale, func(t *testing.T) {
			ctx := timeFmtLocale(locale)
			// Every month of the year, so a layout naming a month cannot slip
			// through on the one month whose name this instant does not reach.
			for month := time.January; month <= time.December; month++ {
				instant := time.Date(2026, month, 14, 21, 3, 7, 0, time.UTC)
				got := FormatDateTime(ctx, &instant)
				for _, name := range english {
					assert.NotContainsf(t, got, name, "%s rendered %q, which carries the English %q", locale, got, name)
				}
			}
		})
	}
}

func TestFormatDateTime_NilAndZeroRenderEmpty(t *testing.T) {
	ctx := timeFmtLocale("en")
	assert.Equal(t, "", FormatDateTime(ctx, nil))
	var zero time.Time
	assert.Equal(t, "", FormatDateTime(ctx, &zero))
}

// TestFormatDateTime_MissingLayoutFallsBackToANumericLayout drives the
// formatter against a translator over an empty bundle, which is the one way
// the layout key resolves to itself. Without the fallback, time.Format takes
// the key as a layout, finds no reference token in it, and renders the key
// verbatim into the table cell rather than failing.
func TestFormatDateTime_MissingLayoutFallsBackToANumericLayout(t *testing.T) {
	empty := &Translator{bundle: &Bundle{}, tag: language.English}
	ctx := context.WithValue(context.Background(), ctxKeyLocalizer, empty)
	instant := timeFmtInstant
	assert.Equal(t, "2026-09-14 21:03", FormatDateTime(ctx, &instant))
}

func TestFormatSince_UnitsAndPlurals(t *testing.T) {
	cases := []struct {
		name    string
		elapsed time.Duration
		en      string
		ptBR    string
	}{
		// Under a second, and the future, are the same answer: no count.
		{name: "same instant", elapsed: 0, en: "just now", ptBR: "agora mesmo"},
		{name: "just under a second", elapsed: 999 * time.Millisecond, en: "just now", ptBR: "agora mesmo"},
		{name: "in the future", elapsed: -5 * time.Second, en: "just now", ptBR: "agora mesmo"},

		// Seconds: the singular boundary, and the last second before minutes.
		{name: "one second", elapsed: time.Second, en: "1 second ago", ptBR: "há 1 segundo"},
		{name: "two seconds", elapsed: 2 * time.Second, en: "2 seconds ago", ptBR: "há 2 segundos"},
		{name: "fifty-nine seconds", elapsed: 59 * time.Second, en: "59 seconds ago", ptBR: "há 59 segundos"},

		// Minutes: the unit boundary, its singular, and the truncation that
		// makes 119 seconds one minute rather than two.
		{name: "one minute exactly", elapsed: time.Minute, en: "1 minute ago", ptBR: "há 1 minuto"},
		{name: "one minute fifty-nine", elapsed: time.Minute + 59*time.Second, en: "1 minute ago", ptBR: "há 1 minuto"},
		{name: "two minutes", elapsed: 2 * time.Minute, en: "2 minutes ago", ptBR: "há 2 minutos"},
		{name: "fifty-nine minutes", elapsed: 59*time.Minute + 59*time.Second, en: "59 minutes ago", ptBR: "há 59 minutos"},

		// Hours.
		{name: "one hour exactly", elapsed: time.Hour, en: "1 hour ago", ptBR: "há 1 hora"},
		{name: "two hours", elapsed: 2 * time.Hour, en: "2 hours ago", ptBR: "há 2 horas"},
		{name: "just under a day", elapsed: 23*time.Hour + 59*time.Minute + 59*time.Second, en: "23 hours ago", ptBR: "há 23 horas"},

		// Days, including the worked example #373 gave, 72h3m.
		{name: "one day exactly", elapsed: 24 * time.Hour, en: "1 day ago", ptBR: "há 1 dia"},
		{name: "three days", elapsed: 72*time.Hour + 3*time.Minute, en: "3 days ago", ptBR: "há 3 dias"},
		// Past the largest unit: the documented ceiling, pinned so shortening
		// it to months later is a visible change rather than a silent one.
		{name: "four hundred days", elapsed: 400 * 24 * time.Hour, en: "400 days ago", ptBR: "há 400 dias"},
	}

	now := timeFmtInstant
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			then := now.Add(-c.elapsed)
			assert.Equal(t, c.en, FormatSince(timeFmtLocale("en"), &then, now), "en")
			assert.Equal(t, c.ptBR, FormatSince(timeFmtLocale("pt-BR"), &then, now), "pt-BR")
		})
	}
}

func TestFormatSince_NilAndZeroRenderEmpty(t *testing.T) {
	ctx := timeFmtLocale("en")
	now := timeFmtInstant
	assert.Equal(t, "", FormatSince(ctx, nil, now))
	var zero time.Time
	assert.Equal(t, "", FormatSince(ctx, &zero, now))
}

// TestFormatSince_UnknownLocaleFallsBackToEnglish holds the phrase keys to the
// same English fallback every other catalog key has: a locale that never
// translated them renders English rather than the key.
func TestFormatSince_UnknownLocaleFallsBackToEnglish(t *testing.T) {
	now := timeFmtInstant
	then := now.Add(-3 * time.Hour)
	assert.Equal(t, "3 hours ago", FormatSince(timeFmtLocale("xx"), &then, now))
}
