package render

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

// localeCtx sets the locale the way a request does, through the one
// locale-setting primitive core/i18n exports, so the assertions below read the
// real embedded catalogs and the real tag rather than a stub. The tags are a
// preference order, as a request's Accept-Language or ui_locales is.
func localeCtx(tags ...string) context.Context {
	return i18n.WithLocale(context.Background(), false, tags...)
}

func TestReference_FallbackChain(t *testing.T) {
	// "BR" resolves via CLDR for the active (English) locale (no country TOML ships).
	englishCtx := localeCtx("en")
	assert.Equal(t, "Brazil", refCountry(englishCtx, "BR", "fallback"))

	// Uncurated but valid code: resolved via CLDR for the active locale.
	assert.Equal(t, "Italy", refCountry(englishCtx, "IT", "fallback"))

	// A locale with no catalog renders an English page, and its names are English.
	unknownCtx := localeCtx("xx")
	assert.Equal(t, "Brazil", refCountry(unknownCtx, "BR", "fallback"))

	// Unparseable country code: fallback wins.
	assert.Equal(t, "fallback", refCountry(englishCtx, "not-a-code", "fallback"))

	// No context at all: defaults to the English CLDR name.
	assert.Equal(t, "Brazil", refCountry(context.Background(), "BR", "fallback"))
}

func TestReference_CountryCLDR(t *testing.T) {
	ptCtx := localeCtx("pt-BR")

	// "BR" resolves via CLDR in pt-BR (no country TOML ships).
	assert.Equal(t, "Brasil", refCountry(ptCtx, "BR", "Brazil"))
	// Other codes resolve via CLDR in pt-BR.
	assert.Equal(t, "Itália", refCountry(ptCtx, "IT", "Italy"))
	assert.Equal(t, "México", refCountry(ptCtx, "MX", "Mexico"))
	assert.Equal(t, "Espanha", refCountry(ptCtx, "ES", "Spain"))
}

func TestReference_PhoneCountryAssembly(t *testing.T) {
	ptCtx := localeCtx("pt-BR")

	// Assembled from emoji + CLDR-localized name + calling code (no phone-country
	// TOML ships), which reproduces the previously-curated pt-BR label exactly.
	assert.Equal(t, "🇧🇷 - Brasil (+55)", refPhoneCountry(ptCtx, "🇧🇷", "BR", "+55", "fallback"))

	// Same assembly path for any other code: emoji + CLDR name + calling code;
	// emoji and calling code pass through untouched.
	assert.Equal(t, "🇮🇹 - Itália (+39)", refPhoneCountry(ptCtx, "🇮🇹", "IT", "+39", "🇮🇹 - Italy (+39)"))

	// Unparseable code: the pre-assembled English fallback label wins.
	assert.Equal(t, "🏳 - Nowhere (+0)", refPhoneCountry(ptCtx, "🏳", "not-a-code", "+0", "🏳 - Nowhere (+0)"))
}

func TestReference_PerKindHelpers(t *testing.T) {
	ctx := localeCtx("en")
	assert.Equal(t, "🇧🇷 - Brazil (+55)", refPhoneCountry(ctx, "🇧🇷", "BR", "+55", "fallback"))
	// Assembled label: CLDR country + IANA zone + comment (no curated TOML anymore).
	assert.Equal(t, "United States - America/New_York - Eastern (most areas)",
		refTimezone(ctx, "America/New_York", "US", "United States", "Eastern (most areas)"))
}

func TestReference_TimezoneFallbackAssembly(t *testing.T) {
	// Zone absent from both TOMLs: assembled "<country> - <zone>[ - <comments>]".
	englishCtx := localeCtx("en")
	assert.Equal(t,
		"Japan - Asia/Tokyo",
		refTimezone(englishCtx, "Asia/Tokyo", "JP", "Japan", ""))
	assert.Equal(t,
		"Antarctica - Antarctica/Casey - Casey",
		refTimezone(englishCtx, "Antarctica/Casey", "AQ", "Antarctica", "Casey"))

	// pt-BR: country name is localized via CLDR, zone + comment stay in English.
	ptCtx := localeCtx("pt-BR")
	assert.Equal(t,
		"Japão - Asia/Tokyo",
		refTimezone(ptCtx, "Asia/Tokyo", "JP", "Japan", ""))
	assert.Equal(t,
		"Estados Unidos - America/Los_Angeles - Pacific",
		refTimezone(ptCtx, "America/Los_Angeles", "US", "United States", "Pacific"))

	// Empty country code: falls back to the supplied English name.
	assert.Equal(t,
		"UTC - Etc/Custom",
		refTimezone(ptCtx, "Etc/Custom", "", "UTC", ""))
}

func TestReference_LocalizedRegionName(t *testing.T) {
	enCtx := localeCtx("en")
	ptCtx := localeCtx("pt-BR")

	assert.Equal(t, "United States", localizedRegionName(enCtx, "US", "fallback"))
	assert.Equal(t, "Estados Unidos", localizedRegionName(ptCtx, "US", "fallback"))
	// Unparseable code → fallback.
	assert.Equal(t, "fallback", localizedRegionName(ptCtx, "not-a-code", "fallback"))
	// Empty code → fallback (skips parse).
	assert.Equal(t, "fallback", localizedRegionName(ptCtx, "", "fallback"))
}

// The labels are in the language of the catalog the page was rendered from, not the first
// preference asked for: sv-SE has no catalog, so its page is English and names Germany "Germany",
// not "Tyskland"; nl-BE first and pt-BR third renders pt-BR, so its names are Portuguese, not
// Dutch (#645 decision 9).
func TestReference_LabelsFollowTheCatalogLanguage(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		tags                            []string
		country, phoneCountry, timezone string
	}{
		{"a first preference with no catalog", []string{"sv-SE"},
			"Germany", "🇩🇪 - Germany (+49)", "Germany - Europe/Berlin - most of Germany"},
		{"a supported German region", []string{"de-AT"},
			"Deutschland", "🇩🇪 - Deutschland (+49)", "Deutschland - Europe/Berlin - most of Germany"},
		{"a third preference with a catalog", []string{"nl-BE", "nl", "pt-BR"},
			"Alemanha", "🇩🇪 - Alemanha (+49)", "Alemanha - Europe/Berlin - most of Germany"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := localeCtx(tc.tags...)
			assert.Equal(t, tc.country, refCountry(ctx, "DE", "fallback"))
			assert.Equal(t, tc.phoneCountry, refPhoneCountry(ctx, "🇩🇪", "DE", "+49", "fallback"))
			assert.Equal(t, tc.timezone, refTimezone(ctx, "Europe/Berlin", "DE", "fallback", "most of Germany"))
		})
	}
}
