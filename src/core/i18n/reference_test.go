package i18n

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReference_FallbackChain(t *testing.T) {
	if _, err := LoadBundle(); err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}

	// "BR" resolves via CLDR for the active (English) locale (no country TOML ships).
	englishCtx := attachLocale(context.Background(), defaultBundle.english, "en", false)
	assert.Equal(t, "Brazil", RefCountry(englishCtx, "BR", "fallback"))

	// Uncurated but valid code: resolved via CLDR for the active locale.
	assert.Equal(t, "Italy", RefCountry(englishCtx, "IT", "fallback"))

	// Unparseable locale tag: CLDR can't resolve, fallback wins.
	unknownCtx := attachLocale(context.Background(), defaultBundle.english, "xx", false)
	assert.Equal(t, "fallback", RefCountry(unknownCtx, "BR", "fallback"))

	// Unparseable country code: fallback wins.
	assert.Equal(t, "fallback", RefCountry(englishCtx, "not-a-code", "fallback"))

	// No context at all: defaults to the English CLDR name.
	assert.Equal(t, "Brazil", RefCountry(context.Background(), "BR", "fallback"))
}

func TestReference_CountryCLDR(t *testing.T) {
	if _, err := LoadBundle(); err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	ptCtx := attachLocale(context.Background(), defaultBundle.english, "pt-BR", false)

	// "BR" resolves via CLDR in pt-BR (no country TOML ships).
	assert.Equal(t, "Brasil", RefCountry(ptCtx, "BR", "Brazil"))
	// Other codes resolve via CLDR in pt-BR.
	assert.Equal(t, "Itália", RefCountry(ptCtx, "IT", "Italy"))
	assert.Equal(t, "México", RefCountry(ptCtx, "MX", "Mexico"))
	assert.Equal(t, "Espanha", RefCountry(ptCtx, "ES", "Spain"))
}

func TestReference_PhoneCountryAssembly(t *testing.T) {
	if _, err := LoadBundle(); err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	ptCtx := attachLocale(context.Background(), defaultBundle.english, "pt-BR", false)

	// Assembled from emoji + CLDR-localized name + calling code (no phone-country
	// TOML ships), which reproduces the previously-curated pt-BR label exactly.
	assert.Equal(t, "🇧🇷 - Brasil (+55)", RefPhoneCountry(ptCtx, "🇧🇷", "BR", "+55", "fallback"))

	// Same assembly path for any other code: emoji + CLDR name + calling code;
	// emoji and calling code pass through untouched.
	assert.Equal(t, "🇮🇹 - Itália (+39)", RefPhoneCountry(ptCtx, "🇮🇹", "IT", "+39", "🇮🇹 - Italy (+39)"))

	// Unparseable code: the pre-assembled English fallback label wins.
	assert.Equal(t, "🏳 - Nowhere (+0)", RefPhoneCountry(ptCtx, "🏳", "not-a-code", "+0", "🏳 - Nowhere (+0)"))
}

func TestReference_LocaleTagFromContext(t *testing.T) {
	assert.Equal(t, "en", LocaleTag(context.Background()))
	ctx := attachLocale(context.Background(), nil, "pt-BR", false)
	assert.Equal(t, "pt-BR", LocaleTag(ctx))
	ctx2 := attachLocale(context.Background(), nil, "en-US,en;q=0.9", false)
	// primaryTag splits on comma/semicolon.
	assert.Equal(t, "en-US", LocaleTag(ctx2))
}

func TestReference_PerKindHelpers(t *testing.T) {
	if _, err := LoadBundle(); err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	ctx := attachLocale(context.Background(), defaultBundle.english, "en", false)
	assert.Equal(t, "🇧🇷 - Brazil (+55)", RefPhoneCountry(ctx, "🇧🇷", "BR", "+55", "fallback"))
	// Assembled label: CLDR country + IANA zone + comment (no curated TOML anymore).
	assert.Equal(t, "United States - America/New_York - Eastern (most areas)",
		RefTimezone(ctx, "America/New_York", "US", "United States", "Eastern (most areas)"))
}

func TestReference_TimezoneFallbackAssembly(t *testing.T) {
	if _, err := LoadBundle(); err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}

	// Zone absent from both TOMLs: assembled "<country> - <zone>[ - <comments>]".
	englishCtx := attachLocale(context.Background(), defaultBundle.english, "en", false)
	assert.Equal(t,
		"Japan - Asia/Tokyo",
		RefTimezone(englishCtx, "Asia/Tokyo", "JP", "Japan", ""))
	assert.Equal(t,
		"Antarctica - Antarctica/Casey - Casey",
		RefTimezone(englishCtx, "Antarctica/Casey", "AQ", "Antarctica", "Casey"))

	// pt-BR: country name is localized via CLDR, zone + comment stay in English.
	ptCtx := attachLocale(context.Background(), defaultBundle.english, "pt-BR", false)
	assert.Equal(t,
		"Japão - Asia/Tokyo",
		RefTimezone(ptCtx, "Asia/Tokyo", "JP", "Japan", ""))
	assert.Equal(t,
		"Estados Unidos - America/Los_Angeles - Pacific",
		RefTimezone(ptCtx, "America/Los_Angeles", "US", "United States", "Pacific"))

	// Empty country code: falls back to the supplied English name.
	assert.Equal(t,
		"UTC - Etc/Custom",
		RefTimezone(ptCtx, "Etc/Custom", "", "UTC", ""))
}

func TestReference_LocalizedRegionName(t *testing.T) {
	enCtx := attachLocale(context.Background(), nil, "en", false)
	ptCtx := attachLocale(context.Background(), nil, "pt-BR", false)

	assert.Equal(t, "United States", localizedRegionName(enCtx, "US", "fallback"))
	assert.Equal(t, "Estados Unidos", localizedRegionName(ptCtx, "US", "fallback"))
	// Unparseable code → fallback.
	assert.Equal(t, "fallback", localizedRegionName(ptCtx, "not-a-code", "fallback"))
	// Empty code → fallback (skips parse).
	assert.Equal(t, "fallback", localizedRegionName(ptCtx, "", "fallback"))
}
