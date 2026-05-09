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

	// The English baseline ships "BR" → "Brazil" in countries.toml.
	englishCtx := attachLocale(context.Background(), defaultBundle.english, "en", false)
	assert.Equal(t, "Brazil", RefCountry(englishCtx, "BR", "fallback"))

	// Unknown locale (no bundle): English bundle is consulted, hits "BR".
	unknownCtx := attachLocale(context.Background(), defaultBundle.english, "xx", false)
	assert.Equal(t, "Brazil", RefCountry(unknownCtx, "BR", "fallback"))

	// Key absent from English bundle: fallback wins.
	assert.Equal(t, "fallback", RefCountry(englishCtx, "ZZ", "fallback"))

	// No context at all: still resolves via the English bundle.
	assert.Equal(t, "Brazil", RefCountry(context.Background(), "BR", "fallback"))
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
	assert.Equal(t, "Brazil (+55)", RefPhoneCountry(ctx, "BR", "fallback"))
	assert.Equal(t, "Eastern Time", RefTimezone(ctx, "America/New_York", "fallback"))
}
