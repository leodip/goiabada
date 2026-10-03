package handlerhelpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLocaleLabel(t *testing.T) {
	// Base language + explicit region: native name gains the region endonym,
	// English name kept in parentheses.
	assert.Equal(t, "português (Brasil) (Portuguese (Brazil))", localeLabel("pt-BR", "Portuguese (Brazil)"))
	assert.Equal(t, "العربية (مصر) (Arabic (Egypt))", localeLabel("ar-EG", "Arabic (Egypt)"))
	assert.Equal(t, "Afrikaans (Suid-Afrika) (Afrikaans (South Africa))", localeLabel("af-ZA", "Afrikaans (South Africa)"))

	// Specialized endonyms are used verbatim (region already folded in).
	assert.Equal(t, "American English (English (United States))", localeLabel("en-US", "English (United States)"))
	assert.Equal(t, "português europeu (Portuguese (Portugal))", localeLabel("pt-PT", "Portuguese (Portugal)"))
	assert.Equal(t, "español latinoamericano (Spanish (Latin America))", localeLabel("es-419", "Spanish (Latin America)"))

	// Bare language (no explicit region): native name only, no invented region.
	assert.Equal(t, "português (Portuguese)", localeLabel("pt", "Portuguese"))
	assert.Equal(t, "日本語 (Japanese)", localeLabel("ja", "Japanese"))

	// Native == English: no redundant "English (English)".
	assert.Equal(t, "English", localeLabel("en", "English"))

	// Unparseable id: fall back to the English name alone.
	assert.Equal(t, "Klingon", localeLabel("not-a-locale", "Klingon"))
}
