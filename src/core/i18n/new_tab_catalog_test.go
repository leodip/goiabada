package i18n

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A link that opens a new tab says so to assistive technology in built-in text, in every built-in
// language (#814 decision 13). The text is read after the link's own, as part of its name.
func TestCatalog_NewTabNoticeInEveryBuiltInLanguage(t *testing.T) {
	want := map[string]string{
		"active.en.toml":    "(opens in a new tab)",
		"active.pt-BR.toml": "(abre em uma nova aba)",
		"active.es.toml":    "(se abre en una pestaña nueva)",
		"active.fr.toml":    "(s’ouvre dans un nouvel onglet)",
		"active.it.toml":    "(si apre in una nuova scheda)",
		"active.de.toml":    "(öffnet sich in einem neuen Tab)",
	}
	assert.ElementsMatch(t, catalogNames(t), keysOf(want), "every built-in catalog has its expected text")
	for name, value := range want {
		assert.Equalf(t, value, loadCatalogFlat(t, name)["common.link.opens_in_new_tab"], "%s: %q", name, "common.link.opens_in_new_tab")
	}
}

func keysOf(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
