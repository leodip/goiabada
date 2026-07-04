package i18n

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadCatalogFlat parses an embedded catalog TOML into a flat key->value map.
// The catalogs use quoted dotted keys (e.g. "auth.pwd.title"), which TOML
// treats as literal single keys, so a flat map[string]string is correct.
func loadCatalogFlat(t *testing.T, name string) map[string]string {
	t.Helper()
	data, err := embeddedCatalogs.ReadFile("catalogs/" + name)
	require.NoError(t, err, "reading %s", name)
	m := map[string]string{}
	require.NoError(t, toml.Unmarshal(data, &m), "parsing %s", name)
	require.NotEmpty(t, m, "%s parsed to zero keys", name)
	return m
}

// TestCatalog_NoEmptyValues guards against the "empty_prefix" class of bug:
// go-i18n drops a message whose value is "" and then reports it identically to
// a missing key, so T() falls back to the visible-miss policy and renders the
// raw key onto the page. An intentionally-empty slot can therefore never work.
func TestCatalog_NoEmptyValues(t *testing.T) {
	for _, name := range []string{"active.en.toml", "active.pt-BR.toml"} {
		for k, v := range loadCatalogFlat(t, name) {
			assert.NotEmptyf(t, v, "%s: key %q has an empty value; go-i18n treats it as missing and leaks the key in the UI", name, k)
		}
	}
}

// TestCatalog_ParityEnPtBR asserts the English source of truth and pt-BR
// translation have identical key sets. A key present in only one locale means
// either an untranslated string (leaks English or the raw key) or an orphan.
func TestCatalog_ParityEnPtBR(t *testing.T) {
	en := loadCatalogFlat(t, "active.en.toml")
	pt := loadCatalogFlat(t, "active.pt-BR.toml")

	for k := range en {
		_, ok := pt[k]
		assert.Truef(t, ok, "key %q is in active.en.toml but missing from active.pt-BR.toml", k)
	}
	for k := range pt {
		_, ok := en[k]
		assert.Truef(t, ok, "key %q is in active.pt-BR.toml but missing from active.en.toml (orphan)", k)
	}
}
