package i18n

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// rawCatalogs holds the un-templated catalog strings keyed by [locale][key].
//
// T() renders each message as a text/template, which is correct for
// server-side strings but wrong for the JS bootstrap: JS message templates use
// {{param}} placeholders substituted client-side by tFormat(), and running
// those through T() fails (text/template sees {{param}} as a call to an unknown
// function) and leaks the key into window.i18n. The bootstrap reads raw strings
// via Raw() instead, so the placeholders survive to the browser.
var rawCatalogs map[string]map[string]string

// localeFromCatalogFile maps "active.pt-BR.toml" -> "pt-BR", matching the
// tag string LocaleTag() carries on the request context.
func localeFromCatalogFile(name string) string {
	return strings.TrimSuffix(strings.TrimPrefix(name, "active."), ".toml")
}

func mergeRawCatalog(locale string, m map[string]string) {
	if rawCatalogs[locale] == nil {
		rawCatalogs[locale] = map[string]string{}
	}
	for k, v := range m {
		rawCatalogs[locale][k] = v
	}
}

// loadRawEmbeddedCatalogs parses the embedded catalog TOMLs into rawCatalogs.
func loadRawEmbeddedCatalogs() error {
	entries, err := fs.ReadDir(embeddedCatalogs, "catalogs")
	if err != nil {
		return fmt.Errorf("i18n: read embedded catalogs dir (raw): %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		data, err := fs.ReadFile(embeddedCatalogs, "catalogs/"+e.Name())
		if err != nil {
			return fmt.Errorf("i18n: read %s (raw): %w", e.Name(), err)
		}
		m := map[string]string{}
		if err := toml.Unmarshal(data, &m); err != nil {
			return fmt.Errorf("i18n: parse %s (raw): %w", e.Name(), err)
		}
		mergeRawCatalog(localeFromCatalogFile(e.Name()), m)
	}
	return nil
}

// loadRawOverrideCatalogs merges override catalog TOMLs over the embedded raw
// set (override wins), mirroring loadOverrideCatalogs. A missing catalogs/
// subdir is not an error.
func loadRawOverrideCatalogs(dir string) error {
	catalogsDir := filepath.Join(dir, "catalogs")
	entries, err := os.ReadDir(catalogsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("i18n: read override catalogs dir (raw): %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(catalogsDir, e.Name()))
		if err != nil {
			return fmt.Errorf("i18n: read override catalog %s (raw): %w", e.Name(), err)
		}
		m := map[string]string{}
		if err := toml.Unmarshal(data, &m); err != nil {
			return fmt.Errorf("i18n: parse override catalog %s (raw): %w", e.Name(), err)
		}
		mergeRawCatalog(localeFromCatalogFile(e.Name()), m)
	}
	return nil
}

// Raw returns the un-templated catalog string for key against the locale
// carried on ctx, falling back to English, then to the key itself. Unlike T()
// it does not execute the string as a template, so {{param}} placeholders are
// preserved for client-side substitution (used by the JS bootstrap).
func Raw(ctx context.Context, key string) string {
	tag := LocaleTag(ctx)
	if m, ok := rawCatalogs[tag]; ok {
		if v := m[key]; v != "" {
			return v
		}
	}
	if tag != "en" {
		if m, ok := rawCatalogs["en"]; ok {
			if v := m[key]; v != "" {
				return v
			}
		}
	}
	return key
}
