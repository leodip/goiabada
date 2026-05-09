package i18n

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	"github.com/BurntSushi/toml"
)

// ReferenceData is the per-locale reference-data store: country names,
// timezone display labels, phone-country labels, and so on. It is loaded
// from `reference/<locale>/<kind>.toml` files at startup and consulted by
// template helpers (RefCountry, RefPhoneCountry, RefTimezone) to render
// dropdowns in the active locale, with English fallback.
type ReferenceData struct {
	// bundles[locale][kind][key] = label
	bundles map[string]map[string]map[string]string
}

// defaultReference is set by LoadBundle and read by Reference and the
// per-kind template helpers. Must not be reassigned after startup.
var defaultReference *ReferenceData

// loadReferenceData scans the embedded `reference/` filesystem and builds
// a per-locale lookup table. Each subdirectory under `reference/` is a
// language tag (`en`, `pt-BR`, ...); each `<kind>.toml` file inside is a
// flat key-value map.
func loadReferenceData(fsys fs.FS) (*ReferenceData, error) {
	rd := &ReferenceData{bundles: map[string]map[string]map[string]string{}}
	entries, err := fs.ReadDir(fsys, "reference")
	if err != nil {
		return nil, fmt.Errorf("i18n: read reference dir: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		locale := e.Name()
		rd.bundles[locale] = map[string]map[string]string{}
		files, err := fs.ReadDir(fsys, "reference/"+locale)
		if err != nil {
			return nil, fmt.Errorf("i18n: read reference/%s: %w", locale, err)
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".toml") {
				continue
			}
			kind := strings.TrimSuffix(f.Name(), ".toml")
			data, err := fs.ReadFile(fsys, "reference/"+locale+"/"+f.Name())
			if err != nil {
				return nil, fmt.Errorf("i18n: read reference/%s/%s: %w", locale, f.Name(), err)
			}
			var m map[string]string
			if err := toml.Unmarshal(data, &m); err != nil {
				return nil, fmt.Errorf("i18n: parse reference/%s/%s: %w", locale, f.Name(), err)
			}
			rd.bundles[locale][kind] = m
		}
	}
	return rd, nil
}

// Reference returns the localized label for (kind, key) against the locale
// carried on ctx. Falls through to English if the active-locale bundle
// lacks the key, then to fallback if English lacks it too.
//
// Visible-miss policy: if both locale-specific and English bundles are
// silent, fallback wins. Templates pass the existing English struct field
// (e.g. country.Name) as fallback so the UI keeps working in English even
// without per-locale TOML files.
func Reference(ctx context.Context, kind, key, fallback string) string {
	if defaultReference == nil {
		return fallback
	}
	tag := LocaleTag(ctx)
	if v := defaultReference.lookup(tag, kind, key); v != "" {
		return v
	}
	if tag != "en" {
		if v := defaultReference.lookup("en", kind, key); v != "" {
			return v
		}
	}
	return fallback
}

func (rd *ReferenceData) lookup(locale, kind, key string) string {
	bundle, ok := rd.bundles[locale]
	if !ok {
		return ""
	}
	kindMap, ok := bundle[kind]
	if !ok {
		return ""
	}
	return kindMap[key]
}

// RefCountry returns the localized country name for an ISO 3166-1 alpha-2
// code, with English fallback to fallback (typically the existing
// English struct field).
func RefCountry(ctx context.Context, alpha2, fallback string) string {
	return Reference(ctx, "countries", alpha2, fallback)
}

// RefPhoneCountry returns the localized phone-country label keyed by
// ISO 3166-1 alpha-2.
func RefPhoneCountry(ctx context.Context, alpha2, fallback string) string {
	return Reference(ctx, "phone_countries", alpha2, fallback)
}

// RefTimezone returns the localized timezone display label keyed by IANA
// zone ID (e.g. "Europe/Paris").
func RefTimezone(ctx context.Context, zoneID, fallback string) string {
	return Reference(ctx, "timezones", zoneID, fallback)
}
