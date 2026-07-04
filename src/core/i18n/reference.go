package i18n

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
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
// code.
//
// Lookup order:
//  1. Per-locale reference TOML hit on the alpha-2 code (a curated
//     override, e.g. one shipped via GOIABADA_I18N_OVERRIDES_DIR).
//  2. CLDR country name for the active locale, via
//     golang.org/x/text/language/display.
//  3. fallback (typically the existing English struct field) when the
//     code or active-locale tag is unparseable, or CLDR has no name.
//
// The English reference TOML is intentionally not consulted between (1)
// and (2): CLDR already carries English names, so an active-locale CLDR
// hit should win over a curated English override.
func RefCountry(ctx context.Context, alpha2, fallback string) string {
	if defaultReference != nil {
		if v := defaultReference.lookup(LocaleTag(ctx), "countries", alpha2); v != "" {
			return v
		}
	}
	return localizedRegionName(ctx, alpha2, fallback)
}

// RefPhoneCountry returns the localized phone-country label for an
// ISO 3166-1 alpha-2 code, in the format "<emoji> - <country> (<code>)".
//
// Lookup order:
//  1. Per-locale reference TOML hit on the alpha-2 code (a curated
//     override for the whole label).
//  2. Assembled "<emoji> - <country> (<callingCode>)" with the country
//     name rendered in the active locale via CLDR. The emoji and calling
//     code are locale-independent and passed through verbatim.
//  3. fallback (the pre-assembled English label) when the code or
//     active-locale tag is unparseable, or CLDR has no name.
func RefPhoneCountry(ctx context.Context, emoji, alpha2, callingCode, fallback string) string {
	if defaultReference != nil {
		if v := defaultReference.lookup(LocaleTag(ctx), "phone_countries", alpha2); v != "" {
			return v
		}
	}
	if name := localizedRegionName(ctx, alpha2, ""); name != "" {
		return emoji + " - " + name + " (" + callingCode + ")"
	}
	return fallback
}

// RefTimezone returns the localized timezone display label keyed by IANA
// zone ID (e.g. "Europe/Paris").
//
// Lookup order:
//  1. Per-locale reference TOML hit on zoneID (the "named" zones we curate).
//  2. English reference TOML hit on zoneID.
//  3. Assembled fallback "<country> - <zone>[ - <comments>]", with the
//     country name rendered in the active locale via CLDR
//     (golang.org/x/text/language/display). The zone identifier and IANA
//     comments stay in their original (English) form.
//
// countryCode is the ISO 3166-1 alpha-2 code from the timezones table;
// countryName is the English name kept as a final fallback when CLDR has
// no name for the active locale + region pair. comments may be empty.
func RefTimezone(ctx context.Context, zoneID, countryCode, countryName, comments string) string {
	if defaultReference != nil {
		tag := LocaleTag(ctx)
		if v := defaultReference.lookup(tag, "timezones", zoneID); v != "" {
			return v
		}
		if tag != "en" {
			if v := defaultReference.lookup("en", "timezones", zoneID); v != "" {
				return v
			}
		}
	}
	name := localizedRegionName(ctx, countryCode, countryName)
	out := name + " - " + zoneID
	if comments != "" {
		out += " - " + comments
	}
	return out
}

// localizedRegionName returns the country name for an ISO 3166-1 alpha-2
// region code rendered in the active locale, sourced from CLDR data
// bundled in golang.org/x/text/language/display.
//
// Falls back to the supplied fallback (typically the English country name
// from the static struct) if the code is unparseable, the active locale
// tag is unparseable, or CLDR has no name for the pair.
func localizedRegionName(ctx context.Context, alpha2, fallback string) string {
	if alpha2 == "" {
		return fallback
	}
	region, err := language.ParseRegion(alpha2)
	if err != nil {
		return fallback
	}
	tag, err := language.Parse(LocaleTag(ctx))
	if err != nil {
		return fallback
	}
	name := display.Regions(tag).Name(region)
	if name == "" {
		return fallback
	}
	return name
}
