// Package i18n is Goiabada's internationalization layer.
//
// At a high level:
//
//   - LoadBundle is called once at startup. It reads embedded message
//     catalogs and merges any runtime overrides from the directory named
//     by GOIABADA_I18N_OVERRIDES_DIR (override files win on conflict).
//   - MiddlewareLocale runs early in every request chain (before identity
//     is established) and attaches a tentative localizer based on
//     ?ui_locales, the in-flight AuthContext.UILocales (authserver only),
//     Accept-Language, then English.
//   - User-locale refinement runs once identity is known. Adminconsole
//     uses MiddlewareLocaleFromJWT (route-level, after JWT validation);
//     authserver uses the per-handler RefineLocalizerWithUser helper. Both
//     skip the refinement when the request carries explicit locale intent
//     (?ui_locales or AuthContext.UILocales).
//   - T and Localizer read the localizer off context.Context.
package i18n

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

//go:embed catalogs/*.toml
var embeddedCatalogs embed.FS

//go:embed reference/*/*.toml
var embeddedReferenceFS embed.FS

// EmbeddedReferenceFS exposes the embedded reference-data filesystem. It holds
// per-locale timezone display labels (`timezones.toml`); country and
// phone-country names are resolved at runtime from CLDR, not from this FS.
// Consumed by the reference-data loader that keys dropdowns off the active
// locale. This is embedded-only and not affected by GOIABADA_I18N_OVERRIDES_DIR.
func EmbeddedReferenceFS() fs.FS { return embeddedReferenceFS }

type ctxKey int

const (
	ctxKeyLocalizer ctxKey = iota
	ctxKeyExplicitIntent
	ctxKeyLocaleTag
)

// Bundle wraps go-i18n's bundle plus the precomputed English localizer
// used as the always-available fallback.
type Bundle struct {
	inner   *i18n.Bundle
	english *i18n.Localizer
	tags    []language.Tag
}

// defaultBundle is set by LoadBundle and read by T/Localizer/EnglishFallback.
// Must not be reassigned after startup.
var defaultBundle *Bundle

// LoadBundle loads embedded catalogs, then merges runtime overrides from
// GOIABADA_I18N_OVERRIDES_DIR (if set). The returned bundle is also stashed
// as the package default so T() can be called without threading a bundle
// through every handler. Call exactly once at process startup.
func LoadBundle() (*Bundle, error) {
	b := i18n.NewBundle(language.English)
	b.RegisterUnmarshalFunc("toml", toml.Unmarshal)

	tags, err := loadEmbeddedCatalogs(b)
	if err != nil {
		return nil, err
	}

	// Parallel raw (un-templated) copy of the catalogs for the JS bootstrap.
	rawCatalogs = map[string]map[string]string{}
	if err := loadRawEmbeddedCatalogs(); err != nil {
		return nil, err
	}

	if dir := strings.TrimSpace(os.Getenv("GOIABADA_I18N_OVERRIDES_DIR")); dir != "" {
		overrideTags, err := loadOverrideCatalogs(b, dir)
		if err != nil {
			return nil, err
		}
		tags = mergeTags(tags, overrideTags)
		if err := loadRawOverrideCatalogs(dir); err != nil {
			return nil, err
		}
	}

	bundle := &Bundle{
		inner:   b,
		english: i18n.NewLocalizer(b, language.English.String()),
		tags:    tags,
	}
	defaultBundle = bundle

	rd, err := loadReferenceData(embeddedReferenceFS)
	if err != nil {
		return nil, err
	}
	defaultReference = rd

	return bundle, nil
}

// mergeTags appends extras into base, dropping duplicates. Order is preserved
// (base order first, then any extras not already in base) so SupportedTags()
// returns embedded locales ahead of override-only ones.
func mergeTags(base, extras []language.Tag) []language.Tag {
	seen := make(map[string]struct{}, len(base)+len(extras))
	out := make([]language.Tag, 0, len(base)+len(extras))
	for _, t := range base {
		k := t.String()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, t)
	}
	for _, t := range extras {
		k := t.String()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, t)
	}
	return out
}

func loadEmbeddedCatalogs(b *i18n.Bundle) ([]language.Tag, error) {
	entries, err := fs.ReadDir(embeddedCatalogs, "catalogs")
	if err != nil {
		return nil, fmt.Errorf("i18n: read embedded catalogs dir: %w", err)
	}
	var tags []language.Tag
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		path := "catalogs/" + e.Name()
		data, err := fs.ReadFile(embeddedCatalogs, path)
		if err != nil {
			return nil, fmt.Errorf("i18n: read %s: %w", path, err)
		}
		mf, err := b.ParseMessageFileBytes(data, e.Name())
		if err != nil {
			return nil, fmt.Errorf("i18n: parse %s: %w", path, err)
		}
		if mf != nil {
			tags = append(tags, mf.Tag)
		}
	}
	return tags, nil
}

// SupportedTags returns the language tags loaded into the bundle, in
// registration order. Useful for tests and for the future locale picker.
func (b *Bundle) SupportedTags() []language.Tag {
	out := make([]language.Tag, len(b.tags))
	copy(out, b.tags)
	return out
}

// English returns the bundle's English localizer.
func (b *Bundle) English() *i18n.Localizer { return b.english }

// localizerFor builds a localizer that prefers the supplied tags, in order.
// go-i18n falls through to English (the bundle's default tag) if none match.
func (b *Bundle) localizerFor(tags []string) *i18n.Localizer {
	if len(tags) == 0 {
		return b.english
	}
	return i18n.NewLocalizer(b.inner, tags...)
}

// DefaultBundle returns the package-level bundle established by LoadBundle.
// Returns nil if LoadBundle has not yet run (tests, very early init).
func DefaultBundle() *Bundle { return defaultBundle }

// T translates key against the localizer carried on ctx, falling back to
// the English catalog when the key is missing in the resolved locale. If
// the key is missing in English too (programmer error), returns the key
// itself so the miss is visible during development.
//
// args[0], when present, must be a map[string]any holding template data
// for parameterized messages. Other arg shapes are silently ignored.
func T(ctx context.Context, key string, args ...any) string {
	loc := Localizer(ctx)
	cfg := &i18n.LocalizeConfig{MessageID: key}
	if len(args) > 0 {
		if td, ok := args[0].(map[string]any); ok {
			cfg.TemplateData = td
		}
	}
	out, err := loc.Localize(cfg)
	if err != nil {
		// Visible-miss: emit the key so the gap is obvious in dev.
		return key
	}
	return out
}

// LocaleTag returns the BCP 47 language tag attached to ctx by the locale
// middleware (or refinement helpers). Returns "en" when none is attached.
// Used by reference-data lookups (countries, timezones, phone countries)
// to find the per-locale translation file.
func LocaleTag(ctx context.Context) string {
	if ctx != nil {
		if v := ctx.Value(ctxKeyLocaleTag); v != nil {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return "en"
}

// Localizer returns the *i18n.Localizer attached to ctx by the locale
// middleware (or by the per-handler refinement helpers). Returns the
// bundle's English localizer if none is attached (test contexts, background
// jobs that never went through middleware). Returns a localizer over an
// empty bundle if LoadBundle has not been called — in that case every key
// resolves to itself.
func Localizer(ctx context.Context) *i18n.Localizer {
	if ctx != nil {
		if v := ctx.Value(ctxKeyLocalizer); v != nil {
			if loc, ok := v.(*i18n.Localizer); ok {
				return loc
			}
		}
	}
	if defaultBundle != nil {
		return defaultBundle.english
	}
	emptyBundle := i18n.NewBundle(language.English)
	return i18n.NewLocalizer(emptyBundle, language.English.String())
}
