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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/BurntSushi/toml"
	"github.com/leodip/goiabada/core/errs"
	"golang.org/x/text/language"
)

//go:embed catalogs/*.toml
var embeddedCatalogs embed.FS

type ctxKey int

const (
	ctxKeyLocalizer ctxKey = iota
	ctxKeyExplicitIntent
	ctxKeyLocaleTag
)

// message is one catalog entry. raw is the verbatim catalog string, which
// Raw() hands to the JS bootstrap; tmpl is the compiled template T() renders,
// present only for values carrying a "{{" placeholder.
type message struct {
	raw  string
	tmpl *template.Template
	// bad marks a value that looks templated but does not parse as one. The
	// JS bootstrap strings are the known case: their {{param}} placeholders
	// are substituted client-side by tFormat(), so text/template reads them
	// as calls to unknown functions. T() renders the key for those, which is
	// what it did before, and Raw() still returns raw verbatim (#273).
	bad bool
}

// Bundle holds every catalog, keyed by language tag, plus the matcher that
// turns a request's preferences into one of those tags.
type Bundle struct {
	// tags is English first, then catalogs in load order with override-only
	// locales last. The matcher indexes into it, so the two must stay aligned.
	tags     []language.Tag
	matcher  language.Matcher
	messages map[language.Tag]map[string]*message
	english  *Translator
}

// Translator renders keys against one resolved language tag, falling back to
// English. It is the type carried on the request context; Localizer(ctx)
// returns it.
type Translator struct {
	bundle *Bundle
	tag    language.Tag
}

// catalogFile is one parsed catalog awaiting the merge, in load order.
type catalogFile struct {
	tag      language.Tag
	messages map[string]string
}

// defaultBundle is set by LoadBundle and read by T/Localizer/EnglishFallback.
// Must not be reassigned after startup.
var defaultBundle *Bundle

// LoadBundle loads embedded catalogs, then merges runtime overrides from
// GOIABADA_I18N_OVERRIDES_DIR (if set). The returned bundle is also stashed
// as the package default so T() can be called without threading a bundle
// through every handler. Call exactly once at process startup.
func LoadBundle() (*Bundle, error) {
	files, err := loadEmbeddedCatalogs()
	if err != nil {
		return nil, err
	}

	if dir := strings.TrimSpace(os.Getenv("GOIABADA_I18N_OVERRIDES_DIR")); dir != "" {
		overrides, err := loadOverrideCatalogs(dir)
		if err != nil {
			return nil, err
		}
		files = append(files, overrides...)
	}

	b := &Bundle{messages: map[language.Tag]map[string]*message{}}
	fileTags := make([]language.Tag, 0, len(files))
	for _, f := range files {
		fileTags = append(fileTags, f.tag)
		locale := b.messages[f.tag]
		if locale == nil {
			locale = map[string]*message{}
			b.messages[f.tag] = locale
		}
		for k, v := range f.messages {
			// An empty value means "no translation here", so a later file
			// removes an earlier one's key rather than shadowing it with a
			// blank. The key then renders English, which is what a
			// self-hoster blanking a line in an override file is asking for
			// (#273).
			if v == "" {
				delete(locale, k)
				continue
			}
			locale[k] = &message{raw: v}
		}
	}
	// English leads the tag list because it is the source-of-truth catalog and
	// the matcher's answer when nothing else matches.
	b.tags = mergeTags([]language.Tag{language.English}, fileTags)
	b.matcher = language.NewMatcher(b.tags)
	b.english = &Translator{bundle: b, tag: language.English}
	compileTemplates(b)

	defaultBundle = b

	return b, nil
}

// compileTemplates parses every value carrying a "{{" placeholder, once, after
// the last file has been merged. The result is immutable for the process
// lifetime, so rendering needs no lock and no cache.
func compileTemplates(b *Bundle) {
	for _, locale := range b.messages {
		for key, m := range locale {
			if !strings.Contains(m.raw, "{{") {
				continue
			}
			tmpl, err := template.New(key).Option("missingkey=default").Parse(m.raw)
			if err != nil {
				m.bad = true
				continue
			}
			m.tmpl = tmpl
		}
	}
}

// parseCatalog reads one catalog file into a flat key->value map and derives
// its language tag from the file name ("active.pt-BR.toml" -> pt-BR).
//
// Catalog values are plain strings. A value of any other type — a [table]
// section in particular, which is how go-i18n used to spell plural forms —
// fails the whole load naming the file and the key, so the process does not
// start rendering one plural form for every count (#273).
//
// An empty value is returned as it stands: the merge in LoadBundle needs to
// see it to remove the key, and the catalog hygiene test needs to see it to
// forbid it in the embedded catalogs.
func parseCatalog(name string, data []byte) (language.Tag, map[string]string, error) {
	var parsed map[string]any
	if err := toml.Unmarshal(data, &parsed); err != nil {
		return language.Tag{}, nil, errs.Errorf("i18n: parse %s: %w", name, err)
	}
	out := make(map[string]string, len(parsed))
	for k, v := range parsed {
		s, ok := v.(string)
		if !ok {
			return language.Tag{}, nil, errs.Errorf(
				"i18n: %s: key %q is a %T, not a string; catalog values are plain strings and [table] sections are not supported",
				name, k, v)
		}
		out[k] = s
	}
	return language.Make(localeFromCatalogFile(filepath.Base(name))), out, nil
}

// localeFromCatalogFile maps "active.pt-BR.toml" -> "pt-BR", matching the
// tag string LocaleTag() carries on the request context.
func localeFromCatalogFile(name string) string {
	return strings.TrimSuffix(strings.TrimPrefix(name, "active."), ".toml")
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

func loadEmbeddedCatalogs() ([]catalogFile, error) {
	entries, err := fs.ReadDir(embeddedCatalogs, "catalogs")
	if err != nil {
		return nil, errs.Errorf("i18n: read embedded catalogs dir: %w", err)
	}
	var out []catalogFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		path := "catalogs/" + e.Name()
		data, err := fs.ReadFile(embeddedCatalogs, path)
		if err != nil {
			return nil, errs.Errorf("i18n: read %s: %w", path, err)
		}
		tag, messages, err := parseCatalog(path, data)
		if err != nil {
			return nil, err
		}
		out = append(out, catalogFile{tag: tag, messages: messages})
	}
	return out, nil
}

// SupportedTags returns the language tags loaded into the bundle, in
// registration order. Useful for tests and the locale picker.
func (b *Bundle) SupportedTags() []language.Tag {
	out := make([]language.Tag, len(b.tags))
	copy(out, b.tags)
	return out
}

// localizerFor builds a translator for the supplied preferences, each of which
// may be a full Accept-Language list. Every preference is parsed with
// language.ParseAcceptLanguage — which drops q=0 ranges and orders the rest by
// quality — unparseable ones are skipped, and the bundle's matcher picks one
// tag from what is left. RFC 9110 section 12.5.4 leaves the matching scheme to
// the implementation; this is the one go-i18n applied, kept verbatim.
func (b *Bundle) localizerFor(tags []string) *Translator {
	if len(tags) == 0 {
		return b.english
	}
	var parsed []language.Tag
	for _, s := range tags {
		ts, _, err := language.ParseAcceptLanguage(s)
		if err != nil {
			continue
		}
		parsed = append(parsed, ts...)
	}
	if len(parsed) == 0 {
		return b.english
	}
	_, idx, _ := b.matcher.Match(parsed...)
	return &Translator{bundle: b, tag: b.tags[idx]}
}

// lookup finds key in the translator's own locale, then in English. The
// English hop is what makes a locale that is missing a key render the English
// text rather than the key itself, as concepts/localization.mdx promises
// (#273).
func (l *Translator) lookup(key string) (*message, bool) {
	if l == nil || l.bundle == nil {
		return nil, false
	}
	if m, ok := l.bundle.messages[l.tag][key]; ok {
		return m, true
	}
	if l.tag != language.English {
		if m, ok := l.bundle.messages[language.English][key]; ok {
			return m, true
		}
	}
	return nil, false
}

// renderOrMiss renders key with data, reporting whether the key was found at
// all. A found-but-unrenderable message (one that failed to parse, or whose
// execution failed) renders the key, which is the visible-miss policy, but is
// still reported as found: English would render it no better.
func (l *Translator) renderOrMiss(key string, data map[string]any) (string, bool) {
	m, ok := l.lookup(key)
	if !ok {
		return "", false
	}
	if m.bad {
		return key, true
	}
	if m.tmpl == nil {
		return m.raw, true
	}
	var sb strings.Builder
	if err := m.tmpl.Execute(&sb, data); err != nil {
		return key, true
	}
	return sb.String(), true
}

func (l *Translator) render(key string, data map[string]any) string {
	out, ok := l.renderOrMiss(key, data)
	if !ok {
		return key
	}
	return out
}

// T translates key against the localizer carried on ctx, falling back to
// the English catalog when the key is missing in the resolved locale. If
// the key is missing in English too (programmer error), returns the key
// itself so the miss is visible during development.
//
// args[0], when present, must be a map[string]any holding template data
// for parameterized messages. Other arg shapes are silently ignored.
func T(ctx context.Context, key string, args ...any) string {
	var data map[string]any
	if len(args) > 0 {
		if td, ok := args[0].(map[string]any); ok {
			data = td
		}
	}
	return Localizer(ctx).render(key, data)
}

// LocaleTag returns the BCP 47 language tag attached to ctx by the locale
// middleware (or refinement helpers). Returns "en" when none is attached.
// Used by the CLDR-backed, locale-sensitive display helpers
// (RefCountry/RefPhoneCountry/RefTimezone) to pick the active locale.
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

// Localizer returns the *Translator attached to ctx by the locale
// middleware (or by the per-handler refinement helpers). Returns the
// bundle's English translator if none is attached (test contexts, background
// jobs that never went through middleware). Returns a translator over an
// empty bundle if LoadBundle has not been called — in that case every key
// resolves to itself.
func Localizer(ctx context.Context) *Translator {
	if ctx != nil {
		if v := ctx.Value(ctxKeyLocalizer); v != nil {
			if loc, ok := v.(*Translator); ok {
				return loc
			}
		}
	}
	if defaultBundle != nil {
		return defaultBundle.english
	}
	return &Translator{bundle: &Bundle{}, tag: language.English}
}
