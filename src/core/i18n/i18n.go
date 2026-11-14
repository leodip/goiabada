// Package i18n is Goiabada's internationalization layer.
//
// At a high level:
//
//   - The message catalogs built into Goiabada are its only ones, served
//     without any setup: they are built once, on first use, so a server, a
//     test or a tool renders any built-in language with no call to make first.
//   - Locale runs early in every request chain (before identity
//     is established) and attaches a tentative localizer based on
//     ?ui_locales, in-flight UI locales (authserver only),
//     Accept-Language, then English.
//   - WithLocale refines the locale a request asks for, and which refinement a
//     process wants is its own: authserver applies an RP's ui_locales, and a
//     registration email the page it was asked for from.
//     A non-explicit call defers to explicit intent already on the context.
//   - WithPageLanguage attaches a user's page language, the catalog they chose
//     for Goiabada's own pages. It wins over every source above, and no later
//     WithLocale call moves it; a tag naming no built-in catalog (CatalogTags,
//     IsCatalogTag) is Automatic, the language the request asks for, which also
//     replaces an earlier user's choice. Each server applies it in a page-language
//     middleware of its own: authserver from the known user's row, adminconsole
//     from its session's copy of the signed-in user's choice.
//   - WithRecipientLanguage attaches the language of an email to a user: their
//     page language, else their locale, else English, over whatever the
//     sending request carries.
//   - T reads the localizer off context.Context.
package i18n

import (
	"context"
	"embed"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
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
	ctxKeyPageLanguage
	ctxKeyRequestLanguage
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

// bundle holds every catalog, keyed by language tag, plus the matcher that
// turns a request's preferences into one of those tags.
type bundle struct {
	// tags is English first, then the other catalogs in file-name order. The
	// matcher indexes into it, so the two must stay aligned.
	tags     []language.Tag
	matcher  language.Matcher
	messages map[language.Tag]map[string]*message
	english  *translator
}

// translator renders keys against one resolved language tag, falling back to
// English. It is the type carried on the request context; localizer(ctx)
// returns it.
type translator struct {
	bundle *bundle
	tag    language.Tag
}

// catalogFile is one parsed catalog, ready to build a bundle from.
type catalogFile struct {
	tag      language.Tag
	messages map[string]string
}

// builtIn is the bundle every rendering surface reads: the catalogs built into
// Goiabada, built once, on first use. Nothing replaces it, so a test or a tool
// renders any built-in language with no call to make first (#431).
var builtIn = sync.OnceValue(func() *bundle {
	return orEmpty(load())
})

// orEmpty is load's answer for the built-in bundle, which has no caller to
// return an error to. A failure there means a catalog compiled into the binary
// does not parse, which catalog_hygiene_test.go exists to stop before it ships.
// Should it happen anyway, every key renders as itself, the visible-miss policy,
// rather than the process refusing to render at all.
func orEmpty(b *bundle, err error) *bundle {
	if err != nil {
		slog.Error("unable to load the embedded message catalogs, so every key renders as itself", "error", err)
		return build(nil)
	}
	return b
}

// load builds a bundle from the embedded catalogs, touching nothing global. It is
// what the built-in bundle is built from.
func load() (*bundle, error) {
	files, err := loadEmbeddedCatalogs()
	if err != nil {
		return nil, err
	}
	return build(files), nil
}

// build makes a bundle of files, one catalog per language. With no files it
// answers a bundle holding no message, whose matcher still answers English:
// orEmpty's fallback.
func build(files []catalogFile) *bundle {
	b := &bundle{messages: map[language.Tag]map[string]*message{}}
	// English leads the tag list because it is the source-of-truth catalog and
	// the matcher's answer when nothing else matches.
	b.tags = []language.Tag{language.English}
	for _, f := range files {
		if f.tag != language.English {
			b.tags = append(b.tags, f.tag)
		}
		locale := make(map[string]*message, len(f.messages))
		for k, v := range f.messages {
			locale[k] = &message{raw: v}
		}
		b.messages[f.tag] = locale
	}
	b.matcher = language.NewMatcher(b.tags)
	b.english = &translator{bundle: b, tag: language.English}
	compileTemplates(b)

	return b
}

// compileTemplates parses every value carrying a "{{" placeholder, once, after
// the bundle is built. The result is immutable for the process
// lifetime, so rendering needs no lock and no cache.
func compileTemplates(b *bundle) {
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
// An empty value is returned as it stands, so the catalog hygiene test can
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

// localizerFor builds a translator for the supplied preferences, each of which
// may be a full Accept-Language list. Every preference is parsed with
// language.ParseAcceptLanguage — which drops q=0 ranges and orders the rest by
// quality — unparseable ones are skipped, and the bundle's matcher picks one
// tag from what is left, followed by English. That final preference prevents
// a guessed match to a different language (gl or eu to es, for example) from
// winning over English, while regional variants still match their language
// and an explicitly listed second language still wins (#658).
// RFC 9110 section 12.5.4 leaves the matching scheme to the implementation.
func (b *bundle) localizerFor(tags []string) *translator {
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
	_, idx, _ := b.matcher.Match(append(parsed, language.English)...)
	return &translator{bundle: b, tag: b.tags[idx]}
}

// lookup finds key in the translator's own locale, then in English. The
// English hop is what makes a locale that is missing a key render the English
// text rather than the key itself (#273).
func (l *translator) lookup(key string) (*message, bool) {
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
func (l *translator) renderOrMiss(key string, data map[string]any) (string, bool) {
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

func (l *translator) render(key string, data map[string]any) string {
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
	return localizer(ctx).render(key, data)
}

// LocaleTag returns the BCP 47 language tag attached to ctx by the locale
// middleware (or refinement helpers). Returns "en" when none is attached.
// It is the first preference asked for, whether or not a catalog matches it,
// which is what an email's language is chosen from, matched against the
// languages its text is written in (#531, #818). What marks a page's language
// and the admin console's CLDR labels read CatalogTag instead (#645).
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

// CatalogTag returns the language tag of the built-in catalog T renders from on ctx. Returns "en"
// when no localizer is attached, which is the catalog T then renders from.
//
// It differs from LocaleTag, which answers the first preference asked for whether or not any
// catalog matches it: "nl-BE,nl;q=0.9,pt-BR;q=0.8" renders in pt-BR, and LocaleTag answers nl-BE.
// Both servers mark a page's <html lang> with it, since it names the language the page is written
// in, and the admin console names its CLDR country labels in it (#645 decisions 8 and 9).
// The admin console sends this tag as Accept-Language on every admin API call, so the auth server
// answers a refusal in the language the console's page is rendered in; the value is always one of
// the built-in catalogs' tags, never text the browser sent (#559 decision 3).
func CatalogTag(ctx context.Context) string {
	return localizer(ctx).tag.String()
}

// localizer returns the translator attached to ctx by the locale middleware
// (or by the per-handler refinement helpers), or the built-in bundle's English
// translator if none is attached (test contexts, background jobs that never went
// through middleware).
func localizer(ctx context.Context) *translator {
	if ctx != nil {
		if v := ctx.Value(ctxKeyLocalizer); v != nil {
			if loc, ok := v.(*translator); ok {
				return loc
			}
		}
	}
	return builtIn().english
}
