// Package i18n is Goiabada's internationalization layer.
//
// At a high level:
//
//   - The embedded message catalogs are served without any setup: they are
//     built once, on first use, so a test or a tool renders English and
//     pt-BR with no call to make first.
//   - LoadBundle is called once by each main, with the overrides directory its
//     configuration read. It merges that directory's catalogs over the embedded
//     ones (override files win on conflict) and refuses a catalog that does not
//     parse, so a broken override stops the server at startup. The package
//     reads no environment variable itself (#431).
//   - MiddlewareLocale runs early in every request chain (before identity
//     is established) and attaches a tentative localizer based on
//     ?ui_locales, in-flight UI locales (authserver only),
//     Accept-Language, then English.
//   - WithLocale is the one locale-setting primitive, and which refinement a
//     process wants is its own: adminconsole from the JWT locale claim,
//     authserver from the user's stored locale, both from an RP's ui_locales.
//     A non-explicit call defers to explicit intent already on the context.
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
	"sync/atomic"
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

// bundle holds every catalog, keyed by language tag, plus the matcher that
// turns a request's preferences into one of those tags.
type bundle struct {
	// tags is English first, then catalogs in load order with override-only
	// locales last. The matcher indexes into it, so the two must stay aligned.
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

// catalogFile is one parsed catalog awaiting the merge, in load order.
type catalogFile struct {
	tag      language.Tag
	messages map[string]string
}

// embedded is the bundle a process serves until its main calls LoadBundle, and
// the only one a test or a tool ever needs: the embedded catalogs, built once on
// first use. It replaced a package variable that stayed nil until LoadBundle ran,
// which made every package whose tests read a rendered sentence carry a TestMain
// whose only job was to load it (#431).
var embedded = sync.OnceValue(func() *bundle {
	return orEmpty(load(""))
})

// installed is the bundle main installed through LoadBundle: the embedded
// catalogs with the operator's overrides merged over them. Nil until then. It is
// an atomic pointer rather than a plain variable so that installing is safe
// against a reader on another goroutine whatever the order: main installs before
// it serves, but a test installing while a parallel test renders would otherwise
// be a data race the race tier reports (#431).
var installed atomic.Pointer[bundle]

// current is the bundle every rendering surface reads: what main installed, or
// else the embedded default.
func current() *bundle {
	if b := installed.Load(); b != nil {
		return b
	}
	return embedded()
}

// orEmpty is load's answer for the embedded default, which has no caller to
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

// LoadBundle builds the embedded catalogs with the overrides under
// overridesDir merged over them, and installs the result as the bundle every
// rendering surface reads. An empty overridesDir means the embedded catalogs
// alone.
//
// Each main calls it once, at startup, with the directory its own configuration
// read from GOIABADA_I18N_OVERRIDES_DIR, and stops on the error: a catalog that
// does not parse is a configuration bug the operator has to see. On an error
// nothing is installed, so whatever was served before is served still.
func LoadBundle(overridesDir string) error {
	b, err := load(overridesDir)
	if err != nil {
		return err
	}
	installed.Store(b)
	return nil
}

// load builds a bundle from the embedded catalogs and, when dir is not empty,
// the override catalogs under it, touching nothing global. It is what
// LoadBundle installs and what the embedded default is built from, and what the
// override tests call without installing anything.
func load(dir string) (*bundle, error) {
	files, err := loadEmbeddedCatalogs()
	if err != nil {
		return nil, err
	}

	if dir != "" {
		overrides, err := loadOverrideCatalogs(dir)
		if err != nil {
			return nil, err
		}
		files = append(files, overrides...)
	}

	return build(files), nil
}

// build merges files, in order, into a bundle. With no files it answers a bundle
// holding no message, whose matcher still answers English: orEmpty's fallback.
func build(files []catalogFile) *bundle {
	b := &bundle{messages: map[language.Tag]map[string]*message{}}
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
	b.english = &translator{bundle: b, tag: language.English}
	compileTemplates(b)

	return b
}

// compileTemplates parses every value carrying a "{{" placeholder, once, after
// the last file has been merged. The result is immutable for the process
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
// An empty value is returned as it stands: the merge in build needs to
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
// (base order first, then any extras not already in base) so a bundle's tags
// list embedded locales ahead of override-only ones.
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

// localizerFor builds a translator for the supplied preferences, each of which
// may be a full Accept-Language list. Every preference is parsed with
// language.ParseAcceptLanguage — which drops q=0 ranges and orders the rest by
// quality — unparseable ones are skipped, and the bundle's matcher picks one
// tag from what is left. RFC 9110 section 12.5.4 leaves the matching scheme to
// the implementation; this is the one go-i18n applied, kept verbatim.
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
	_, idx, _ := b.matcher.Match(parsed...)
	return &translator{bundle: b, tag: b.tags[idx]}
}

// lookup finds key in the translator's own locale, then in English. The
// English hop is what makes a locale that is missing a key render the English
// text rather than the key itself, as concepts/localization.mdx promises
// (#273).
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

// localizer returns the translator attached to ctx by the locale middleware
// (or by the per-handler refinement helpers), or the current bundle's English
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
	return current().english
}
