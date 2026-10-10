package i18n

// The override examples on Customize and translate the pages, held to the catalogs (#522).
//
// The page shows the override catalogs a reader copies to add a language or reword one, each in a
// toml block titled with its path under GOIABADA_I18N_OVERRIDES_DIR. Each such block is written where its title says, loaded the way LoadBundle loads it, and must then show:
// every key is one the screens use, every value is what that locale renders, and a key the block
// leaves out renders the English text, which is the fallback the page promises.
//
// It reads files and loads catalogs into bundles it never installs, and nothing else.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"golang.org/x/text/language"
)

// The guide, relative to the repository root.
const customizeGuide = "site/src/content/docs/guides/customize-and-translate-the-pages.mdx"

// The override catalogs on Customize and translate the pages load as shown: each key is one the
// screens use, each value is what its locale renders, and a key left out renders English.
func TestGuideDocs_TheOverrideExamplesLoadAsShown(t *testing.T) {
	assertOverrideExamples(t, filepath.Dir(guard.SourceRoot(t)), customizeGuide)
}

func TestGuideDocs_AnOverrideExampleNamingAnUnknownKeyFails(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/translate.mdx", "## Add a language\n\n"+
		"```toml title=\"catalogs/active.es.toml\"\n"+
		"\"auth.pwd.title\" = \"Iniciar sesión\"\n"+
		"\"auth.pwd.no_such_key\" = \"Nada\"\n"+
		"```\n")

	report := guard.Run(func(r guard.Reporter) { assertOverrideExamples(r, root, "site/translate.mdx") })

	want := []string{`site/translate.mdx: catalogs/active.es.toml names "auth.pwd.no_such_key", which no screen uses`}
	if report.Stopped || !slices.Equal(report.Errors, want) {
		t.Errorf("failures %+v\nwant %q", report, want)
	}
}

func TestGuideDocs_AnOverrideExampleOutsideTheCatalogsDirectoryFails(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/translate.mdx", "## Add a language\n\n"+
		"```toml title=\"active.es.toml\"\n"+
		"\"auth.pwd.title\" = \"Iniciar sesión\"\n"+
		"```\n")

	report := guard.Run(func(r guard.Reporter) { assertOverrideExamples(r, root, "site/translate.mdx") })

	want := []string{`site/translate.mdx: active.es.toml renders "Sign in" for "auth.pwd.title" in es, not "Iniciar sesión"`}
	if report.Stopped || !slices.Equal(report.Errors, want) {
		t.Errorf("failures %+v\nwant %q", report, want)
	}
}

func TestGuideDocs_AnOverrideExampleLoadingAsShownPasses(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/translate.mdx", "## Add a language\n\n"+
		"```toml title=\"catalogs/active.es.toml\"\n"+
		"\"auth.pwd.title\" = \"Iniciar sesión\"\n"+
		"\"auth.pwd.button\" = \"Entrar\"\n"+
		"```\n\n## Change a few words\n\n"+
		"```toml title=\"catalogs/active.en.toml\"\n"+
		"\"auth.pwd.title\" = \"Welcome back\"\n"+
		"```\n")

	report := guard.Run(func(r guard.Reporter) { assertOverrideExamples(r, root, "site/translate.mdx") })

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("examples that load as shown were refused: %+v", report)
	}
}

func TestGuideDocs_AGuideWithNoOverrideExampleStops(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/translate.mdx", "## Add a language\n\n```toml\n\"auth.pwd.title\" = \"x\"\n```\n")

	report := guard.Run(func(r guard.Reporter) { assertOverrideExamples(r, root, "site/translate.mdx") })

	if !report.Stopped || !strings.Contains(report.Fatal, "no toml block titled with its path") {
		t.Errorf("a guide with no titled example did not stop the check: %+v", report)
	}
}

func TestGuideDocs_AMissingGuideStopsTheOverrideCheck(t *testing.T) {
	report := guard.Run(func(r guard.Reporter) { assertOverrideExamples(r, t.TempDir(), "site/translate.mdx") })

	if !report.Stopped || !strings.Contains(report.Fatal, "site/translate.mdx") {
		t.Errorf("a missing guide did not stop the check naming it: %+v", report)
	}
}

// overrideExample is one toml block titled with its path under the overrides directory.
type overrideExample struct {
	path    string
	content string
}

// assertOverrideExamples is the reporting half of the override check: each titled toml block on the
// page is loaded alone, as the only file in an overrides directory, and one failure is reported per
// key the screens never use, per value its locale does not render, and per locale in which a key the
// block leaves out does not render English. A stop for a page not read, or one with no such block.
func assertOverrideExamples(r guard.Reporter, root, page string) {
	r.Helper()
	examples, err := guideOverrideExamples(root, page)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	embedded, err := load("")
	if err != nil {
		r.Fatalf("loading the embedded catalogs: %v", err)
		return
	}
	english := embedded.messages[language.English]
	englishKeys := make([]string, 0, len(english))
	for key := range english {
		englishKeys = append(englishKeys, key)
	}
	slices.Sort(englishKeys)

	for _, example := range examples {
		dir, err := os.MkdirTemp("", "guide-overrides-")
		if err != nil {
			r.Fatalf("creating an overrides directory: %v", err)
			return
		}
		defer func() { _ = os.RemoveAll(dir) }()
		path := filepath.Join(dir, filepath.FromSlash(example.path))
		if mkdirErr := os.MkdirAll(filepath.Dir(path), 0o755); mkdirErr != nil {
			r.Fatalf("creating %s: %v", filepath.Dir(path), mkdirErr)
			return
		}
		if writeErr := os.WriteFile(path, []byte(example.content), 0o600); writeErr != nil {
			r.Fatalf("writing %s: %v", path, writeErr)
			return
		}

		_, values, err := parseCatalog(example.path, []byte(example.content))
		if err != nil {
			r.Errorf("%s: %s does not parse as a catalog: %v", page, example.path, err)
			continue
		}
		bundle, err := load(dir)
		if err != nil {
			r.Errorf("%s: %s does not load: %v", page, example.path, err)
			continue
		}
		locale := localeFromCatalogFile(filepath.Base(example.path))
		ctx := ctxForBundle(bundle, locale)

		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			if _, ok := english[key]; !ok {
				r.Errorf("%s: %s names %q, which no screen uses", page, example.path, key)
				continue
			}
			if got := T(ctx, key); got != values[key] {
				r.Errorf("%s: %s renders %q for %q in %s, not %q", page, example.path, got, key, locale, values[key])
			}
		}

		for _, key := range englishKeys {
			message := english[key]
			if _, shown := values[key]; shown || strings.Contains(message.raw, "{{") {
				continue
			}
			if _, translated := embedded.messages[language.Make(locale)][key]; translated {
				continue
			}
			if got := T(ctx, key); got != message.raw {
				r.Errorf("%s: %s leaves %q out, which renders %q in %s rather than the English %q",
					page, example.path, key, got, locale, message.raw)
			}
			break
		}
	}
}

// overrideFence is the opening line of a toml block titled with its path.
var overrideFence = regexp.MustCompile("^```toml title=\"([^\"]+)\"$")

// guideOverrideExamples is every toml block on the page whose fence is titled with a path.
func guideOverrideExamples(root, page string) ([]overrideExample, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(page)))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", page, err)
	}
	var examples []overrideExample
	var current *overrideExample
	var block []string
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case current != nil && strings.HasPrefix(trimmed, "```"):
			current.content = strings.Join(block, "\n") + "\n"
			examples = append(examples, *current)
			current, block = nil, nil
		case current != nil:
			block = append(block, trimmed)
		default:
			if match := overrideFence.FindStringSubmatch(trimmed); match != nil {
				current = &overrideExample{path: match[1]}
			}
		}
	}
	if len(examples) == 0 {
		return nil, fmt.Errorf("%s has no toml block titled with its path", page)
	}
	return examples, nil
}

func writeGuideFixture(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
