package web

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// thirdPartyAsset matches a script or stylesheet loaded from another origin: an absolute or
// protocol-relative URL in a script's src or a link's href. Each page's assets are served from
// /static, the vendored libraries among them, so no page makes a third-party request (#542).
var thirdPartyAsset = regexp.MustCompile(`(?i)<(script|link)\b[^>]*\b(src|href)\s*=\s*["']?\s*(https?:)?//`)

func TestTemplates_LoadNoScriptOrStylesheetFromAnotherOrigin(t *testing.T) {
	checked := 0
	err := fs.WalkDir(templateFS, "template", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		content, err := templateFS.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		for _, m := range thirdPartyAsset.FindAllString(string(content), -1) {
			t.Errorf("%s loads %q from another origin; vendor it under static and pin it in versions.yaml", path, m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no template was read")
	}
}

// catalogClass is a class attribute inside a catalog message, in either quote style.
var catalogClass = regexp.MustCompile(`class=\\?['"]([^'"\\]+)`)

// Every class the i18n catalogs write into message HTML is in the served main.css. Tailwind reads
// the templates and static scripts only, so a class used nowhere else would be built out of the
// stylesheet: input.css lists the catalogs' classes inline, and this fails when a catalog adds one
// it leaves out (#542).
func TestMainCSS_HoldsEveryClassTheCatalogsWrite(t *testing.T) {
	css, err := staticFS.ReadFile("static/main.css")
	if err != nil {
		t.Fatal(err)
	}
	catalogs, err := filepath.Glob("../../core/i18n/catalogs/*.toml")
	if err != nil || len(catalogs) == 0 {
		t.Fatalf("no catalog found: %v", err)
	}
	classes := map[string]bool{}
	for _, catalog := range catalogs {
		content, err := os.ReadFile(catalog)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range catalogClass.FindAllStringSubmatch(string(content), -1) {
			for _, class := range strings.Fields(m[1]) {
				classes[class] = true
			}
		}
	}
	if len(classes) == 0 {
		t.Fatal("the catalogs write no class, so this test reads nothing")
	}
	for class := range classes {
		if !regexp.MustCompile(`\.` + regexp.QuoteMeta(class) + `\b`).Match(css) {
			t.Errorf("a catalog writes class %q, which main.css lacks: add it to input.css's @source inline and rebuild", class)
		}
	}
}
