package web

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// A built-in language ships bodies for every English email as well as subjects.
// Read the source catalog roster without exporting core/i18n's embedded FS.
func TestEmails_EveryBuiltInLanguageHasEveryBody(t *testing.T) {
	catalogs, err := os.ReadDir(filepath.Join(guard.SourceRoot(t), "core", "i18n", "catalogs"))
	if err != nil {
		t.Fatal(err)
	}
	bodies, err := fs.Glob(templateFS, "template/emails/*.html")
	if err != nil {
		t.Fatal(err)
	}
	var english []string
	for _, body := range bodies {
		if strings.Count(filepath.Base(body), ".") == 1 {
			english = append(english, body)
		}
	}
	if len(english) == 0 {
		t.Fatal("no English emails found")
	}
	languages := 0
	for _, catalog := range catalogs {
		name := catalog.Name()
		if catalog.IsDir() || !strings.HasPrefix(name, "active.") || !strings.HasSuffix(name, ".toml") {
			continue
		}
		lang := strings.TrimSuffix(strings.TrimPrefix(name, "active."), ".toml")
		if lang == "en" {
			continue
		}
		languages++
		for _, body := range english {
			copy := strings.TrimSuffix(body, ".html") + "." + lang + ".html"
			if _, err := fs.Stat(templateFS, copy); err != nil {
				t.Errorf("catalog %s has no email body %s: %v", name, copy, err)
			}
		}
	}
	if languages == 0 {
		t.Fatal("no translated catalogs found")
	}
}
