package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// titleDefineRe matches a {{define "title"}} ... {{end}} block (across lines).
var titleDefineRe = regexp.MustCompile(`(?s)\{\{\s*define\s+"title"\s*\}\}(.*?)\{\{\s*end\s*\}\}`)

func walkHTMLTemplates(t *testing.T, fn func(path, content string)) {
	t.Helper()
	err := fs.WalkDir(templateFS, "template", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".html") {
			return nil
		}
		b, rErr := fs.ReadFile(templateFS, p)
		if rErr != nil {
			return rErr
		}
		fn(p, string(b))
		return nil
	})
	if err != nil {
		t.Fatalf("walking templates: %v", err)
	}
}

// TestTemplates_NoHTMLInTitle guards the admin_users_* bug: the {{define "title"}}
// block feeds the HTML <title> element, which renders tags literally, so any
// markup there shows up as raw text in the browser tab.
func TestTemplates_NoHTMLInTitle(t *testing.T) {
	walkHTMLTemplates(t, func(path, content string) {
		for _, m := range titleDefineRe.FindAllStringSubmatch(content, -1) {
			if strings.Contains(m[1], "<") {
				t.Errorf("%s: {{define \"title\"}} contains HTML (renders literally in <title>): %q",
					path, strings.TrimSpace(m[1]))
			}
		}
	})
}

// TestTemplates_HtmlLangNotHardcoded guards the <html lang="en"> bug: page
// layouts must render the lang attribute from the active locale so the document
// advertises the language it renders in. Email layouts are exempt (emails are
// per-locale sibling files, not context-driven).
func TestTemplates_HtmlLangNotHardcoded(t *testing.T) {
	walkHTMLTemplates(t, func(path, content string) {
		if !strings.Contains(path, "layouts/") || strings.Contains(path, "email") {
			return
		}
		if strings.Contains(content, `<html lang="en"`) {
			t.Errorf(`%s: <html lang="en"> is hardcoded; use lang="{{ Lang $.ctx }}"`, path)
		}
	})
}
