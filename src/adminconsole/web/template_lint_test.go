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

// TestTemplates_RedirectURIAndWebOriginCellsAreText guards the issue #105 sink: the
// redirect URIs and web origins pages render a stored value into a table cell and read it
// back when deleting a row. Both sides must use textContent.
//
// innerHTML on the write side parses markup in the value, which made a DCR-registered
// "x:<svg onload=...>" execute in the admin console. innerHTML on the read side returns a
// re-serialised string, so a value containing "&" no longer matched the raw array entry and
// deletion silently did nothing.
//
// Deliberately scoped to these two files. Around twenty other innerHTML assignments across
// the admin templates take server data and are currently protected by input validation
// rather than by output encoding; auditing them is issue #120, which should replace this
// narrow check with a general rule plus an allowlist rather than add a second lint.
func TestTemplates_RedirectURIAndWebOriginCellsAreText(t *testing.T) {
	guarded := map[string]bool{
		"template/admin_clients_redirect_uris.html": true,
		"template/admin_clients_web_origins.html":   true,
	}

	// The write side, "cell1.innerHTML = uri", and the read side,
	// getElementsByTagName("td")[0].innerHTML.
	banned := []string{
		"innerHTML = uri",
		`getElementsByTagName("td")[0].innerHTML`,
	}

	seen := 0
	walkHTMLTemplates(t, func(path, content string) {
		if !guarded[path] {
			return
		}
		seen++
		for _, b := range banned {
			if strings.Contains(content, b) {
				t.Errorf("%s: found %q; use textContent on both the write and the read side (issue #105)",
					path, b)
			}
		}
	})

	// If either file is renamed, the check above silently guards nothing.
	if seen != len(guarded) {
		t.Errorf("expected to check %d templates, checked %d; update the guarded set if a file was renamed",
			len(guarded), seen)
	}
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
