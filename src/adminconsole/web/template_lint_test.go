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

// TestTemplates_NoCsrfField guards the half of the CSRF token deletion that nothing else in any
// tier can observe. #155 replaced the CSRF token with an origin check, so no handler binds
// csrfField any more and no template may name it again.
//
// The reason this needs a lint rather than a test is that a template naming a bind no handler
// supplies is completely silent. It does not fail to compile. It does not fail the render tests:
// restoring {{ .csrfField }} to account_phone.html, which TestRender_AccountPhone and
// TestRender_JSBootstrapNoKeyLeak both render from a bind map that no longer carries it, left the
// whole adminconsole tier green. And it does not look wrong in a browser either: every csrfField
// line deleted here was a standalone {{ .csrfField }} action sitting in HTML text, and there
// html/template renders a missing map key as nothing at all.
//
// (text/template is what renders the literal "<no value>", and these pages are not text/template.
// html/template's answer is context-dependent rather than uniform, so "it renders as nothing" is a
// statement about the shape these lines had, not about missing binds in general: a missing key
// becomes ZgotmplZ in an unquoted attribute and null in an unquoted JavaScript value, while HTML
// text, quoted attributes, quoted URLs, JavaScript strings and CSS values all render empty.
// Option("missingkey=error") would turn every one of them into a render error, and nothing in this
// repo sets it.)
//
// So a stray reference is not a broken page. It is a dead one, invisible everywhere, that reads to
// the next person as though a CSRF field were still being emitted. That is exactly what #155
// deleted the plumbing to avoid, and a lint is the only thing that can see it.
//
// The claim is lexical and stops there: no template source contains the string csrfField. A
// reference reintroduced by copy-paste or a revert carries that spelling, which is the shape a
// regression takes. A key spelled around the scan does not, and this is demonstrable rather than
// theoretical: {{ index . "\x63srfField" }} reads the same runtime key and this test does not see
// it. Catching that would mean parsing each file with text/template/parse and walking the tree,
// which needs this module's whole func map to parse at all, and a key computed at run time would
// still be out of reach. The boundary is drawn here on purpose. See the matching note in
// internal/handlers/csrf_lint_test.go, which draws the same one on the bind side.
func TestTemplates_NoCsrfField(t *testing.T) {
	walkHTMLTemplates(t, func(path, content string) {
		if strings.Contains(content, "csrfField") {
			// Lexical, like the scan. It does not predict what the occurrence would render
			// as: that depends on the context the action sits in, per the note above.
			t.Errorf(`%s: names csrfField, the spelling #155 deleted when it replaced the CSRF `+
				`token with an origin check; no handler binds it, so remove the occurrence or `+
				`update this guard`, path)
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
