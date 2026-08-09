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

// TestTemplates_NoCsrfField guards the half of the CSRF token deletion that nothing else
// observes. A template naming a bind no handler supplies does not fail to compile, and neither the
// handler tests nor the integration suite catches it either: both assert on the fields a page
// carries rather than on the absence of a stray one, and restoring {{ .csrfField }} to all eight
// forms left every one of them green.
//
// It does not look wrong in a browser either. All eight references deleted here were standalone
// {{ .csrfField }} actions sitting in HTML text, and there html/template renders a missing map key
// as nothing at all. (text/template is what renders the literal "<no value>"; these pages are not
// text/template. That distinction was measured for the admin console side of this change, after
// this comment first asserted the text/template answer. html/template's answer is context-dependent
// rather than uniform, so this says what these eight lines did and not what a missing bind does in
// general: elsewhere a missing key becomes ZgotmplZ in an unquoted attribute and null in an
// unquoted JavaScript value.) A stray reference is therefore a dead one, invisible everywhere,
// reading to the next person as though a CSRF field were still emitted.
//
// csrfField was the last bind in that shape. #155 replaced the CSRF token with an origin check, so
// no handler binds it any more and no template may name it again.
//
// The claim is lexical and stops there: no template source contains the string csrfField. That is
// the shape a regression takes, since a reference comes back by copy-paste or by a revert and both
// carry the spelling. A key spelled around the scan does not: {{ index . "\x63srfField" }} reads
// the same runtime key and this test does not see it. The admin console's copy of this guard
// carries the same boundary and the reasoning for drawing it there.
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
// layouts must render the lang attribute from the active locale. Email layouts
// are exempt (emails are per-locale sibling files, not context-driven).
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
