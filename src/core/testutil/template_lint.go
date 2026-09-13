package testutil

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// titleDefineRe matches a {{define "title"}} ... {{end}} block (across lines).
var titleDefineRe = regexp.MustCompile(`(?s)\{\{\s*define\s+"title"\s*\}\}(.*?)\{\{\s*end\s*\}\}`)

// templateFinding is one offending template, located.
type templateFinding struct {
	// path is the file as the walked fs.FS spells it, so "template/layouts/auth_layout.html".
	path string
	// detail is the offending text where the rule has one to quote, and empty where the finding is
	// that a spelling is present at all.
	detail string
}

// WalkHTMLTemplates calls fn for every .html file under root in fsys, with the file's path as fsys
// spells it and its whole contents as a string.
//
// The three rules below are the ones both servers run, and this walk is what they share. It is
// exported because a fourth caller reaches it: the admin console's own
// TestTemplates_RedirectURIAndWebOriginCellsAreText, a rule about two of its client pages that
// belongs to that module alone (#105) and stays there. Sharing the walk and not the rule is the
// shape of this whole file -- lifting that rule too would make core/testutil the place one
// application's policy lives, which is what ARCHITECTURE.md rule 2 refuses (#333).
//
// Callers pass their //go:embed FS rather than a directory on disk, deliberately. That FS is what
// the binary renders from, so it is the set a rule about rendered output has to be held against: a
// template sitting in the tree but outside the embed pattern is not a page anyone can reach, and one
// inside it is a page whatever the deployment's filesystem looks like.
//
// Which makes the embed pattern the single point of failure for every rule here, so a walk reaching
// no file at all is fatal rather than a silent pass. Each of these rules passes vacuously over an
// empty set, and both callers are green on arrival and have been for releases, so nothing else in
// any tier can tell a guard that covers every page from one that covers none.
func WalkHTMLTemplates(t *testing.T, fsys fs.FS, root string, fn func(path, content string)) {
	t.Helper()

	n, err := walkHTMLTemplates(fsys, root, fn)
	if err != nil {
		t.Fatalf("walking templates under %s: %v", root, err)
	}
	if n == 0 {
		t.Fatalf("walked no .html files under %s; this guard is checking nothing", root)
	}
}

// walkHTMLTemplates is the walk itself, returning how many .html files it reached so its caller can
// refuse to pass over an empty set. It is the pure half: the rule tests reach every rule through it
// rather than through a *testing.T, so a rule that has stopped matching is a failing assertion
// rather than a quiet green.
func walkHTMLTemplates(fsys fs.FS, root string, fn func(path, content string)) (int, error) {
	n := 0
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".html") {
			return nil
		}
		b, rErr := fs.ReadFile(fsys, p)
		if rErr != nil {
			return rErr
		}
		n++
		fn(p, string(b))
		return nil
	})
	return n, err
}

// AssertTemplatesNoHTMLInTitle guards the admin_users_* bug: the {{define "title"}} block feeds the
// HTML <title> element, which renders tags literally, so any markup there shows up as raw text in
// the browser tab.
func AssertTemplatesNoHTMLInTitle(t *testing.T, fsys fs.FS, root string) {
	t.Helper()

	WalkHTMLTemplates(t, fsys, root, func(path, content string) {
		for _, f := range findHTMLInTitle(path, content) {
			t.Errorf("%s: {{define \"title\"}} contains HTML (renders literally in <title>): %q",
				f.path, f.detail)
		}
	})
}

// findHTMLInTitle returns one finding per {{define "title"}} block in content carrying a "<".
func findHTMLInTitle(path, content string) []templateFinding {
	var found []templateFinding
	for _, m := range titleDefineRe.FindAllStringSubmatch(content, -1) {
		if strings.Contains(m[1], "<") {
			found = append(found, templateFinding{path: path, detail: strings.TrimSpace(m[1])})
		}
	}
	return found
}

// AssertTemplatesNoCsrfField guards the half of the CSRF token deletion that nothing else in any
// tier can observe. #155 replaced the CSRF token with an origin check, so no handler binds csrfField
// any more and no template may name it again.
//
// The reason this needs a lint rather than a test is that a template naming a bind no handler
// supplies is completely silent. It does not fail to compile. It does not fail the render tests:
// each caller's comment records the page it restored {{ .csrfField }} to and the tier that stayed
// green anyway. And it does not look wrong in a browser either: every csrfField line #155 deleted
// was a standalone {{ .csrfField }} action sitting in HTML text, and there html/template renders a
// missing map key as nothing at all.
//
// (text/template is what renders the literal "<no value>", and these pages are not text/template.
// html/template's answer is context-dependent rather than uniform, so "it renders as nothing" is a
// statement about the shape those lines had, not about missing binds in general: a missing key
// becomes ZgotmplZ in an unquoted attribute and null in an unquoted JavaScript value, while HTML
// text, quoted attributes, quoted URLs, JavaScript strings and CSS values all render empty.
// Option("missingkey=error") would turn every one of them into a render error, and nothing in this
// repo sets it.)
//
// So a stray reference is not a broken page. It is a dead one, invisible everywhere, that reads to
// the next person as though a CSRF field were still being emitted. That is exactly what #155 deleted
// the plumbing to avoid, and a lint is the only thing that can see it.
//
// The claim is lexical and stops there: no template source contains the string csrfField. A
// reference reintroduced by copy-paste or a revert carries that spelling, which is the shape a
// regression takes. A key spelled around the scan does not, and this is demonstrable rather than
// theoretical: {{ index . "\x63srfField" }} reads the same runtime key and this test does not see
// it. Catching that would mean parsing each file with text/template/parse and walking the tree,
// which needs the calling module's whole func map to parse at all, and a key computed at run time
// would still be out of reach. The boundary is drawn here on purpose. See the matching note in
// adminconsole/internal/handlers/csrf_lint_test.go, which draws the same one on the bind side.
func AssertTemplatesNoCsrfField(t *testing.T, fsys fs.FS, root string) {
	t.Helper()

	WalkHTMLTemplates(t, fsys, root, func(path, content string) {
		for _, f := range findCsrfField(path, content) {
			// Lexical, like the scan. It does not predict what the occurrence would render
			// as: that depends on the context the action sits in, per the note above.
			t.Errorf(`%s: names csrfField, the spelling #155 deleted when it replaced the CSRF `+
				`token with an origin check; no handler binds it, so remove the occurrence or `+
				`update this guard`, f.path)
		}
	})
}

// findCsrfField returns a finding when content names csrfField at all.
func findCsrfField(path, content string) []templateFinding {
	if !strings.Contains(content, "csrfField") {
		return nil
	}
	return []templateFinding{{path: path}}
}

// AssertTemplatesHtmlLangNotHardcoded guards the <html lang="en"> bug: page layouts must render the
// lang attribute from the active locale so the document advertises the language it renders in. Email
// layouts are exempt (emails are per-locale sibling files, not context-driven).
func AssertTemplatesHtmlLangNotHardcoded(t *testing.T, fsys fs.FS, root string) {
	t.Helper()

	WalkHTMLTemplates(t, fsys, root, func(path, content string) {
		for _, f := range findHardcodedHTMLLang(path, content) {
			t.Errorf(`%s: <html lang="en"> is hardcoded; use lang="{{ Lang $.ctx }}"`, f.path)
		}
	})
}

// findHardcodedHTMLLang returns a finding when a non-email layout hardcodes the lang attribute.
func findHardcodedHTMLLang(path, content string) []templateFinding {
	if !strings.Contains(path, "layouts/") || strings.Contains(path, "email") {
		return nil
	}
	if !strings.Contains(content, `<html lang="en"`) {
		return nil
	}
	return []templateFinding{{path: path}}
}
