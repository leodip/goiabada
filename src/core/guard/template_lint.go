package guard

import (
	"io/fs"
	"regexp"
	"strconv"
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

// walkOrFail calls fn for every .html file under root in fsys, with the file's path as fsys spells
// it and its whole contents as a string. The four rules below are the ones both servers run, and
// this walk is what they share.
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
//
// It fails through a Reporter so a rule test can drive it and the four assertions built on it
// against a fixture FS. See Reporter in guard.go.
func walkOrFail(r Reporter, fsys fs.FS, root string, fn func(path, content string)) {
	r.Helper()

	n, err := walkHTMLTemplates(fsys, root, fn)
	if err != nil {
		r.Fatalf("walking templates under %s: %v", root, err)
	}
	if n == 0 {
		r.Fatalf("walked no .html files under %s; this guard is checking nothing", root)
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

	assertTemplatesNoHTMLInTitle(t, fsys, root)
}

// assertTemplatesNoHTMLInTitle is the reporting half, failing through a Reporter so a rule test can drive it
// against a fixture FS. See Reporter in guard.go.
func assertTemplatesNoHTMLInTitle(r Reporter, fsys fs.FS, root string) {
	r.Helper()

	walkOrFail(r, fsys, root, func(path, content string) {
		for _, f := range findHTMLInTitle(path, content) {
			r.Errorf("%s: {{define \"title\"}} contains HTML (renders literally in <title>): %q",
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

	assertTemplatesNoCsrfField(t, fsys, root)
}

// assertTemplatesNoCsrfField is the reporting half, failing through a Reporter so a rule test can drive it
// against a fixture FS. See Reporter in guard.go.
func assertTemplatesNoCsrfField(r Reporter, fsys fs.FS, root string) {
	r.Helper()

	walkOrFail(r, fsys, root, func(path, content string) {
		for _, f := range findCsrfField(path, content) {
			// Lexical, like the scan. It does not predict what the occurrence would render
			// as: that depends on the context the action sits in, per the note above.
			r.Errorf(`%s: names csrfField, the spelling #155 deleted when it replaced the CSRF `+
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

// AssertTemplatesHtmlLangNotHardcoded guards the <html lang="en"> bug: layouts must render the lang
// attribute from the language the document renders in, a page's from the active locale and an email's
// from the body copy the renderer chose. Email layouts are held to it too: the bodies are per-locale
// sibling files, but the one layout they are drawn in is shared (#645 decision 10).
func AssertTemplatesHtmlLangNotHardcoded(t *testing.T, fsys fs.FS, root string) {
	t.Helper()

	assertTemplatesHtmlLangNotHardcoded(t, fsys, root)
}

// assertTemplatesHtmlLangNotHardcoded is the reporting half, failing through a Reporter so a rule test can drive it
// against a fixture FS. See Reporter in guard.go.
func assertTemplatesHtmlLangNotHardcoded(r Reporter, fsys fs.FS, root string) {
	r.Helper()

	walkOrFail(r, fsys, root, func(path, content string) {
		for _, f := range findHardcodedHTMLLang(path, content) {
			r.Errorf(`%s: <html lang="en"> is hardcoded; use lang="{{ Lang $.ctx }}", or in an `+
				`email layout the language of the body copy the renderer chose`, f.path)
		}
	})
}

// findHardcodedHTMLLang returns a finding when a layout hardcodes the lang attribute.
func findHardcodedHTMLLang(path, content string) []templateFinding {
	if !strings.Contains(path, "layouts/") {
		return nil
	}
	if !strings.Contains(content, `<html lang="en"`) {
		return nil
	}
	return []templateFinding{{path: path}}
}

// newTabNoticeKey is the catalog key of the built-in text a link that opens a new tab carries for
// assistive technology, "(opens in a new tab)" in English.
const newTabNoticeKey = "common.link.opens_in_new_tab"

// linkStartTagRe matches a link's start tag, <a ...>, an action inside it read whole so a ">" in
// one does not end the tag.
var linkStartTagRe = regexp.MustCompile(`(?is)<a\b(?:[^>{]|\{\{.*?\}\}|\{)*>`)

// newTabTargetRe matches a target attribute naming a new browsing context, _blank, however it is
// quoted or cased.
var newTabTargetRe = regexp.MustCompile(`(?i)\btarget\s*=\s*["']?_blank\b`)

// linkEndTagRe matches a link's end tag.
var linkEndTagRe = regexp.MustCompile(`(?i)</a\s*>`)

// newTabNoticeRe matches the action that renders the new-tab text, from the page's dot or a
// partial's, or the field the auth server's form_post page carries it in: that page is parsed with
// no template functions, so its text arrives translated in its data (#814).
var newTabNoticeRe = regexp.MustCompile(`\{\{-?\s*(?:T\s+\$?\.ctx\s+"` + regexp.QuoteMeta(newTabNoticeKey) + `"|\$\.page\.NewTabNotice)\s*-?\}\}`)

// AssertTemplatesNewTabLinksSaySo holds every link that opens a new tab to saying so to assistive
// technology, in built-in text (#814 decision 13): a link whose start tag carries target="_blank"
// renders the common.link.opens_in_new_tab text among its contents, before its end tag, so the
// text is part of the link's name. The templates draw it in a sr-only span after the link's own
// text, so nothing visible moves:
//
//	<a href="..." target="_blank" rel="noopener noreferrer">Label<span class="sr-only"> {{ T $.ctx "common.link.opens_in_new_tab" }}</span></a>
//
// A new tab moves a screen reader's user to another page with no Back to return by, which WCAG
// 2.2's technique G201 says to announce; without a guard the next such link is written without it,
// as eleven were.
//
// The claim is lexical, like the rules above: a start tag spelling target="_blank" anywhere in it,
// in a branch included, and the action spelled as the templates spell it between that tag and the
// next </a>, or, in the form_post page, its {{ $.page.NewTabNotice }} field. A target computed by
// an action, a link a script opens in a new tab, and a form's target are outside it.
func AssertTemplatesNewTabLinksSaySo(t *testing.T, fsys fs.FS, root string) {
	t.Helper()

	assertTemplatesNewTabLinksSaySo(t, fsys, root)
}

// assertTemplatesNewTabLinksSaySo is the reporting half, failing through a Reporter so a rule test
// can drive it against a fixture FS. See Reporter in guard.go.
func assertTemplatesNewTabLinksSaySo(r Reporter, fsys fs.FS, root string) {
	r.Helper()

	walkOrFail(r, fsys, root, func(path, content string) {
		for _, f := range findSilentNewTabLinks(path, content) {
			r.Errorf(`%s: %s opens a new tab without saying so; put <span class="sr-only"> `+
				`{{ T $.ctx "%s" }}</span> after the link's text`, f.path, f.detail, newTabNoticeKey)
		}
	})
}

// findSilentNewTabLinks returns one finding per link in content that opens a new tab and carries no
// new-tab text, its detail the line and the start tag.
func findSilentNewTabLinks(path, content string) []templateFinding {
	var found []templateFinding
	for _, loc := range linkStartTagRe.FindAllStringIndex(content, -1) {
		tag := content[loc[0]:loc[1]]
		if !newTabTargetRe.MatchString(tag) {
			continue
		}
		body := content[loc[1]:]
		if end := linkEndTagRe.FindStringIndex(body); end != nil {
			body = body[:end[0]]
		}
		if newTabNoticeRe.MatchString(body) {
			continue
		}
		line := strings.Count(content[:loc[0]], "\n") + 1
		found = append(found, templateFinding{path: path, detail: "line " + strconv.Itoa(line) + ": " + tag})
	}
	return found
}
