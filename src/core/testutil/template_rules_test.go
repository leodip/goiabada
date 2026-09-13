package testutil

// Seam 3: the rule table the three shared template guards enforce, over fstest.MapFS fixtures walked
// through the same functions the four real callers reach.
//
// The synthetic half exists because the real half cannot fail informatively. Both servers' templates
// are green on arrival and have been for releases, so the real callers would pass identically
// whether each rule still fires or has quietly stopped matching anything. Every "rejected" row below
// is a template the rule must find; every "admitted" row is one it must leave alone.

import (
	"sort"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// renderFindings renders findings as "<path>" or "<path>: <detail>" so a failure names what was
// missed or over-matched rather than printing a struct.
func renderFindings(found []templateFinding) []string {
	out := make([]string, 0, len(found))
	for _, f := range found {
		if f.detail == "" {
			out = append(out, f.path)
			continue
		}
		out = append(out, f.path+": "+f.detail)
	}
	sort.Strings(out)
	return out
}

// runRule walks fsys from root through the production walk and collects what rule reports, so every
// row below is exercised through the same two functions the callers use rather than by calling a
// matcher directly.
func runRule(t *testing.T, fsys fstest.MapFS, rule func(path, content string) []templateFinding) ([]string, int) {
	t.Helper()

	var found []templateFinding
	n, err := walkHTMLTemplates(fsys, "template", func(path, content string) {
		found = append(found, rule(path, content)...)
	})
	require.NoError(t, err)
	return renderFindings(found), n
}

// TestTemplates_TheTitleTable holds the {{define "title"}} rule: markup in the block is rejected,
// text is not, and each block in a file is judged on its own.
//
// One fixture rather than one per row: the regexp is non-greedy across lines, so a block that cannot
// see the block after it is not exercising the thing that could break -- a greedy version would
// swallow the {{end}} of the first and report the two as one.
func TestTemplates_TheTitleTable(t *testing.T) {
	fsys := fstest.MapFS{
		// Rejected: markup of any kind, on one line or spread over several.
		"template/inline.html":  {Data: []byte(`{{define "title"}}Users <b>admin</b>{{end}}`)},
		"template/spaced.html":  {Data: []byte(`{{ define  "title" }}<span>x</span>{{ end }}`)},
		"template/wrapped.html": {Data: []byte("{{define \"title\"}}\n  Clients\n  <i>beta</i>\n{{end}}")},
		// Rejected once, not twice: the first block here is clean and only the second is not.
		"template/two.html": {Data: []byte(
			`{{define "title"}}Groups{{end}}` + "\n" + `{{define "title"}}Roles <em>x</em>{{end}}`)},
		// Admitted: no markup, and a "<" outside a title block is not this rule's business.
		"template/clean.html":     {Data: []byte(`{{define "title"}}Permissions{{end}}<p>body</p>`)},
		"template/nodefine.html":  {Data: []byte(`<html><head><title>literal</title></head></html>`)},
		"template/othername.html": {Data: []byte(`{{define "subtitle"}}<b>x</b>{{end}}`)},
	}

	found, n := runRule(t, fsys, findHTMLInTitle)

	assert.Equal(t, []string{
		"template/inline.html: Users <b>admin</b>",
		"template/spaced.html: <span>x</span>",
		"template/two.html: Roles <em>x</em>",
		"template/wrapped.html: Clients\n  <i>beta</i>",
	}, found)
	assert.Equal(t, 7, n)
}

// TestTemplates_TheCsrfFieldTable holds the csrfField rule: the spelling anywhere in a template is
// rejected, in an action or not, and nothing else is.
//
// The "spelled around" row is the boundary the guard's own comment claims, asserted rather than
// stated: an escape that reads the same runtime key is not found. A row that changes it is a change
// to the guard, not a bug in the fixture.
func TestTemplates_TheCsrfFieldTable(t *testing.T) {
	fsys := fstest.MapFS{
		// Rejected: the spelling, however it is reached.
		"template/action.html":  {Data: []byte(`<form>{{ .csrfField }}</form>`)},
		"template/indexed.html": {Data: []byte(`<form>{{ index . "csrfField" }}</form>`)},
		"template/comment.html": {Data: []byte(`<!-- csrfField went away in #155 -->`)},
		// Admitted: no such spelling, including the escape the guard says it cannot see.
		"template/plain.html":   {Data: []byte(`<form><input name="email"></form>`)},
		"template/escaped.html": {Data: []byte(`{{ index . "\x63srfField" }}`)},
		"template/similar.html": {Data: []byte(`<input name="csrfToken">`)},
	}

	found, n := runRule(t, fsys, findCsrfField)

	assert.Equal(t, []string{
		"template/action.html",
		"template/comment.html",
		"template/indexed.html",
	}, found)
	assert.Equal(t, 6, n)
}

// TestTemplates_TheHtmlLangTable holds the hardcoded-lang rule, which is scoped by path twice over:
// only under a layouts/ directory, and never on an email layout, because emails are per-locale
// sibling files with no active locale to read.
//
// The last admitted row is the rule's stated boundary rather than an oversight. It matches the one
// spelling <html lang="en", so a layout hardcoding some other language passes. That is where both
// copies drew it before this lift and the lift does not move it: "en" is the value a copied layout
// actually carries, and widening to any literal lang would need the locale-driven spelling
// enumerated instead, which is a different rule.
func TestTemplates_TheHtmlLangTable(t *testing.T) {
	hardcoded := []byte(`<html lang="en" class="h-full">`)
	driven := []byte(`<html lang="{{ Lang $.ctx }}" class="h-full">`)

	fsys := fstest.MapFS{
		// Rejected: a page layout advertising a language it does not necessarily render in.
		"template/layouts/auth_layout.html": {Data: hardcoded},
		"template/layouts/nested/deep.html": {Data: hardcoded},
		// Admitted: driven by the locale; an email layout, which is exempt; outside layouts/
		// entirely; and a hardcoded language that is not the one spelling this rule matches.
		"template/layouts/no_menu_layout.html":  {Data: driven},
		"template/layouts/email_layout.html":    {Data: hardcoded},
		"template/layouts/email_layout_pt.html": {Data: hardcoded},
		"template/account_profile.html":         {Data: hardcoded},
		"template/layouts/other_language.html":  {Data: []byte(`<html lang="pt">`)},
	}

	found, n := runRule(t, fsys, findHardcodedHTMLLang)

	assert.Equal(t, []string{
		"template/layouts/auth_layout.html",
		"template/layouts/nested/deep.html",
	}, found)
	assert.Equal(t, 7, n)
}

// TestTemplates_TheWalkReachesEveryHTMLFileAndNothingElse pins what the shared walk hands the rules:
// every .html file under the root at any depth, with its own path and its own contents, and no other
// file whatever it contains.
//
// The non-.html rows matter because each rule is a substring scan. A .txt or .go file carrying the
// banned spelling is not a page and must never be a finding, and asserting that here is what lets
// the three tables above stay about their own rule.
func TestTemplates_TheWalkReachesEveryHTMLFileAndNothingElse(t *testing.T) {
	fsys := fstest.MapFS{
		"template/index.html":             {Data: []byte("a")},
		"template/layouts/deep/page.html": {Data: []byte("b")},
		"template/notes.txt":              {Data: []byte(`{{define "title"}}<b>x</b>{{end}} csrfField`)},
		"template/script.js":              {Data: []byte("csrfField")},
		"template/page.html.bak":          {Data: []byte("csrfField")},
		"static/outside.html":             {Data: []byte("csrfField")},
	}

	seen := map[string]string{}
	n, err := walkHTMLTemplates(fsys, "template", func(path, content string) {
		seen[path] = content
	})

	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, map[string]string{
		"template/index.html":             "a",
		"template/layouts/deep/page.html": "b",
	}, seen)
}

// TestTemplates_AWalkThatReachesNothingIsVisible pins the count WalkHTMLTemplates turns into a
// t.Fatalf. A directory that exists and holds no .html file is not an error from fs.WalkDir, so
// zero is the only signal there is, and every rule here passes vacuously over it: a //go:embed
// pattern narrowed by a rename would otherwise leave four guards reporting nothing and reading as
// green.
func TestTemplates_AWalkThatReachesNothingIsVisible(t *testing.T) {
	fsys := fstest.MapFS{"template/readme.txt": {Data: []byte("no pages here")}}

	n, err := walkHTMLTemplates(fsys, "template", func(path, content string) {})

	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

// TestTemplates_AMissingRootIsAnError pins the other half of that: a root that is not there at all
// is an error rather than an empty walk, which is what WalkHTMLTemplates reports before it ever
// looks at the count.
func TestTemplates_AMissingRootIsAnError(t *testing.T) {
	fsys := fstest.MapFS{"static/app.css": {Data: []byte("body{}")}}

	n, err := walkHTMLTemplates(fsys, "template", func(path, content string) {})

	require.Error(t, err)
	assert.Equal(t, 0, n)
}

// Seam 4: the reporting halves. Everything above asserts on what the three matchers returned and on
// the count the walk reached, which leaves the lines that turn those into a failure untested across
// four real call sites -- both servers' template tiers.

// TestTemplates_TheGuardsFailOnATreeThatBreaksEachRule drives all three reporting halves over one
// fixture that violates all three, so a guard whose report loop has been blinded is caught here
// rather than trusted. They are one test because the failure they share is the interesting one: the
// walk is common to all three, and a rule silently reporting through the wrong one of them would
// otherwise still look like three passes.
func TestTemplates_TheGuardsFailOnATreeThatBreaksEachRule(t *testing.T) {
	fsys := fstest.MapFS{
		"template/page.html": {Data: []byte(`{{define "title"}}<b>Users</b>{{end}}` + "\n" +
			`<form>{{ csrfField }}</form>`)},
		"template/layouts/base.html": {Data: []byte(`<html lang="en">`)},
	}

	title := RunGuard(func(r Reporter) { assertTemplatesNoHTMLInTitle(r, fsys, "template") })
	require.True(t, title.Failed(), "markup in a title block passed the guard")
	assert.Contains(t, title.Text(), "template/page.html")
	assert.Contains(t, title.Text(), "<b>Users</b>")
	assert.Contains(t, title.Text(), "renders literally in <title>")

	csrf := RunGuard(func(r Reporter) { assertTemplatesNoCsrfField(r, fsys, "template") })
	require.True(t, csrf.Failed(), "a csrfField occurrence passed the guard")
	assert.Contains(t, csrf.Text(), "template/page.html")
	assert.Contains(t, csrf.Text(), "#155")

	lang := RunGuard(func(r Reporter) { assertTemplatesHtmlLangNotHardcoded(r, fsys, "template") })
	require.True(t, lang.Failed(), "a hardcoded lang attribute passed the guard")
	assert.Contains(t, lang.Text(), "template/layouts/base.html")
	assert.Contains(t, lang.Text(), "{{ Lang $.ctx }}")
}

// TestTemplates_TheGuardsPassACleanTree is the other direction, over a fixture carrying the admitted
// shape of each rule: a text-only title, no csrfField, and a layout rendering the locale.
func TestTemplates_TheGuardsPassACleanTree(t *testing.T) {
	fsys := fstest.MapFS{
		"template/page.html":         {Data: []byte(`{{define "title"}}Users{{end}}`)},
		"template/layouts/base.html": {Data: []byte(`<html lang="{{ Lang $.ctx }}">`)},
	}

	for name, guard := range map[string]func(Reporter, fstest.MapFS, string){
		"title": func(r Reporter, f fstest.MapFS, root string) { assertTemplatesNoHTMLInTitle(r, f, root) },
		"csrf":  func(r Reporter, f fstest.MapFS, root string) { assertTemplatesNoCsrfField(r, f, root) },
		"lang": func(r Reporter, f fstest.MapFS, root string) {
			assertTemplatesHtmlLangNotHardcoded(r, f, root)
		},
	} {
		t.Run(name, func(t *testing.T) {
			report := RunGuard(func(r Reporter) { guard(r, fsys, "template") })
			assert.False(t, report.Failed(), "a clean tree failed the guard: %s", report.Text())
		})
	}
}

// TestTemplates_AWalkThatReachesNothingFailsEveryGuard completes the seam
// TestTemplates_AWalkThatReachesNothingIsVisible could only assert through the count. A //go:embed
// pattern narrowed by a rename leaves a root that exists and holds no page, and every rule passes
// vacuously over it, so the empty walk has to be the failure.
func TestTemplates_AWalkThatReachesNothingFailsEveryGuard(t *testing.T) {
	fsys := fstest.MapFS{"template/readme.txt": {Data: []byte("no pages here")}}

	report := RunGuard(func(r Reporter) { assertTemplatesNoHTMLInTitle(r, fsys, "template") })

	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked no .html files under template")
	assert.Contains(t, report.Fatal, "checking nothing")
}

// TestTemplates_AMissingRootIsFatalRatherThanEmpty separates the two ways a walk covers nothing, so
// an embed that resolves to no directory at all is not reported as a directory holding no pages.
func TestTemplates_AMissingRootIsFatalRatherThanEmpty(t *testing.T) {
	fsys := fstest.MapFS{"static/app.css": {Data: []byte("body{}")}}

	report := RunGuard(func(r Reporter) { assertTemplatesNoCsrfField(r, fsys, "template") })

	require.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "walking templates under template")
	assert.NotContains(t, report.Fatal, "walked no .html files")
}
