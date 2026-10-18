package guard

// The rule table AssertWellFormedTemplates enforces, each rule over a template it must refuse and one
// it must admit, read through findMarkupProblems; the page rules over fixture trees of pages, layouts
// and partials, read as the renderer assembles them; and the reporting half driven through Run over
// fixture trees: one that breaks a rule, one that breaks none, a pending list in both directions, and
// the walks that reach nothing.

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func markupDetails(src string) []string {
	var out []string
	for _, f := range findMarkupProblems("template/t.html", src) {
		out = append(out, f.detail)
	}
	return out
}

func TestWellFormedTemplates_TheRuleTable(t *testing.T) {
	branchMismatch := func(ends, began string) string {
		return "line 1: a branch ends " + ends + ", where it began " + began +
			": what a branch opens it closes, so the page reads the same whichever branch runs"
	}
	cases := []struct {
		name string
		src  string
		want []string
	}{
		// Closing.
		{"an element left open", `<div><p>text</p>`,
			[]string{`line 1: <div> is never closed`}},
		{"misnested end tags", `<div><span>x</div></span>`,
			[]string{`line 1: <span> is not closed before </div> on line 1`, `line 1: </span> closes nothing that is open`}},
		{"a void element's end tag", `<br></br>`,
			[]string{`line 1: </br>: a void element has no end tag`}},
		{"a trailing slash on a void element", `<input type="hidden" name="a"/>`,
			[]string{`line 1: <input/>: write a void element without the trailing slash`}},
		{"a trailing slash on a container", `<div/>`,
			[]string{`line 1: <div/>: the slash does not close an HTML element; write </div>`, `line 1: <div> is never closed`}},
		{"self-closing inside SVG is fine", `<svg aria-hidden="true"><path d="M0 0"/></svg>`, nil},
		{"a bare less-than in text", `<p>a < b</p>`,
			[]string{`line 1: a bare < in text: write &lt;`}},
		{"a raw-text end tag is its whole name", `<textarea aria-label="Notes"></textareax> stays text</textarea>`, nil},
		{"a JSON block holding a longer end tag", `<script type="application/json" id="d">{"a": "</scriptx>"}</script>`, nil},

		// Branches.
		{"an element opened in one branch and closed after it",
			`{{if .a}}<a href="/x">{{else}}<span>{{end}}text{{if .a}}</a>{{else}}</span>{{end}}`,
			[]string{
				branchMismatch("in text with <a> open", "in text with no element open"),
				branchMismatch("in text with <span> open", "in text with no element open"),
				`line 1: </a> closes nothing that is open`,
				`line 1: </span> closes nothing that is open`,
			}},
		{"attributes and values in branches",
			`<input type="checkbox" id="c"{{if .on}} checked{{end}} class="{{if .x}}a{{else}}b{{end}}"><label for="c">C</label>`, nil},
		{"an attribute written alone in a branch", `<option{{if .s}} selected{{end}}>x</option>`, nil},

		// Attributes.
		{"an unquoted value", `<div class=box>x</div>`,
			[]string{`line 1: attribute class is not quoted`}},
		{"an unquoted action value", `<div class={{.c}}>x</div>`,
			[]string{`line 1: attribute class is not quoted: write class="{{.c}}"`}},
		{"an attribute twice", `<div class="a" class="b">x</div>`,
			[]string{`line 1: <div> carries class twice`}},
		{"an attribute twice across a branch", `<div class="a"{{if .x}} class="b"{{end}}>x</div>`,
			[]string{`line 1: <div> carries class twice`}},
		{"an attribute once in each of two branches", `<div {{if .x}}class="a"{{else}}class="b"{{end}}>x</div>`, nil},

		// Nesting a browser repairs.
		{"a block in a paragraph", `<p><div>x</div></p>`,
			[]string{`line 1: <div> inside a <p>, which a browser closes before it`}},
		{"a form in a form", `<form><form></form></form>`,
			[]string{`line 1: a <form> inside a <form>, which a browser drops`}},
		{"a button in a link", `<a href="/">x<button>y</button></a>`,
			[]string{`line 1: <button> inside a link or a button`}},
		{"a list item outside a list", `<div><li>x</li></div>`,
			[]string{`line 1: <li> outside a list`}},
		{"a list item from a range in a list", `<ul>{{range .}}<li>{{.}}</li>{{end}}</ul>`, nil},
		{"a div in a table body", `<table><tbody><div>x</div></tbody></table>`,
			[]string{`line 1: <div> directly in a <tbody>, which a browser moves out of it`}},
		{"text in a table row", `<table><tr>x<td>y</td></tr></table>`,
			[]string{`line 1: text directly in a <tr>, which a browser moves out of it`}},
		{"HTML inside an SVG foreignObject is held to HTML's nesting",
			`<svg aria-hidden="true"><foreignObject><p><div>x</div></p></foreignObject></svg>`,
			[]string{`line 1: <div> inside a <p>, which a browser closes before it`}},

		// Script.
		{"an inline script", `<script>alert(1)</script>`,
			[]string{`line 1: an inline <script> runs code: move it to a static file, or make it a <script type="application/json"> data block`}},
		{"an inline module", `<script type="module">x()</script>`,
			[]string{`line 1: an inline <script> runs code: move it to a static file, or make it a <script type="application/json"> data block`}},
		{"a script inside SVG", `<svg aria-hidden="true"><script>alert(1)</script></svg>`,
			[]string{`line 1: a <script> inside SVG runs code: move it to a static file`}},
		{"a JSON data block holding an action", `<script type="application/json" id="d">{"a": {{.a}}, "b": [{{.b}}]}</script>`, nil},
		{"a JSON data block whose branches are each JSON",
			`<script type="application/json" id="d">{{if .x}}{"a": 1}{{else}}[1, {{.b}}]{{end}}</script>`, nil},
		{"a JSON data block with one branch that is not JSON",
			`<script type="application/json" id="d">{{if .x}}{"a": 1}{{else}}{a: 1}{{end}}</script>`,
			[]string{`line 1: the JSON data block is not valid JSON in every branch, reading each action as a value`}},
		{"a JSON data block that is not JSON", `<script type="application/json" id="d">{a: 1}</script>`,
			[]string{`line 1: the JSON data block is not valid JSON in every branch, reading each action as a value`}},
		{"a script file", `<script src="/static/x.js" defer></script>`, nil},
		{"a script file with a body", `<script src="/static/x.js">go()</script>`,
			[]string{`line 1: a <script src> also holds code, which a browser never runs`}},
		{"an event attribute", `<button onclick="go()">Go</button>`,
			[]string{`line 1: <button> carries onclick: register the handler from a static script`}},
		{"a javascript: URL", `<a href="javascript:go()">Go</a>`,
			[]string{`line 1: <a href> is a javascript: URL: register the behaviour from a static script`}},

		// Accessibility.
		{"an unlabelled input", `<input type="text" name="q">`,
			[]string{`line 1: <input> has no label: give it an id a <label for> names, or aria-label`}},
		{"an input whose label names another id", `<label for="b">B</label><input id="a" name="a">`,
			[]string{
				`line 1: the control with id "a" has no <label for="a"> wherever it renders, and no aria-label`,
				`line 1: for names id "b", which is not declared wherever the reference renders`,
			}},
		{"a label shown in one branch for an input always shown",
			`{{if .x}}<label for="a">A</label>{{end}}<input id="a" name="a">`,
			[]string{`line 1: the control with id "a" has no <label for="a"> wherever it renders, and no aria-label`}},
		{"a label always shown for an input shown in one branch",
			`<label for="a">A</label>{{if .x}}<input id="a" name="a">{{end}}`,
			[]string{`line 1: for names id "a", which is not declared wherever the reference renders`}},
		{"a label and its input in one branch",
			`{{if .x}}<label for="a">A</label><input id="a" name="a">{{end}}`, nil},
		{"labelled four ways",
			`<label for="a">A</label><input id="a"><label>B <select name="b"></select></label>` +
				`<textarea aria-label="C"></textarea><input type="hidden" name="d"><input type="submit" value="Go">`, nil},
		{"an image without alt", `<img src="/x.png">`,
			[]string{`line 1: <img> has no alt: describe it, or write alt="" if it only decorates`}},
		{"a decorative image", `<img src="/x.png" alt="">`, nil},
		{"an image with alt in one branch alone", `<img src="/x.png"{{if .x}} alt="X"{{end}}>`,
			[]string{`line 1: <img> has no alt: describe it, or write alt="" if it only decorates`}},
		{"an icon neither hidden nor named", `<svg viewBox="0 0 1 1"></svg>`,
			[]string{`line 1: <svg> is neither hidden with aria-hidden="true" nor named`}},
		{"a button showing only an icon", `<button><svg aria-hidden="true"></svg></button>`,
			[]string{`line 1: <button> has no name in every branch: give it text, or aria-label if it shows only an icon`}},
		{"a button named in one branch alone", `<button>{{if .x}}Save{{end}}</button>`,
			[]string{`line 1: <button> has no name in every branch: give it text, or aria-label if it shows only an icon`}},
		{"a button named in both branches", `<button>{{if .x}}Save{{else}}{{ .label }}{{end}}</button>`, nil},
		{"buttons and links named four ways",
			`<button><svg aria-hidden="true"></svg><span class="sr-only">Close</span></button>` +
				`<button aria-label="Close"></button><a href="/">{{ T $.ctx "home" }}</a><a href="/"><img src="/l.png" alt="Home"></a>`, nil},
		{"a second h1", "<h1>A</h1>\n<h1>B</h1>",
			[]string{`line 2: a second <h1>: a page has one, its title`}},
		{"an h1 in each of two exclusive branches", `{{if .x}}<h1>A</h1>{{else}}<h1>B</h1>{{end}}`, nil},
		{"a skipped heading level", `<h1>A</h1><h3>B</h3>`,
			[]string{`line 1: <h3> follows an <h1>: heading levels do not skip on the way down`}},
		{"a positive tabindex", `<div tabindex="2">x</div>`,
			[]string{`line 1: <div> has tabindex 2: a positive tabindex reorders the keyboard path`}},
		{"a html without lang", `<html><body></body></html>`,
			[]string{`line 1: <html> has no lang`}},
		{"a description naming no id", `<input id="a" aria-describedby="hint" aria-label="A">`,
			[]string{`line 1: aria-describedby names id "hint", which is not declared wherever the reference renders`}},
		{"a description naming an id shown in one branch alone",
			`{{if .x}}<p id="hint">h</p>{{end}}<input id="a" aria-describedby="hint" aria-label="A">`,
			[]string{`line 1: aria-describedby names id "hint", which is not declared wherever the reference renders`}},
		{"an id declared in every arm of an if, else if and else",
			`{{if .a}}<p id="h">a</p>{{else if .b}}<p id="h">b</p>{{else}}<p id="h">c</p>{{end}}<input aria-label="X" aria-describedby="h">`, nil},
		{"an id declared in two of three arms",
			`{{if .a}}<p id="h">a</p>{{else if .b}}<p id="h">b</p>{{else}}<p>c</p>{{end}}<input aria-label="X" aria-describedby="h">`,
			[]string{`line 1: aria-describedby names id "h", which is not declared wherever the reference renders`}},
		{"ids and references with actions", `{{ $id := .id }}<p id="{{$id}}_t">x</p><dialog aria-labelledby="{{$id}}_t">y</dialog>`, nil},
		{"a static id in a range", `<ul>{{range .}}<li id="row">x</li>{{end}}</ul>`,
			[]string{`line 1: id "row" is written inside a {{range}}, so it repeats on the page`}},
		{"an id declared twice", `<p id="a">x</p><p id="a">y</p>`,
			[]string{`line 1: id "a" is declared twice where both can render`}},
		{"an id declared twice inside one branch", `{{if .x}}<p id="a">x</p><p id="a">y</p>{{end}}`,
			[]string{`line 1: id "a" is declared twice where both can render`}},
		{"an id in each of two exclusive branches", `{{if .x}}<p id="a">x</p>{{else}}<p id="a">y</p>{{end}}`, nil},
		{"a declaration renders nothing", `{{- $x := 1 }}<p>{{ $x }}</p>`, nil},
		{"a template that does not parse", `{{if}}`, []string{"does not parse: template: template/t.html:1: missing value for if"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, markupDetails(tc.src))
		})
	}
}

// Each {{define}} is checked on its own, so a fragment that balances in its block passes, and a
// block that leaves an element open is found whatever the file's other blocks do.
func TestWellFormedTemplates_EachBlockIsCheckedOnItsOwn(t *testing.T) {
	src := `{{define "title"}}Users{{end}}` + "\n" +
		`{{define "body"}}<main><h1>Users</h1></main>{{end}}` + "\n" +
		`{{define "head"}}<div>{{end}}`
	assert.Equal(t, []string{`line 3: <div> is never closed`}, markupDetails(src))
}

// pageDetails reads one page of a fixture tree as the guard does, the page alone and as served.
func pageDetails(t *testing.T, fsys fstest.MapFS, page string) []string {
	t.Helper()
	contents := map[string]string{}
	for path, file := range fsys {
		contents[path] = string(file.Data)
	}
	var out []string
	for _, f := range newTemplateSet("template", contents, nil).problems(page) {
		out = append(out, f.path+": "+f.detail)
	}
	return out
}

// A page is read in each layout that finds every template it calls, with the partials, a call
// resolved where it is made: a partial is held to where the page puts it, and the page to the
// rules about a whole page.
func TestWellFormedTemplates_APageIsReadAsServed(t *testing.T) {
	layout := `<!DOCTYPE html><html lang="en"><head><title>{{template "title" .}}</title></head>` +
		`<body>{{template "body" .}}</body></html>`
	fsys := fstest.MapFS{
		"template/layouts/base.html":    {Data: []byte(layout)},
		"template/partials/notice.html": {Data: []byte(`{{define "notice"}}<div class="notice">Saved</div>{{end}}`)},
		"template/good.html": {Data: []byte(`{{define "title"}}Good{{end}}` +
			`{{define "body"}}<main><h1 id="t">Good</h1><section aria-labelledby="t">{{template "notice" .}}</section></main>{{end}}`)},
		"template/nested.html": {Data: []byte(`{{define "title"}}Nested{{end}}` +
			`{{define "body"}}<main><h1>Nested</h1><p>{{template "notice" .}}</p></main>{{end}}`)},
		"template/untitled.html": {Data: []byte(`{{define "title"}}Untitled{{end}}` +
			`{{define "body"}}<main><h2>Section</h2></main>{{end}}`)},
		"template/misnamed.html": {Data: []byte(`{{define "title"}}Misnamed{{end}}` +
			`{{define "content"}}<main><h1>Misnamed</h1></main>{{end}}`)},
	}

	assert.Empty(t, pageDetails(t, fsys, "template/good.html"))
	assert.Equal(t, []string{
		"template/partials/notice.html: line 1: <div> inside a <p>, which a browser closes before it" +
			" (where template/nested.html line 1 calls it) (in template/layouts/base.html)",
	}, pageDetails(t, fsys, "template/nested.html"))
	assert.Equal(t, []string{
		"template/untitled.html: line 1: the page has no <h1> on every branch (in template/layouts/base.html)",
	}, pageDetails(t, fsys, "template/untitled.html"))
	assert.Equal(t, []string{
		"template/misnamed.html: line 1: no layout under layouts/ finds every template it calls in this page",
	}, pageDetails(t, fsys, "template/misnamed.html"))
}

func TestWellFormedTemplates_TheGuardFailsOnATreeThatBreaksARule(t *testing.T) {
	fsys := fstest.MapFS{
		"template/page.html": {Data: []byte(`<h1>Search</h1><form><input name="q"></form>`)},
	}

	report := Run(func(r Reporter) { assertWellFormedTemplates(r, fsys, "template", nil, nil) })

	require.True(t, report.Failed(), "an unlabelled control passed the guard")
	assert.Contains(t, report.Text(), "template/page.html: line 1: <input> has no label")
}

func TestWellFormedTemplates_TheGuardPassesACleanTree(t *testing.T) {
	fsys := fstest.MapFS{
		"template/page.html":           {Data: []byte(`<h1>Search</h1><form><label for="q">Search</label><input id="q" name="q"></form>`)},
		"template/emails/message.html": {Data: []byte(`<p>An email, <br/> unchecked</p>`)},
		"template/old.html":            {Data: []byte(`<h1>Old</h1><button onclick="go()">Go</button>`)},
	}

	report := Run(func(r Reporter) {
		assertWellFormedTemplates(r, fsys, "template", []string{"emails/"}, []string{"old.html"})
	})

	assert.False(t, report.Failed(), "a clean tree failed the guard: %s", report.Text())
}

// The pending list only shrinks: a pending page that already meets every rule, and an entry naming
// no template, are each reported.
func TestWellFormedTemplates_ThePendingListOnlyShrinks(t *testing.T) {
	fsys := fstest.MapFS{
		"template/page.html": {Data: []byte(`<h1>Fine</h1>`)},
		"template/done.html": {Data: []byte(`<h1>Fine too</h1>`)},
	}

	report := Run(func(r Reporter) {
		assertWellFormedTemplates(r, fsys, "template", []string{"gone/missing.html"}, []string{"done.html", "deleted.html"})
	})

	require.True(t, report.Failed())
	assert.Contains(t, report.Text(), "template/done.html: listed as pending, and already meets every rule; remove it from the list")
	assert.Contains(t, report.Text(), "template/deleted.html: listed, and no such template exists; remove it from the list")
	assert.Contains(t, report.Text(), "template/gone/missing.html: listed, and no such template exists; remove it from the list")
	assert.NotContains(t, report.Text(), "template/page.html")
}

func TestWellFormedTemplates_AWalkThatReachesNothingIsFatal(t *testing.T) {
	empty := fstest.MapFS{"template/readme.txt": {Data: []byte("no pages here")}}
	report := Run(func(r Reporter) { assertWellFormedTemplates(r, empty, "template", nil, nil) })
	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked no .html files under template")

	exempt := fstest.MapFS{"template/emails/a.html": {Data: []byte(`<p>x</p>`)}}
	report = Run(func(r Reporter) { assertWellFormedTemplates(r, exempt, "template", []string{"emails/"}, nil) })
	require.True(t, report.Stopped, "a walk whose every page is exempt checks nothing, and must be fatal")
	assert.Contains(t, report.Fatal, "every .html file under template is out of scope or pending")
}
