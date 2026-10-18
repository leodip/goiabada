package guard

// The rule table AssertWellFormedTemplates enforces, each rule over a template it must refuse and one
// it must admit, read through findMarkupProblems, and the reporting half driven through Run over
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

		// Branches.
		{"an element opened in one branch and closed after it",
			`{{if .a}}<a href="/x">{{else}}<span>{{end}}text{{if .a}}</a>{{else}}</span>{{end}}`,
			[]string{
				`line 1: a branch ends in text with <a> open, where it began in text with no element open: what a branch opens it closes, so the page reads the same whichever branch runs`,
				`line 1: a branch ends in text with <span> open, where it began in text with no element open: what a branch opens it closes, so the page reads the same whichever branch runs`,
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

		// Script.
		{"an inline script", `<script>alert(1)</script>`,
			[]string{`line 1: an inline <script> runs code: move it to a static file, or make it a <script type="application/json"> data block`}},
		{"an inline module", `<script type="module">x()</script>`,
			[]string{`line 1: an inline <script> runs code: move it to a static file, or make it a <script type="application/json"> data block`}},
		{"a JSON data block holding an action", `<script type="application/json" id="d">{"a": {{.a}}, "b": [{{.b}}]}</script>`, nil},
		{"a JSON data block that is not JSON", `<script type="application/json" id="d">{a: 1}</script>`,
			[]string{`line 1: the JSON data block is not valid JSON, reading each action as a value`}},
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
			[]string{`line 1: the control with id "a" has no <label for="a">, and no aria-label`, `line 1: for names id "b", which this template does not declare`}},
		{"labelled four ways",
			`<label for="a">A</label><input id="a"><label>B <select name="b"></select></label>` +
				`<textarea aria-label="C"></textarea><input type="hidden" name="d"><input type="submit" value="Go">`, nil},
		{"an image without alt", `<img src="/x.png">`,
			[]string{`line 1: <img> has no alt: describe it, or write alt="" if it only decorates`}},
		{"a decorative image", `<img src="/x.png" alt="">`, nil},
		{"an icon neither hidden nor named", `<svg viewBox="0 0 1 1"></svg>`,
			[]string{`line 1: <svg> is neither hidden with aria-hidden="true" nor named`}},
		{"a button showing only an icon", `<button><svg aria-hidden="true"></svg></button>`,
			[]string{`line 1: <button> has no name: give it text, or aria-label if it shows only an icon`}},
		{"buttons and links named four ways",
			`<button><svg aria-hidden="true"></svg><span class="sr-only">Close</span></button>` +
				`<button aria-label="Close"></button><a href="/">{{ T $.ctx "home" }}</a><a href="/"><img src="/l.png" alt="Home"></a>`, nil},
		{"a second h1", "<h1>A</h1>\n<h1>B</h1>",
			[]string{`line 2: a second <h1>: a page has one, its title`}},
		{"a skipped heading level", `<h1>A</h1><h3>B</h3>`,
			[]string{`line 1: <h3> follows an <h1>: heading levels do not skip on the way down`}},
		{"a positive tabindex", `<div tabindex="2">x</div>`,
			[]string{`line 1: <div> has tabindex 2: a positive tabindex reorders the keyboard path`}},
		{"a html without lang", `<html><body></body></html>`,
			[]string{`line 1: <html> has no lang`}},
		{"a description naming no id", `<input id="a" aria-describedby="hint" aria-label="A">`,
			[]string{`line 1: aria-describedby names id "hint", which this template does not declare`}},
		{"ids and references with actions", `{{ $id := .id }}<p id="{{$id}}_t">x</p><dialog aria-labelledby="{{$id}}_t">y</dialog>`, nil},
		{"a static id in a range", `<ul>{{range .}}<li id="row">x</li>{{end}}</ul>`,
			[]string{`line 1: id "row" is written inside a {{range}}, so it repeats on the page`}},
		{"an id declared twice", `<p id="a">x</p><p id="a">y</p>`,
			[]string{`line 1: id "a" is declared twice`}},
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

func TestWellFormedTemplates_TheGuardFailsOnATreeThatBreaksARule(t *testing.T) {
	fsys := fstest.MapFS{
		"template/page.html": {Data: []byte(`<form><input name="q"></form>`)},
	}

	report := Run(func(r Reporter) { assertWellFormedTemplates(r, fsys, "template", nil, nil) })

	require.True(t, report.Failed(), "an unlabelled control passed the guard")
	assert.Contains(t, report.Text(), "template/page.html: line 1: <input> has no label")
}

func TestWellFormedTemplates_TheGuardPassesACleanTree(t *testing.T) {
	fsys := fstest.MapFS{
		"template/page.html":           {Data: []byte(`<form><label for="q">Search</label><input id="q" name="q"></form>`)},
		"template/emails/message.html": {Data: []byte(`<p>An email, <br/> unchecked</p>`)},
		"template/old.html":            {Data: []byte(`<button onclick="go()">Go</button>`)},
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
		"template/page.html": {Data: []byte(`<p>fine</p>`)},
		"template/done.html": {Data: []byte(`<p>fine too</p>`)},
	}

	report := Run(func(r Reporter) {
		assertWellFormedTemplates(r, fsys, "template", []string{"gone/missing.html"}, []string{"done.html", "deleted.html"})
	})

	require.True(t, report.Failed())
	assert.Contains(t, report.Text(), "template/done.html: listed as pending, and already meets every rule; remove it from the list")
	assert.Contains(t, report.Text(), "template/deleted.html: listed, and no such template exists; remove it from the list")
	assert.Contains(t, report.Text(), "template/gone/missing.html: listed, and no such template exists; remove it from the list")
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
