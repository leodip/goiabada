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
		{"a javascript: URL in one branch of a value", `<a href="{{if .x}}javascript:go(){{else}}/safe{{end}}">Go</a>`,
			[]string{`line 1: <a href> is a javascript: URL: register the behaviour from a static script`}},
		{"a script whose src is written in one branch alone", `<script{{if .x}} src="/static/x.js"{{end}}>go()</script>`,
			[]string{`line 1: an inline <script> runs code: move it to a static file, or make it a <script type="application/json"> data block`}},
		{"a JSON data block with more branch combinations than are read",
			`<script type="application/json" id="d">[{{if .a}}1{{else}}2{{end}},{{if .b}}1{{else}}2{{end}},{{if .c}}1{{else}}2{{end}},` +
				`{{if .d}}1{{else}}2{{end}},{{if .e}}1{{else}}2{{end}},{{if .f}}1{{else}}2,{{end}}]</script>`,
			[]string{`line 1: this <script> takes more than 32 branch combinations, more than this guard reads; simplify it`}},
		{"a JSON data block that is not JSON", `<script type="application/json" id="d">{a: 1}</script>`,
			[]string{`line 1: the JSON data block is not valid JSON in every branch, reading each action as a value`}},
		{"a javascript: URL in one of two branches writing the attribute", `<a {{if .x}}href="/safe"{{else}}href="javascript:go()"{{end}}>Go</a>`,
			[]string{`line 1: <a href> is a javascript: URL: register the behaviour from a static script`}},
		{"a script typed JavaScript in one branch of its type", `<script type="{{if .x}}application/json{{else}}text/javascript{{end}}">{}</script>`,
			[]string{`line 1: an inline <script> runs code: move it to a static file, or make it a <script type="application/json"> data block`}},
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
		{"an h1 in a range", `{{range .rows}}<h1>{{.}}</h1>{{else}}<h1>Empty</h1>{{end}}`,
			[]string{`line 1: an <h1> inside a {{range}} repeats on the page: a page has one, its title`}},
		{"an h1 in a range's else", `{{range .rows}}<p>{{.}}</p>{{else}}<h1>Empty</h1>{{end}}`, nil},
		{"a skipped heading level", `<h1>A</h1><h3>B</h3>`,
			[]string{`line 1: <h3> follows an <h1>: heading levels do not skip on the way down`}},
		{"a heading level skipped on some branches", `<h1>A</h1>{{if .x}}{{if .y}}<h2>B</h2>{{end}}{{end}}<h3>C</h3>`,
			[]string{`line 1: <h3> follows an <h1>: heading levels do not skip on the way down`}},
		{"a heading level reached on every branch", `<h1>A</h1>{{if .x}}<h2>B</h2>{{else}}<h2>C</h2>{{end}}<h3>D</h3>`, nil},
		{"a heading in a range's textarea is text", `<h1>A</h1><h2>B</h2><h3>C</h3>{{range .}}<textarea aria-label="Code"><h2>Example</h2></textarea><h4>Row</h4>{{end}}`, nil},
		{"a heading level a called template skips on the next run of a range",
			`{{define "row"}}{{if .x}}<h2>A</h2>{{else}}<h4>B</h4>{{end}}{{end}}<h1>T</h1><h2>S</h2><h3>U</h3>{{range .}}{{template "row" .}}{{end}}`,
			[]string{`line 1: <h4> follows an <h2>: heading levels do not skip on the way down (where template/t.html line 1 calls it)`}},
		{"a positive tabindex", `<div tabindex="2">x</div>`,
			[]string{`line 1: <div> has tabindex 2: a positive tabindex reorders the keyboard path`}},
		{"a positive tabindex in one branch of its value", `<div tabindex="{{if .x}}0{{else}}2{{end}}">x</div>`,
			[]string{`line 1: <div> has tabindex 2: a positive tabindex reorders the keyboard path`}},
		{"a positive tabindex in one of two branches writing it", `<div {{if .x}}tabindex="0"{{else}}tabindex="2"{{end}}>x</div>`,
			[]string{`line 1: <div> has tabindex 2: a positive tabindex reorders the keyboard path`}},
		{"a html without lang", `<html><body></body></html>`,
			[]string{`line 1: <html> has no lang`}},
		{"a description naming no id", `<input id="a" aria-describedby="hint" aria-label="A">`,
			[]string{`line 1: aria-describedby names id "hint", which is not declared wherever the reference renders`}},
		{"a description naming an id shown in one branch alone",
			`{{if .x}}<p id="hint">h</p>{{end}}<input id="a" aria-describedby="hint" aria-label="A">`,
			[]string{`line 1: aria-describedby names id "hint", which is not declared wherever the reference renders`}},
		{"a description naming a missing id in one branch of its value",
			`<p id="hint">h</p><input aria-label="A" aria-describedby="{{if .x}}hint{{else}}missing{{end}}">`,
			[]string{`line 1: aria-describedby names id "missing", which is not declared wherever the reference renders`}},
		{"an id in one branch of its value declared again", `<p id="a">x</p><p id="{{if .x}}a{{else}}b{{end}}">y</p>`,
			[]string{`line 1: id "a" is declared twice where both can render`}},
		{"an id in each branch of its value", `<p id="{{if .x}}a{{else}}b{{end}}">x</p><p id="c">y</p>`, nil},
		{"an id declared in every arm of an if, else if and else",
			`{{if .a}}<p id="h">a</p>{{else if .b}}<p id="h">b</p>{{else}}<p id="h">c</p>{{end}}<input aria-label="X" aria-describedby="h">`, nil},
		{"an id declared in two of three arms",
			`{{if .a}}<p id="h">a</p>{{else if .b}}<p id="h">b</p>{{else}}<p>c</p>{{end}}<input aria-label="X" aria-describedby="h">`,
			[]string{`line 1: aria-describedby names id "h", which is not declared wherever the reference renders`}},
		{"a notice and the field naming it under two ifs on one condition",
			`{{if .error}}<p id="e">E</p>{{end}}<input aria-label="X"{{if .error}} aria-describedby="e"{{end}}>`, nil},
		{"the field naming the notice under one more branch",
			`{{if .error}}<p id="e">E</p>{{end}}{{if .y}}<input aria-label="X"{{if .error}}{{if .z}} aria-describedby="e"{{end}}{{end}}>{{end}}`, nil},
		{"the root's field from another dot", `{{if $.error}}<p id="e">E</p>{{end}}` +
			`{{with .form}}<input aria-label="X"{{if $.error}} aria-describedby="e"{{end}}>{{end}}`, nil},
		{"the dot's field and the root's field in the template's own dot",
			`{{if .error}}<p id="e">E</p>{{end}}<input aria-label="X"{{if $.error}} aria-describedby="e"{{end}}>`, nil},
		{"the dot's field and the root's field in a called template's own dot",
			`{{define "field"}}{{if .error}}<p id="e">E</p>{{end}}<input aria-label="X"{{if $.error}} aria-describedby="e"{{end}}>{{end}}` +
				`{{template "field" .form}}`, nil},
		{"$ assigned", `{{if $.error}}<p id="e">E</p>{{end}}{{$ = .form}}<input aria-label="X"{{if $.error}} aria-describedby="e"{{end}}>`,
			[]string{`line 1: rebinds $, which is the data the template was called with: give the value a variable of its own`}},
		{"$ declared", `{{$ := .form}}<p>{{.x}}</p>`,
			[]string{`line 1: rebinds $, which is the data the template was called with: give the value a variable of its own`}},
		{"$ declared by a range", `<ul>{{range $i, $ := .rows}}<li>{{$i}}</li>{{end}}</ul>`,
			[]string{`line 1: rebinds $, which is the data the template was called with: give the value a variable of its own`}},
		{"two ifs on different conditions",
			`{{if .error}}<p id="e">E</p>{{end}}<input aria-label="X"{{if .other}} aria-describedby="e"{{end}}>`,
			[]string{`line 1: aria-describedby names id "e", which is not declared wherever the reference renders`}},
		{"the same condition read from another dot", `{{if .error}}<p id="e">E</p>{{end}}` +
			`{{with .form}}<input aria-label="X"{{if .error}} aria-describedby="e"{{end}}>{{end}}`,
			[]string{`line 1: aria-describedby names id "e", which is not declared wherever the reference renders`}},
		{"the same condition inside a range", `{{if .error}}<p id="e">E</p>{{end}}` +
			`{{range .rows}}<input aria-label="X"{{if .error}} aria-describedby="e"{{end}}>{{end}}`,
			[]string{`line 1: aria-describedby names id "e", which is not declared wherever the reference renders`}},
		{"the same condition in a template called with other data",
			`{{define "field"}}<input aria-label="X"{{if .error}} aria-describedby="e"{{end}}>{{end}}` +
				`{{if .error}}<p id="e">E</p>{{end}}{{template "field" .form}}`,
			[]string{`line 1: aria-describedby names id "e", which is not declared wherever the reference renders`}},
		{"a condition calling a function is its own",
			`{{if eq .a "x"}}<p id="e">E</p>{{end}}<input aria-label="X"{{if eq .a "x"}} aria-describedby="e"{{end}}>`,
			[]string{`line 1: aria-describedby names id "e", which is not declared wherever the reference renders`}},
		{"an h1 in opposite branches of two ifs on one condition", `{{if .x}}<h1>A</h1>{{end}}{{if .x}}{{else}}<h1>B</h1>{{end}}`, nil},
		{"an id in the same branch of two ifs on one condition", `{{if .x}}<p id="a">x</p>{{end}}{{if .x}}<p id="a">y</p>{{end}}`,
			[]string{`line 1: id "a" is declared twice where both can render`}},
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

// pageDetails reads one page of a fixture tree as the guard does, the page alone and as served in
// the layouts bindings name.
func pageDetails(t *testing.T, fsys fstest.MapFS, bindings map[string][]string, page string) []string {
	t.Helper()
	contents := map[string]string{}
	for path, file := range fsys {
		contents[path] = string(file.Data)
	}
	var out []string
	for _, f := range newTemplateSet("template", contents, nil, bindings).problems(page) {
		out = append(out, f.path+": "+f.detail)
	}
	return out
}

const servedLayout = `<!DOCTYPE html><html lang="en"><head><title>{{template "title" .}}</title></head>` +
	`<body>{{template "body" .}}</body></html>`

// A page is read in each layout a handler renders it in, with the partials, a call resolved where
// it is made: a partial is held to where the page puts it, and the page to the rules about a whole
// page.
func TestWellFormedTemplates_APageIsReadAsServed(t *testing.T) {
	fsys := fstest.MapFS{
		"template/layouts/base.html":     {Data: []byte(servedLayout)},
		"template/layouts/nested.html":   {Data: []byte(`<!DOCTYPE html><html lang="en"><head><title>{{template "title" .}}</title></head><body><p>{{template "body" .}}</p></body></html>`)},
		"template/layouts/extra.html":    {Data: []byte(`<!DOCTYPE html><html lang="en"><head><title>{{template "title" .}}</title></head><body>{{template "body" .}}{{template "footer" .}}</body></html>`)},
		"template/partials/notice.html":  {Data: []byte(`{{define "notice"}}<div class="notice">Saved</div>{{end}}`)},
		"template/partials/label.html":   {Data: []byte(`{{define "searchLabel"}}<label for="q">Search</label>{{end}}`)},
		"template/partials/control.html": {Data: []byte(`{{define "queryControl"}}<input name="q">{{end}}{{define "queryItem"}}<li>Query</li>{{end}}`)},
		"template/good.html": {Data: []byte(`{{define "title"}}Good{{end}}` +
			`{{define "body"}}<main><h1 id="t">Good</h1><section aria-labelledby="t">{{template "notice" .}}</section></main>{{end}}`)},
		"template/nested.html": {Data: []byte(`{{define "title"}}Nested{{end}}` +
			`{{define "body"}}<main><h1>Nested</h1><p>{{template "notice" .}}</p></main>{{end}}`)},
		"template/untitled.html": {Data: []byte(`{{define "title"}}Untitled{{end}}` +
			`{{define "body"}}<main><h2>Section</h2></main>{{end}}`)},
		"template/either.html": {Data: []byte(`{{define "title"}}Either{{end}}` +
			`{{define "body"}}<main>{{if .x}}<h1>A</h1>{{else if .y}}<h1>B</h1>{{else}}<h1>C</h1>{{end}}</main>{{end}}`)},
		"template/across.html": {Data: []byte(`{{define "title"}}Across{{end}}` +
			`{{define "body"}}<main><h1 id="heading">Across</h1>{{template "searchLabel" .}}<input id="q" name="q">{{template "more" .}}</main>{{end}}` +
			`{{define "more"}}<section aria-labelledby="heading"><p>More</p></section>{{end}}`)},
		"template/wrapped.html": {Data: []byte(`{{define "title"}}Wrapped{{end}}` +
			`{{define "body"}}<main><h1>Wrapped</h1><label>Query {{template "queryControl" .}}</label><ul>{{template "queryItem" .}}</ul></main>{{end}}`)},
		"template/bare.html": {Data: []byte(`{{define "title"}}Bare{{end}}` +
			`{{define "body"}}<main><h1>Bare</h1>{{template "queryControl" .}}{{template "queryItem" .}}</main>{{end}}`)},
		"template/unbound.html":  {Data: []byte(`{{define "title"}}Unbound{{end}}{{define "body"}}<main><h1>Unbound</h1></main>{{end}}`)},
		"template/footless.html": {Data: []byte(`{{define "title"}}Footless{{end}}{{define "body"}}<main><h1>Footless</h1></main>{{end}}`)},
		"template/whole.html":    {Data: []byte(`<!DOCTYPE html><html lang="en"><head><title>Whole</title></head><body><h1>Whole</h1>{{template "missing" .}}</body></html>`)},
	}
	bindings := map[string][]string{
		"good.html":     {"layouts/base.html"},
		"nested.html":   {"layouts/base.html"},
		"untitled.html": {"layouts/base.html"},
		"either.html":   {"layouts/base.html"},
		"across.html":   {"layouts/base.html"},
		"footless.html": {"layouts/extra.html"},
		"wrapped.html":  {"layouts/base.html"},
		"bare.html":     {"layouts/base.html"},
	}

	assert.Empty(t, pageDetails(t, fsys, bindings, "template/good.html"), "the layout that would nest the page in a <p> is no handler's, so it is not read")
	assert.Equal(t, []string{
		"template/partials/notice.html: line 1: <div> inside a <p>, which a browser closes before it" +
			" (where template/nested.html line 1 calls it) (in template/layouts/base.html)",
	}, pageDetails(t, fsys, bindings, "template/nested.html"))
	assert.Equal(t, []string{
		"template/untitled.html: line 1: the page has no <h1> on every branch (in template/layouts/base.html)",
	}, pageDetails(t, fsys, bindings, "template/untitled.html"))
	assert.Empty(t, pageDetails(t, fsys, bindings, "template/either.html"), "an <h1> in every arm is an <h1> on every branch")
	assert.Empty(t, pageDetails(t, fsys, bindings, "template/across.html"), "a label in a partial and an id in another template of the page")
	assert.Empty(t, pageDetails(t, fsys, bindings, "template/partials/control.html"), "a partial read alone is held to its structure, its context being the page's")
	assert.Empty(t, pageDetails(t, fsys, bindings, "template/wrapped.html"), "a control a partial writes inside the page's label, a list item inside its list")
	assert.Equal(t, []string{
		"template/partials/control.html: line 1: <input> has no label: give it an id a <label for> names, or aria-label" +
			" (where template/bare.html line 1 calls it) (in template/layouts/base.html)",
		"template/partials/control.html: line 1: <li> outside a list (where template/bare.html line 1 calls it) (in template/layouts/base.html)",
	}, pageDetails(t, fsys, bindings, "template/bare.html"))
	assert.Equal(t, []string{
		"template/unbound.html: line 1: no handler renders this page: no RenderTemplate call names it",
	}, pageDetails(t, fsys, bindings, "template/unbound.html"))
	assert.Equal(t, []string{
		`template/layouts/extra.html: line 1: calls template "footer", which neither the page, its layout nor a partial defines (in template/layouts/extra.html)`,
	}, pageDetails(t, fsys, bindings, "template/footless.html"))
	assert.Equal(t, []string{
		`template/whole.html: line 1: calls template "missing", which neither the page, its layout nor a partial defines`,
	}, pageDetails(t, fsys, bindings, "template/whole.html"))
}

// The pages a handler renders, and the layout it renders each in, are read from the calls it makes:
// a literal, or a variable its function assigns literals and nothing else to; a call passing its
// function's own parameters, never reassigned, forwards and binds nothing; any other call is
// unresolved.
func TestWellFormedTemplates_TheBindingsAreTheHandlersCalls(t *testing.T) {
	handlers := fstest.MapFS{
		"handlers/pages.go": {Data: []byte(`package handlers

func Pwd(h Renderer) {
	h.RenderTemplate(w, r, "/layouts/auth_layout.html", "/auth_pwd.html", nil)
}

func Otp(h Renderer, enrol bool) {
	template := "/auth_otp.html"
	if enrol {
		template = "/auth_otp_enrollment.html"
	}
	h.RenderTemplate(w, r, "/layouts/auth_layout.html", template, nil)
}

func Mail(h Renderer) {
	h.RenderTemplateToBuffer(r, "/layouts/email_layout.html", "/emails/welcome.html", nil)
}

func (h *Renderer) RenderTemplate(w W, r R, layoutName string, templateName string, data D) error {
	return h.RenderTemplateToBuffer(r, layoutName, templateName, data)
}

func Odd(h Renderer, pages map[string]string) {
	h.RenderTemplate(w, r, "/layouts/auth_layout.html", pages["x"], nil)
}

func Chosen(h Renderer, x bool) {
	page := "/p.html"
	if x {
		page = choosePage()
	}
	h.RenderTemplate(w, r, "/layouts/base.html", page, nil)
}

func Half(h Renderer, layoutName string, pages map[string]string) {
	h.RenderTemplate(w, r, layoutName, pages["x"], nil)
}

func Defaulted(h Renderer, page string) {
	if page == "" {
		page = "/fallback.html"
	}
	h.RenderTemplate(w, r, "/layouts/base.html", page, nil)
}
`)},
		"handlers/pages_test.go": {Data: []byte(`package handlers

func TestX(h Renderer) { h.RenderTemplate(w, r, "/layouts/test.html", "/test.html", nil) }
`)},
	}

	bindings, unresolved, err := findRenderBindings(handlers)
	require.NoError(t, err)
	assert.Equal(t, map[string][]string{
		"auth_pwd.html":            {"layouts/auth_layout.html"},
		"auth_otp.html":            {"layouts/auth_layout.html"},
		"auth_otp_enrollment.html": {"layouts/auth_layout.html"},
		"emails/welcome.html":      {"layouts/email_layout.html"},
	}, bindings)
	require.Len(t, unresolved, 4, "a name not read from literals alone, a forwarder's other name unread, a parameter reassigned")
	for i, line := range []string{"24", "32", "36", "43"} {
		assert.Contains(t, unresolved[i], "handlers/pages.go:"+line+":")
		assert.Contains(t, unresolved[i], "cannot tell which page it renders")
	}
}

// handlerSource is a handler file rendering each page in layouts/base.html.
func handlerSource(pages ...string) fstest.MapFS {
	src := "package handlers\n\nfunc Render(h Renderer) {\n"
	for _, page := range pages {
		src += `	h.RenderTemplate(w, r, "/layouts/base.html", "/` + page + `", nil)` + "\n"
	}
	return fstest.MapFS{"handlers.go": {Data: []byte(src + "}\n")}}
}

func TestWellFormedTemplates_TheGuardFailsOnATreeThatBreaksARule(t *testing.T) {
	fsys := fstest.MapFS{
		"template/layouts/base.html": {Data: []byte(servedLayout)},
		"template/page.html": {Data: []byte(`{{define "title"}}Search{{end}}` +
			`{{define "body"}}<main><h1>Search</h1><form><input name="q"></form></main>{{end}}`)},
	}

	report := Run(func(r Reporter) {
		assertWellFormedTemplates(r, fsys, "template", handlerSource("page.html"), nil, nil)
	})

	require.True(t, report.Failed(), "an unlabelled control passed the guard")
	assert.Contains(t, report.Text(), "template/page.html: line 1: <input> has no label")
}

func TestWellFormedTemplates_TheGuardPassesACleanTree(t *testing.T) {
	fsys := fstest.MapFS{
		"template/layouts/base.html": {Data: []byte(servedLayout)},
		"template/page.html": {Data: []byte(`{{define "title"}}Search{{end}}` +
			`{{define "body"}}<main><h1>Search</h1><form><label for="q">Search</label><input id="q" name="q"></form></main>{{end}}`)},
		"template/emails/message.html": {Data: []byte(`<p>An email, <br/> unchecked</p>`)},
		"template/old.html":            {Data: []byte(`{{define "title"}}Old{{end}}{{define "body"}}<button onclick="go()">Go</button>{{end}}`)},
	}

	report := Run(func(r Reporter) {
		assertWellFormedTemplates(r, fsys, "template", handlerSource("page.html", "old.html"), []string{"emails/"}, []string{"old.html"})
	})

	assert.False(t, report.Failed(), "a clean tree failed the guard: %s", report.Text())
}

// The pending list only shrinks: a pending page that already meets every rule, and an entry naming
// no template, are each reported.
func TestWellFormedTemplates_ThePendingListOnlyShrinks(t *testing.T) {
	fsys := fstest.MapFS{
		"template/page.html": {Data: []byte(`<!DOCTYPE html><html lang="en"><head><title>Fine</title></head><body><h1>Fine</h1></body></html>`)},
		"template/done.html": {Data: []byte(`<!DOCTYPE html><html lang="en"><head><title>Done</title></head><body><h1>Fine too</h1></body></html>`)},
	}

	report := Run(func(r Reporter) {
		assertWellFormedTemplates(r, fsys, "template", handlerSource("other.html"), []string{"gone/missing.html"}, []string{"done.html", "deleted.html"})
	})

	require.True(t, report.Failed())
	assert.Contains(t, report.Text(), "template/done.html: listed as pending, and already meets every rule; remove it from the list")
	assert.Contains(t, report.Text(), "template/deleted.html: listed, and no such template exists; remove it from the list")
	assert.Contains(t, report.Text(), "template/gone/missing.html: listed, and no such template exists; remove it from the list")
	assert.NotContains(t, report.Text(), "template/page.html")
}

func TestWellFormedTemplates_AWalkThatReachesNothingIsFatal(t *testing.T) {
	empty := fstest.MapFS{"template/readme.txt": {Data: []byte("no pages here")}}
	report := Run(func(r Reporter) {
		assertWellFormedTemplates(r, empty, "template", handlerSource("page.html"), nil, nil)
	})
	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked no .html files under template")

	exempt := fstest.MapFS{"template/emails/a.html": {Data: []byte(`<p>x</p>`)}}
	report = Run(func(r Reporter) {
		assertWellFormedTemplates(r, exempt, "template", handlerSource("page.html"), []string{"emails/"}, nil)
	})
	require.True(t, report.Stopped, "a walk whose every page is exempt checks nothing, and must be fatal")
	assert.Contains(t, report.Fatal, "every .html file under template is out of scope or pending")

	report = Run(func(r Reporter) {
		assertWellFormedTemplates(r, exempt, "template", fstest.MapFS{"x.go": {Data: []byte("package x\n")}}, nil, nil)
	})
	require.True(t, report.Stopped, "handlers naming no page leave every page unread as served, and must be fatal")
	assert.Contains(t, report.Fatal, "found no RenderTemplate call naming a layout and a page")
}
