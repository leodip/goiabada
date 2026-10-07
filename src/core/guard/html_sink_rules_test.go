package guard

// The rule table AssertNoHTMLSinks enforces, over fstest.MapFS fixtures walked through the same
// finder and reporting half the two servers' web packages reach.
//
// The synthetic half exists because the real half cannot fail informatively: the auth server is
// clean and the admin console's sites are all allowlisted, so both callers pass whether each rule
// still fires or has quietly stopped matching anything. Every refused row below is a line the finder
// must report; every allowed row is one it must leave alone.

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// renderHTMLSinks renders findings as "<path>:<line>: <text>" so a failure names what was missed
// or over-matched rather than printing a struct.
func renderHTMLSinks(found []htmlSink) []string {
	out := make([]string, 0, len(found))
	for _, f := range found {
		out = append(out, fmt.Sprintf("%s:%d: %s", f.path, f.line, f.text))
	}
	sort.Strings(out)
	return out
}

// script wraps body in a page the way the templates carry their code: markup around one inline
// script element.
func script(body string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte("{{define \"body\"}}\n<div id=\"x\"></div>\n<script>\n" + body + "\n</script>\n{{end}}\n")}
}

// TestHTMLSinks_TheRefusedShapes holds every shape decision 4 of #120 refuses, each on its own line
// so a finding names it. Line 4 of a fixture page is the first line of its script body.
func TestHTMLSinks_TheRefusedShapes(t *testing.T) {
	fsys := fstest.MapFS{
		// innerHTML written from anything but one literal.
		"template/variable.html":     script(`cell.innerHTML = value.Scope;`),
		"template/call.html":         script(`cell.innerHTML = getTrashCanMarkup("", "f();", "");`),
		"template/concat.html":       script(`cell.innerHTML = "<span>{{ T $.ctx "a" }}" + maxRows + "</span>";`),
		"template/concat_later.html": script("cell.innerHTML = \"<b>\"\n    + name;"),
		"template/backtick.html":     script("cell.innerHTML = `<a href=\"/u/${id}\">${email}</a>`;"),
		"template/static_tick.html":  script("cell.innerHTML = `static`;"),
		"template/action.html":       script(`cell.innerHTML = "{{ .user.Email }}";`),
		"template/kv_action.html":    script(`cell.innerHTML = "{{ T $.ctx "k" "name" .user.Email }}";`),
		"template/bare_action.html":  script(`cell.innerHTML = {{ .markup }};`),
		"template/ternary.html":      script(`cell.innerHTML = ok ? "{{ T $.ctx "a" }}" : "";`),
		"template/append.html":       script(`cell.innerHTML += "{{ T $.ctx "a" }}";`),
		// innerHTML read, by any route.
		"template/read.html":    script(`const uri = row.getElementsByTagName("td")[0].innerHTML;`),
		"template/compare.html": script(`if (cell.innerHTML == "") { go(); }`),
		// The other sinks, whatever they are handed.
		"template/outer.html":    script(`row.outerHTML = "<tr></tr>";`),
		"template/adjacent.html": script(`row.insertAdjacentHTML("beforeend", "<td></td>");`),
		"template/write.html":    script(`document.write("<p>x</p>");`),
		"template/writeln.html":  script(`document.writeln(x);`),
		"template/onclick.html":  script(`b.setAttribute("onclick", "Add(event, this, " + user.Id + ");");`),
		"template/onload.html":   script(`img.setAttribute('ONLOAD', handler);`),
		"template/computed.html": script(`b.setAttribute(attributeName, value);`),
		// A member named by a fixed string is the member, by either quote and read or written.
		"template/computed_write.html":  script(`cell["innerHTML"] = row.Label;`),
		"template/computed_read.html":   script("const label = cell[`innerHTML`];"),
		"template/computed_method.html": script(`button["setAttribute"]("onclick", handlerText);`),
		"template/computed_write2.html": script(`document['write'](row.Label);`),
		// A template literal's interpolation is code.
		"template/interpolation.html": script("const label = `${cell.innerHTML = row.Label}`;"),
		// An on... attribute and a javascript: URL are code, their character references decoded
		// as the browser decodes them, and so is a script element written in capitals.
		"template/inline.html":      {Data: []byte("<div>\n<button onclick=\"cell.innerHTML = row.Label;\">Update</button>\n</div>\n")},
		"template/inline_ref.html":  {Data: []byte("<div>\n<button ONCLICK='cell.inner&#72;TML = row.Label' class=\"{{ if .x }}a{{ end }}\">x</button>\n</div>\n")},
		"template/inline_bare.html": {Data: []byte("<div>\n<img src=x onerror=cell.innerHTML=row.Label>\n</div>\n")},
		"template/js_url.html":      {Data: []byte("<div>\n<a href=\" JavaScript:document.write(row.Label)\">x</a>\n</div>\n")},
		"template/upper.html":       {Data: []byte("<div>\n<SCRIPT>\ncell.innerHTML = row.Label;\n</SCRIPT>\n</div>\n")},
		// A static script is held like a page, and a regex literal holding a quote does not
		// derail the reading of the line after it.
		"static/utils.js": {Data: []byte("function esc(s) {\n  return s.replace(/\"/g, \"&quot;\").replace(/'/g, \"&#039;\");\n}\nel.innerHTML = message;\n")},
	}

	found, n, err := findHTMLSinks(fsys)
	require.NoError(t, err)
	assert.Equal(t, len(fsys), n, "the finder read the wrong set of files")

	assert.Equal(t, []string{
		`static/utils.js:4: el.innerHTML = message;`,
		`template/action.html:4: cell.innerHTML = "{{ .user.Email }}";`,
		`template/adjacent.html:4: row.insertAdjacentHTML("beforeend", "<td></td>");`,
		`template/append.html:4: cell.innerHTML += "{{ T $.ctx "a" }}";`,
		`template/backtick.html:4: cell.innerHTML = ` + "`<a href=\"/u/${id}\">${email}</a>`;",
		`template/bare_action.html:4: cell.innerHTML = {{ .markup }};`,
		`template/call.html:4: cell.innerHTML = getTrashCanMarkup("", "f();", "");`,
		`template/compare.html:4: if (cell.innerHTML == "") { go(); }`,
		`template/computed.html:4: b.setAttribute(attributeName, value);`,
		`template/computed_method.html:4: button["setAttribute"]("onclick", handlerText);`,
		"template/computed_read.html:4: const label = cell[`innerHTML`];",
		`template/computed_write.html:4: cell["innerHTML"] = row.Label;`,
		`template/computed_write2.html:4: document['write'](row.Label);`,
		`template/concat.html:4: cell.innerHTML = "<span>{{ T $.ctx "a" }}" + maxRows + "</span>";`,
		`template/concat_later.html:4: cell.innerHTML = "<b>"`,
		`template/inline.html:2: <button onclick="cell.innerHTML = row.Label;">Update</button>`,
		`template/inline_bare.html:2: <img src=x onerror=cell.innerHTML=row.Label>`,
		`template/inline_ref.html:2: <button ONCLICK='cell.inner&#72;TML = row.Label' class="{{ if .x }}a{{ end }}">x</button>`,
		"template/interpolation.html:4: const label = `${cell.innerHTML = row.Label}`;",
		`template/js_url.html:2: <a href=" JavaScript:document.write(row.Label)">x</a>`,
		`template/kv_action.html:4: cell.innerHTML = "{{ T $.ctx "k" "name" .user.Email }}";`,
		`template/onclick.html:4: b.setAttribute("onclick", "Add(event, this, " + user.Id + ");");`,
		`template/onload.html:4: img.setAttribute('ONLOAD', handler);`,
		`template/outer.html:4: row.outerHTML = "<tr></tr>";`,
		`template/read.html:4: const uri = row.getElementsByTagName("td")[0].innerHTML;`,
		"template/static_tick.html:4: cell.innerHTML = `static`;",
		`template/ternary.html:4: cell.innerHTML = ok ? "{{ T $.ctx "a" }}" : "";`,
		`template/upper.html:3: cell.innerHTML = row.Label;`,
		`template/variable.html:4: cell.innerHTML = value.Scope;`,
		`template/write.html:4: document.write("<p>x</p>");`,
		`template/writeln.html:4: document.writeln(x);`,
	}, renderHTMLSinks(found))
}

// TestHTMLSinks_TheAllowedShapes holds what decision 4 of #120 leaves alone: an innerHTML write
// from one literal of static text and catalog lookups, or the empty string, and every mention of a
// sink that is not code.
func TestHTMLSinks_TheAllowedShapes(t *testing.T) {
	fsys := fstest.MapFS{
		"template/catalog.html": script(
			`removed.innerHTML = "{{ T $.ctx "adminconsole.removed_label" }}";` + "\n" +
				`cell1.innerHTML = "{{ T $.ctx "adminconsole.none_yet" }}"` + "\n" +
				`cell2.innerHTML = "&nbsp;";` + "\n" +
				`tbody.innerHTML = '';` + "\n" +
				`label.innerHTML = "{{- T .ctx "a" -}} / {{ T $.ctx "b" }}";` + "\n" +
				`cell.innerHTML = "<span class='p-1 bg-warning'>{{ T $.ctx "none_found" }}</span>";` + "\n" +
				`if (x) { cell.innerHTML = "" }`),
		// The words in comments, strings and markup are not sinks.
		"template/mentions.html": {Data: []byte(`<p>innerHTML and document.write are named here</p>
{{/* outerHTML in a template comment */}}
<!-- insertAdjacentHTML in a markup comment -->
<button onclick="go()" title="innerHTML = x" data-x='{{ .y }}'>x</button>
<button onclick="cell.textContent = &quot;{{ T $.ctx "a" }}&quot;; el.innerHTML = '{{ T $.ctx "b" }}'">y</button>
<a href="/innerHTML">javascript: is text here</a>
<script>
  const names = ["innerHTML"], picked = names["length"];
  const label = ` + "`innerHTML ${value}`" + `;
  // textContent, not innerHTML: a redirect URI is data.
  /* reading innerHTML re-serialises the value */
  const msg = "showModalDialog assigns its message to innerHTML";
  const pattern = /innerHTML/;
  cell1.textContent = uri;
  el.setAttribute("class", "px-2");
  el.setAttribute('data-permissionid', id);
  const keys = {{ .keys }};
</script>
<script src="/static/utils.js"></script>`)},
		// A static script is not a template, so braces in its strings are text, not actions.
		"static/utils.js": {Data: []byte("const s = \"{{param}}\";\nel.innerHTML = \"{{param}}\";\nconst q = a / b; el.innerHTML = \"\";\n")},
		// Neither a page nor a script, whatever it says.
		"static/main.css":    {Data: []byte(`.x { content: "innerHTML = x"; }`)},
		"template/notes.txt": {Data: []byte(`el.innerHTML = value;`)},
	}

	found, n, err := findHTMLSinks(fsys)
	require.NoError(t, err)
	assert.Empty(t, renderHTMLSinks(found))
	assert.Equal(t, 3, n, "the finder read the wrong set of files")
}

// TestHTMLSinks_FailsOnASinkAndOnAStaleAllowance drives the reporting half: the cases above assert
// on what the finder returned, and the lines that turn a finding into a failure are reached only
// here. An allowance admits its own site and nothing else, and one that admits nothing fails, so a
// fixed site has to leave the list.
func TestHTMLSinks_FailsOnASinkAndOnAStaleAllowance(t *testing.T) {
	fsys := fstest.MapFS{
		"template/a.html": script("cell.innerHTML = value;\nother.innerHTML = value;\ncell.innerHTML = value;"),
	}
	allow := []HTMLSinkAllowance{
		{File: "template/a.html", Text: "cell.innerHTML = value;"},
		{File: "template/a.html", Text: "gone.innerHTML = value;"},
		{File: "template/b.html", Text: "cell.innerHTML = value;"},
	}

	report := Run(func(r Reporter) { assertNoHTMLSinks(r, allow, fsys) })

	require.True(t, report.Failed(), "an unallowed sink and two stale allowances passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	// One allowance admits one occurrence: the second identical line is still a finding, and the
	// first is the one admitted.
	assert.Equal(t, []string{
		`template/a.html:5: other.innerHTML = value;`,
		`template/a.html:6: cell.innerHTML = value;`,
	}, prefixed(report.Errors, "template/a.html:"))
	assert.Contains(t, report.Text(), `allowance {template/a.html "gone.innerHTML = value;"} matches nothing`)
	assert.Contains(t, report.Text(), `allowance {template/b.html "cell.innerHTML = value;"} matches nothing`)
	assert.Len(t, report.Errors, 4)
}

// TestHTMLSinks_PassesWhenEverySiteIsAllowed is the other direction: each site named once, and
// twice where it occurs twice, and nothing else.
func TestHTMLSinks_PassesWhenEverySiteIsAllowed(t *testing.T) {
	fsys := fstest.MapFS{
		"template/a.html": script("cell.innerHTML = value;\nremoved.innerHTML = \"{{ T $.ctx \"k\" }}\";\ncell.innerHTML = value;"),
		"static/utils.js": {Data: []byte("el.innerHTML = message;\n")},
	}
	allow := []HTMLSinkAllowance{
		{File: "template/a.html", Text: "cell.innerHTML = value;"},
		{File: "template/a.html", Text: "cell.innerHTML = value;"},
		{File: "static/utils.js", Text: "el.innerHTML = message;"},
	}

	report := Run(func(r Reporter) { assertNoHTMLSinks(r, allow, fsys) })

	assert.False(t, report.Failed(), report.Text())
}

// TestHTMLSinks_AWalkThatReachesNothingIsFatal pins the walk's own failure. Each rule passes
// vacuously over an empty set, so a tree reaching no page or script, an embed pattern that stopped
// matching, must stop the guard rather than pass it, and so must each tree on its own: a caller
// handing two passes nothing when either reaches nothing.
func TestHTMLSinks_AWalkThatReachesNothingIsFatal(t *testing.T) {
	pages := fstest.MapFS{"template/a.html": script(`cell.textContent = value;`)}
	empty := fstest.MapFS{"static/main.css": {Data: []byte(`.x {}`)}}

	report := Run(func(r Reporter) { assertNoHTMLSinks(r, nil, pages, empty) })

	require.True(t, report.Stopped, "a tree with no page or script passed the guard")
	assert.Contains(t, report.Fatal, "reached no .html or .js file")
}

// prefixed returns the first line of each of errs that starts with prefix, in order: a finding's
// location and text, without the explanation under it.
func prefixed(errs []string, prefix string) []string {
	var out []string
	for _, e := range errs {
		if strings.HasPrefix(e, prefix) {
			out = append(out, strings.SplitN(e, "\n", 2)[0])
		}
	}
	return out
}
