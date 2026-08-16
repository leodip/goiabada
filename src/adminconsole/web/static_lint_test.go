package web

import (
	"regexp"
	"strings"
	"testing"
)

// utilsJS returns the real embedded static/utils.js, the file the browser is served.
//
// Reading it through staticFS rather than off disk is deliberate: it is the same byte stream
// StaticFS() hands the router, so a file that stopped being embedded fails here rather than
// passing a lint and then 404ing in production.
func utilsJS(t *testing.T) string {
	t.Helper()
	b, err := staticFS.ReadFile("static/utils.js")
	if err != nil {
		t.Fatalf("reading static/utils.js: %v", err)
	}
	return string(b)
}

// splitJoinRe matches one `.split(<literal>).join(<literal>)` link of the escapeHtml chain,
// in either JavaScript quote style, since the chain uses both.
var splitJoinRe = regexp.MustCompile(`\.split\(\s*("(?:[^"\\]*)"|'(?:[^'\\]*)')\s*\)\s*\.join\(\s*("(?:[^"\\]*)"|'(?:[^'\\]*)')\s*\)`)

// escapeHtmlBodyRe captures the body of function escapeHtml, up to the first closing brace in
// column zero. The chain lives entirely inside it, so a `.split().join()` elsewhere in the file
// cannot be mistaken for part of the escaping.
var escapeHtmlBodyRe = regexp.MustCompile(`(?s)function\s+escapeHtml\s*\([^)]*\)\s*\{(.*?)\n\}`)

// jsLiteral decodes a JavaScript string literal that contains no backslash escapes.
//
// The regex above admits no backslash, so a literal that gains one stops matching and is reported
// as a missing link rather than being silently mis-decoded. That is the intended boundary: this
// guard would rather fail and be updated than approximate what the browser does with `\\`.
func jsLiteral(s string) string {
	return s[1 : len(s)-1]
}

// TestUtilsJS_ErrorDescriptionIsEscaped pins the call site half of #122's fix: every read of the
// server-supplied err.error_description in utils.js goes through escapeHtml before it reaches
// showModalDialog, which assigns its message to innerHTML.
//
// The reason this needs a lint is that nothing else in any tier can observe it. The Go handler test
// for this path (adminclienthandlers) asserts the status and the JSON bytes the API proxy writes,
// which is the correct seam for what it covers and stops one layer short of the browser. There is no
// JavaScript test runner anywhere in this repository. So deleting the escapeHtml call leaves the
// complete admin console tier green while the administrator's own raw input is parsed as markup in a
// script sink. That mutation was run and it survived, which is what produced this file.
//
// The claim is lexical and stops there: no occurrence of the string err.error_description appears
// outside an escapeHtml( call. A future comment spelling err.error_description in prose would trip
// this, which is a loud, safe direction to fail in; update the guard rather than the comment. A sink
// that reaches the same value by another spelling, destructuring it or aliasing it first, is out of
// this check's reach, and closing that would mean parsing the file with a JavaScript parser this
// module does not depend on.
func TestUtilsJS_ErrorDescriptionIsEscaped(t *testing.T) {
	const (
		sink    = "err.error_description"
		wrapper = "escapeHtml("
	)

	content := utilsJS(t)

	found := 0
	for i := 0; ; {
		j := strings.Index(content[i:], sink)
		if j < 0 {
			break
		}
		at := i + j
		found++
		if !strings.HasSuffix(content[:at], wrapper) {
			line := 1 + strings.Count(content[:at], "\n")
			t.Errorf("static/utils.js:%d: %s is not wrapped in %s; showModalDialog assigns "+
				"its message to innerHTML, so the server-supplied description must be escaped (#122)",
				line, sink, wrapper)
		}
		i = at + len(sink)
	}

	// If the sink is renamed or the branch is restructured, every assertion above passes
	// vacuously and this file would go on reporting success while guarding nothing.
	if found == 0 {
		t.Errorf("static/utils.js: no %s found; the AJAX error branch was renamed or removed, "+
			"so this guard no longer covers anything. Update it to name the new sink", sink)
	}
}

// TestUtilsJS_EscapeHtmlEscapes pins the function half: escapeHtml, as written in the real file,
// still turns each of the five HTML-significant characters into its entity, and still does the
// ampersand first.
//
// It does not read the chain and check it looks right. It extracts the .split().join() pairs from
// the embedded source and replays them in order over a table of adversarial values, so the assertion
// is about what the function computes rather than about which substrings appear in it. That
// distinction is what makes the ordering observable: moving the ampersand link to the end leaves all
// five replacements present, and a "contains all five" check would pass, but every entity the other
// four produce then has its own ampersand escaped and "<" renders as "&amp;lt;" instead of "&lt;".
// The table below fails on that.
//
// The boundary, stated plainly: this replays JavaScript semantics in Go. String.prototype.split with
// a string separator followed by join is a global literal replace, which strings.ReplaceAll matches
// exactly, so the simulation is faithful for the chain shape this function has. It is not a
// JavaScript engine, and it proves nothing about a rewrite of escapeHtml into some other shape: a
// body that stops matching escapeHtmlBodyRe, or that escapes by some means other than split/join,
// fails here rather than being approximated, and whoever makes that change owns replacing this guard
// with one that can see the new shape.
func TestUtilsJS_EscapeHtmlEscapes(t *testing.T) {
	content := utilsJS(t)

	body := escapeHtmlBodyRe.FindStringSubmatch(content)
	if body == nil {
		t.Fatalf("static/utils.js: function escapeHtml not found, or its body is not a brace " +
			"block ending at column zero; this guard cannot read it (#122)")
	}

	// The chain must start from String(str), or a description that is absent or not a string
	// throws a TypeError on .split and the modal never opens at all.
	if !strings.Contains(body[1], "String(str)") {
		t.Errorf("static/utils.js: escapeHtml no longer coerces with String(str); a missing or " +
			"non-string error_description would throw on .split and suppress the whole dialog")
	}

	type link struct{ from, to string }
	var chain []link
	for _, m := range splitJoinRe.FindAllStringSubmatch(body[1], -1) {
		chain = append(chain, link{from: jsLiteral(m[1]), to: jsLiteral(m[2])})
	}

	// Every HTML-significant character, and the entity it must become. Dropping any one of these
	// links is a live XSS on the innerHTML sink for the character it stops covering.
	want := []link{
		{"&", "&amp;"},
		{"<", "&lt;"},
		{">", "&gt;"},
		{`"`, "&quot;"},
		{"'", "&#39;"},
	}
	for _, w := range want {
		found := false
		for _, c := range chain {
			if c.from == w.from {
				found = true
				if c.to != w.to {
					t.Errorf("static/utils.js: escapeHtml maps %q to %q, want %q",
						w.from, c.to, w.to)
				}
			}
		}
		if !found {
			t.Errorf("static/utils.js: escapeHtml no longer replaces %q; that character reaches "+
				"showModalDialog's innerHTML assignment unescaped (#122)", w.from)
		}
	}

	// Replay the chain as the browser would and assert the result. This is what catches a
	// reordering, which the per-character check above cannot see.
	apply := func(s string) string {
		for _, c := range chain {
			s = strings.ReplaceAll(s, c.from, c.to)
		}
		return s
	}

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"the payload the sink would execute", `<img src=x onerror=alert(1)>`,
			`&lt;img src=x onerror=alert(1)&gt;`},
		{"ampersand first, so entities are not double-escaped", `<`, `&lt;`},
		{"bare ampersand", `&`, `&amp;`},
		{"greater than", `>`, `&gt;`},
		{"double quote", `"`, `&quot;`},
		{"single quote", `'`, `&#39;`},
		{"entity-shaped input stays text rather than becoming a second-pass tag",
			`&lt;script&gt;`, `&amp;lt;script&amp;gt;`},
		{"all five together", `a&<>"'z`, `a&amp;&lt;&gt;&quot;&#39;z`},
		{"the real refusal message is unchanged",
			`Redirect URI must be an absolute URI: //evil.example/cb`,
			`Redirect URI must be an absolute URI: //evil.example/cb`},
		{"empty", ``, ``},
	}
	for _, tc := range cases {
		if got := apply(tc.in); got != tc.want {
			t.Errorf("%s: escapeHtml(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}
