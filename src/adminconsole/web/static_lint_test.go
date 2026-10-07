package web

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
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

// TestUtilsJS_ErrorDescriptionReachesTheDialogAsText pins what replaced #122's fix: every read of
// the server-supplied err.error_description in utils.js is handed to showModalDialog whole, as its
// message, and showModalDialog shows a message its builders did not build as text. The description
// can echo back what the administrator typed, since handlers forward the API's 400 description
// verbatim so a validation failure is readable.
//
// #122 escaped it at the call site, because the dialog parsed every message as HTML. Since #120 the
// dialog parses only what dialogMarkup or dialogMarkupFormat built, so escaping the description
// before it reaches the dialog would now show its entities as typed: "a < b" as "a &lt; b". Wrapping
// it in either builder is refused too, since it carries no markup to keep. What keeps it from the
// HTML parser is the dialog's plain branch, which core/guard.AssertNoHTMLSinks holds to writing no
// innerHTML, and which this test reads as a textContent write besides.
//
// Lexical, like its neighbours, because no JavaScript runs in any tier: each occurrence of
// err.error_description outside a comment must be the whole third argument of a showModalDialog
// call. A sink that reaches the same value by another spelling, destructuring it or aliasing it
// first, is out of this check's reach.
func TestUtilsJS_ErrorDescriptionReachesTheDialogAsText(t *testing.T) {
	content := utilsJS(t)
	toks := guard.TokenizeScript(content)

	isDescription := func(toks []guard.ScriptToken, i int) bool {
		return i+2 < len(toks) && toks[i].Is(guard.ScriptIdent, "err") && toks[i+1].Is(guard.ScriptPunct, ".") &&
			toks[i+2].Is(guard.ScriptIdent, "error_description")
	}

	whole := map[int]bool{}
	for i, tok := range toks {
		if !tok.Is(guard.ScriptIdent, "showModalDialog") || (i > 0 && toks[i-1].Is(guard.ScriptIdent, "function")) ||
			i+1 >= len(toks) || !toks[i+1].Is(guard.ScriptPunct, "(") {
			continue
		}
		if arg := callArgument(toks, i+2, 2); len(arg) == 3 && isDescription(arg, 0) {
			whole[arg[0].Offset] = true
		}
	}

	found := 0
	for i := range toks {
		if !isDescription(toks, i) {
			continue
		}
		found++
		if !whole[toks[i].Offset] {
			line := toks[i].Line
			t.Errorf("static/utils.js:%d: err.error_description is not handed to showModalDialog "+
				"whole, as its message; the dialog shows a plain message as text, so escaping it "+
				"first shows its entities as typed, and it carries no markup for a builder to keep (#120)",
				line)
		}
	}
	if found == 0 {
		t.Errorf("static/utils.js: no err.error_description found; the AJAX error branch was renamed " +
			"or removed, so this check no longer covers anything. Update it to name the new sink")
	}

	_, body, ok := functionBody(content, "showModalDialog")
	if !ok {
		t.Fatalf("static/utils.js: function showModalDialog not found, or its body cannot be read; " +
			"this check cannot read it (#120)")
	}
	if !strings.Contains(body, ".textContent = message;") {
		t.Errorf("static/utils.js: showModalDialog no longer writes a plain message through " +
			"textContent; a message its builders did not build is shown as text (#120)")
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

	// The chain must start from String(str), or a builder value that is not a string, the unexpected
	// error dialog's status number or Error, throws a TypeError on .split and the modal never opens
	// at all.
	if !strings.Contains(body[1], "String(str)") {
		t.Errorf("static/utils.js: escapeHtml no longer coerces with String(str); a non-string " +
			"builder value would throw on .split and suppress the whole dialog")
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
				"the dialog's markup branch unescaped through a builder value (#120)", w.from)
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

// imageUploadJS returns the real embedded static/image-upload.js, for the same reason utilsJS
// reads through staticFS: it is the byte stream the browser is served.
func imageUploadJS(t *testing.T) string {
	t.Helper()
	b, err := staticFS.ReadFile("static/image-upload.js")
	if err != nil {
		t.Fatalf("reading static/image-upload.js: %v", err)
	}
	return string(b)
}

// TestImageUploadJS_ReadsErrorDescription pins the browser half of the picture and logo upload
// change in #279.
//
// The three upload handlers used to write their own {"success": false, "error": <sentence>} body,
// and this script read data.error to fill the modal. They now answer through the console's shared
// JSON writers, whose body is RFC 6749 5.2's shape: error carries the machine code ("not_found",
// "invalid_request_body", "server_error") and error_description carries the sentence. So a read of
// data.error alone still works, still shows something, and shows the administrator the word
// "server_error" where a sentence used to be.
//
// Nothing in any tier can observe that. The Go tests for these handlers assert the *ErrorDetail the
// handler hands the writer, which is the right seam and stops one layer short of the browser, and
// this repository has no JavaScript test runner. Reverting the script alone therefore leaves every
// tier green while the modal degrades to a bare code, which is exactly the shape of regression a
// lint exists for.
//
// The claim is lexical and narrow: each !response.ok branch reads error_description before it falls
// back to error. Restructuring the branches, or reaching the value under another name, is out of
// reach here and is the change's author's to re-cover.
func TestImageUploadJS_ReadsErrorDescription(t *testing.T) {
	content := imageUploadJS(t)

	// Both fetch chains, upload and delete, parse the error body the same way.
	const wantReads = 2
	reads := strings.Count(content, "data.error_description || data.error")
	if reads != wantReads {
		t.Errorf("static/image-upload.js: found %d reads of "+
			"`data.error_description || data.error`, want %d (the upload branch and the delete "+
			"branch). The shared JSON writers put the code in `error` and the sentence in "+
			"`error_description`, so a branch reading `error` alone shows the administrator a "+
			"bare code such as \"server_error\" (#279)", reads, wantReads)
	}

	// A bare data.error read, outside the fallback above, is the regression this guards.
	for i := 0; ; {
		j := strings.Index(content[i:], "data.error")
		if j < 0 {
			break
		}
		at := i + j
		rest := content[at:]
		if !strings.HasPrefix(rest, "data.error_description") &&
			!strings.HasPrefix(rest, "data.error ||") &&
			!strings.HasPrefix(rest, "data.error |") {
			line := 1 + strings.Count(content[:at], "\n")
			t.Errorf("static/image-upload.js:%d: a read of data.error that is not preceded by "+
				"data.error_description; the sentence lives in error_description (#279)", line)
		}
		i = at + len("data.error")
	}
}

// TestUtilsJS_ModalTitleFollowsTheStatus pins the title sendAjaxRequest gives the error modal.
//
// Every non-401 failure with a JSON body used to open under "Server error", whatever the status
// was. After #279 the AJAX handlers forward the API's own 400, 404 and 409, so that title sat over
// "Redirect URI must be an absolute URI" and "the record no longer exists", which are the
// administrator's mistake and a stale page, not the server's. The title is now a ternary on
// response.status: 5xx keeps "Server error", everything else is the plain "Error" the catch branch
// already uses.
//
// Lexical, like its two neighbours, and for the same reason: no JavaScript runs in any tier of this
// repository, so the only observable is the source. The claim is that the title argument in the
// parsed-JSON branch is chosen by status, and that the old unconditional spelling is gone.
func TestUtilsJS_ModalTitleFollowsTheStatus(t *testing.T) {
	content := utilsJS(t)

	const (
		chooser  = "response.status >= 500"
		server   = `t("js.error.server_error_title")`
		generic  = `t("js.error.error_title")`
		oldTitle = `showModalDialog(props.modalId, t("js.error.server_error_title")`
	)

	at := strings.Index(content, chooser)
	if at < 0 {
		t.Fatalf("static/utils.js: no `%s`; the modal title is no longer chosen by status (#279)", chooser)
	}
	// The two arms follow the condition, in this order, before the next showModalDialog call.
	window := content[at:]
	if end := strings.Index(window, "showModalDialog("); end >= 0 {
		window = window[:end]
	}
	serverAt := strings.Index(window, server)
	genericAt := strings.Index(window, generic)
	if serverAt < 0 || genericAt < 0 || genericAt < serverAt {
		t.Errorf("static/utils.js: the title ternary after `%s` must read %s for the 5xx arm and "+
			"then %s for the rest; found server arm at %d and generic arm at %d",
			chooser, server, generic, serverAt, genericAt)
	}

	if strings.Contains(content, oldTitle) {
		line := 1 + strings.Count(content[:strings.Index(content, oldTitle)], "\n")
		t.Errorf("static/utils.js:%d: showModalDialog is handed \"Server error\" unconditionally; "+
			"a 400, 404 or 409 is not the server's mistake (#279)", line)
	}
}

// TestUtilsJS_DialogMarkupEscapesEveryValue pins the builders' half of #120's decision 1:
// dialogMarkup and dialogMarkupFormat, whose results showModalDialog parses as HTML, pass every
// value they are handed through escapeHtml. Their markup is the catalog's, which
// TestDialogMessages_MarkupOnlyThroughTheBuilder holds; the values are what may carry data.
//
// Lexical, like its neighbours, and for the same reason: no JavaScript runs in any tier. The claim
// is that inside each builder's body its values are read in exactly the ways listed and no other,
// so a value read as values[i] or params[name] reaches the result only through escapeHtml, and a
// spelling that reads them whole, values.join or a spread, is refused rather than missed.
func TestUtilsJS_DialogMarkupEscapesEveryValue(t *testing.T) {
	content := utilsJS(t)

	for _, b := range []struct {
		fn, values string
		// reads are every way the body may name values, each as the text around the name.
		reads []string
	}{
		{"dialogMarkup", "values", []string{"escapeHtml(values[", "values.length"}},
		{"dialogMarkupFormat", "params", []string{"escapeHtml(params[", "in params)"}},
	} {
		params, body, ok := functionBody(content, b.fn)
		if !ok {
			t.Errorf("static/utils.js: function %s not found, or its body cannot be read; this "+
				"check cannot read it (#120)", b.fn)
			continue
		}
		if !strings.Contains(params, b.values) {
			t.Errorf("static/utils.js: %s no longer takes its values as %q; update this check to "+
				"name them (#120)", b.fn, b.values)
			continue
		}
		nameRe := regexp.MustCompile(`\b` + b.values + `\b`)
		escaped := 0
		for _, at := range nameRe.FindAllStringIndex(body, -1) {
			ok := false
			for _, r := range b.reads {
				i := strings.Index(r, b.values)
				if at[0] >= i && strings.HasPrefix(body[at[0]-i:], r) {
					ok = true
					if strings.HasPrefix(r, "escapeHtml(") {
						escaped++
					}
				}
			}
			if !ok {
				t.Errorf("static/utils.js: %s reads %s other than through escapeHtml: %q; "+
					"showModalDialog parses its result as HTML, so every value must be escaped (#120)",
					b.fn, b.values, strings.TrimSpace(lineAround(body, at[0])))
			}
		}
		if escaped == 0 {
			t.Errorf("static/utils.js: %s never passes %s through escapeHtml (#120)", b.fn, b.values)
		}
	}
}

// lineAround returns the line of s holding the byte at i.
func lineAround(s string, i int) string {
	start := strings.LastIndexByte(s[:i], '\n') + 1
	end := strings.IndexByte(s[i:], '\n')
	if end < 0 {
		return s[start:]
	}
	return s[start : i+end]
}

// functionBody returns the parameter list and the body of the one function declared as name in the
// JavaScript source src, each without its brackets, read through the tokenizer so its indentation
// does not matter.
func functionBody(src, name string) (params, body string, ok bool) {
	toks := guard.TokenizeScript(src)
	for i := 0; i+2 < len(toks); i++ {
		if !toks[i].Is(guard.ScriptIdent, "function") || !toks[i+1].Is(guard.ScriptIdent, name) ||
			!toks[i+2].Is(guard.ScriptPunct, "(") {
			continue
		}
		closeParams := matching(toks, i+2)
		if closeParams < 0 || closeParams+1 >= len(toks) || !toks[closeParams+1].Is(guard.ScriptPunct, "{") {
			return "", "", false
		}
		closeBody := matching(toks, closeParams+1)
		if closeBody < 0 {
			return "", "", false
		}
		return src[toks[i+2].Offset+1 : toks[closeParams].Offset],
			src[toks[closeParams+1].Offset+1 : toks[closeBody].Offset], true
	}
	return "", "", false
}

// matching returns the index of the bracket closing the one at toks[open], or -1.
func matching(toks []guard.ScriptToken, open int) int {
	closer := map[string]string{"(": ")", "[": "]", "{": "}"}[toks[open].Text]
	depth := 0
	for j := open; j < len(toks); j++ {
		switch {
		case toks[j].Is(guard.ScriptPunct, toks[open].Text):
			depth++
		case toks[j].Is(guard.ScriptPunct, closer):
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}

// dialogExports are the names the dialog's markup boundary in utils.js hands out.
var dialogExports = []string{"dialogMarkup", "dialogMarkupFormat", "showModalDialog"}

// TestUtilsJS_DialogMarkupBrandIsPrivate pins where the dialog's markup boundary is kept (#120,
// decision 1). showModalDialog parses a message as HTML when it carries the brand its builders put
// on what they built, so whatever can put that brand on a value can hand the dialog raw markup.
// That is the registry and the function adding to it, and both are private to one closure in
// utils.js, which exports the two builders and the dialog and nothing else. Were the registry or the
// sealing function declared at the top level, any page could brand a value it never escaped.
//
// Lexical, like its neighbours: the file declares the three names once, by destructuring them from
// a function expression called in place; that function's one return is a list of exactly those
// names; the registry, the file's one WeakSet, is created inside it, and nothing inside it names
// window, globalThis or self, which is how a closure would leak a name past its return.
func TestUtilsJS_DialogMarkupBrandIsPrivate(t *testing.T) {
	content := utilsJS(t)
	toks := guard.TokenizeScript(content)

	names := func(open int) ([]string, int) {
		closeAt := matching(toks, open)
		if closeAt < 0 {
			return nil, -1
		}
		var out []string
		for j := open + 1; j < closeAt; j++ {
			switch {
			case toks[j].Kind == guard.ScriptIdent && (toks[j+1].Is(guard.ScriptPunct, ",") || j+1 == closeAt):
				out = append(out, toks[j].Text)
			case toks[j].Is(guard.ScriptPunct, ","):
			default:
				return nil, -1
			}
		}
		slices.Sort(out)
		return out, closeAt
	}

	// const { ... } = (function () { ... })();
	start := -1
	for i := 0; i+1 < len(toks); i++ {
		if toks[i].Is(guard.ScriptIdent, "const") && toks[i+1].Is(guard.ScriptPunct, "{") {
			if got, end := names(i + 1); end >= 0 && slices.Equal(got, dialogExports) {
				start = end
				break
			}
		}
	}
	if start < 0 {
		t.Fatalf("static/utils.js: no `const { %s } = ...` declaring the dialog's three names; "+
			"the boundary keeping the markup brand private is gone or reshaped (#120)",
			strings.Join(dialogExports, ", "))
	}
	head := []string{"=", "(", "function", "(", ")", "{"}
	for k, want := range head {
		if j := start + 1 + k; j >= len(toks) || toks[j].Text != want {
			t.Fatalf("static/utils.js:%d: the dialog's names are not destructured from a function "+
				"expression called in place, `= (function () { ... })();`; the brand is private "+
				"only inside such a closure (#120)", toks[start].Line)
		}
	}
	bodyOpen := start + len(head)
	bodyClose := matching(toks, bodyOpen)
	if bodyClose < 0 || bodyClose+4 >= len(toks) || !toks[bodyClose+1].Is(guard.ScriptPunct, ")") ||
		!toks[bodyClose+2].Is(guard.ScriptPunct, "(") || !toks[bodyClose+3].Is(guard.ScriptPunct, ")") {
		t.Fatalf("static/utils.js: the dialog's closure is not called in place (#120)")
	}

	depth := 0
	returns, weakSets := 0, 0
	for j := bodyOpen + 1; j < bodyClose; j++ {
		tok := toks[j]
		switch {
		case tok.Is(guard.ScriptPunct, "{"):
			depth++
		case tok.Is(guard.ScriptPunct, "}"):
			depth--
		case tok.Is(guard.ScriptIdent, "return") && depth == 0:
			returns++
			got, end := names(j + 1)
			if !toks[j+1].Is(guard.ScriptPunct, "{") || end < 0 || !slices.Equal(got, dialogExports) {
				t.Errorf("static/utils.js:%d: the dialog's closure returns something other than "+
					"{ %s }; whatever else it hands out is outside the boundary, and the brand "+
					"must not be (#120)", tok.Line, strings.Join(dialogExports, ", "))
			}
		case tok.Kind == guard.ScriptIdent && (tok.Text == "window" || tok.Text == "globalThis" || tok.Text == "self"):
			t.Errorf("static/utils.js:%d: the dialog's closure names %s, through which it can hand "+
				"out what its return does not (#120)", tok.Line, tok.Text)
		}
	}
	if returns != 1 {
		t.Errorf("static/utils.js: the dialog's closure returns %d times at its top level; it "+
			"returns its three names once (#120)", returns)
	}

	for j, tok := range toks {
		if !tok.Is(guard.ScriptIdent, "WeakSet") {
			continue
		}
		weakSets++
		if j <= bodyOpen || j >= bodyClose {
			t.Errorf("static/utils.js:%d: a WeakSet is created outside the dialog's closure; the "+
				"registry of built messages lives inside it, where no page can add to it (#120)", tok.Line)
		}
	}
	if weakSets != 1 {
		t.Errorf("static/utils.js: found %d WeakSets; the dialog's registry is the one, inside its "+
			"closure, and this check names it by that (#120)", weakSets)
	}
}
