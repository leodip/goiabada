package guard

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// HTMLSinkAllowance is one site a caller still lets through AssertNoHTMLSinks: a file as the walked
// FS spells it, so "template/admin_users_groups.html", and the offending line, trimmed. It names the
// text rather than a line number so it does not drift as the file is edited, and each allowance
// admits one occurrence, so a line repeated in a file is listed as often as it occurs.
type HTMLSinkAllowance struct {
	File string
	Text string
}

// AssertNoHTMLSinks holds every page and script a server serves to handing data to the browser as
// text (#120). A value written into the document through an HTML or JavaScript parser runs as
// markup or code the day it carries the characters for it, and the only thing that stopped that
// before #120 was the auth server's input validators, which live in another binary and record no
// such duty. So it refuses, in all the code of every page and script under each tree:
//
//   - an innerHTML write from anything but one string literal whose template actions, if any, are
//     all catalog lookups ({{ T $.ctx "key" }} with no arguments): a variable, a call, a
//     concatenation, a template literal, a ternary, a += and a literal carrying any other action
//     are all refused;
//   - any read of innerHTML, which re-serialises the value, so a "&" no longer equals itself (#105);
//   - outerHTML, insertAdjacentHTML and document.write or writeln, whatever they are handed;
//   - setAttribute naming an on... attribute, or naming its attribute through anything but a
//     literal, which could be one.
//
// A catalog literal stays allowed: about fifty labels are written that way, from a catalog that
// carries no data, and converting them is churn with no gain. allow names the sites a caller has
// not converted yet. An allowance that matches nothing is itself a failure, so a site that is fixed
// has to leave the list, the way ARCHITECTURE.md's exceptions do.
//
// Each tree is walked from its root, and both servers pass their //go:embed sets, the bytes the
// binary serves, so a file that stopped being embedded fails here rather than passing. A tree that
// reaches no .html or .js file is fatal, because every rule passes vacuously over nothing.
//
// The code is read through ReadScripts, the reader the admin console's dialog rule shares: every
// .js file, and every <script> element, on... attribute and javascript: URL of every .html file,
// with template literals' interpolations read as code and a member named by a fixed string,
// el["innerHTML"], read as el.innerHTML. A sink named in a comment or a message string is not one.
// Its boundary is the reader's: a name assembled at run time is beyond a lexical reading.
func AssertNoHTMLSinks(t *testing.T, allow []HTMLSinkAllowance, trees ...fs.FS) {
	t.Helper()

	assertNoHTMLSinks(t, allow, trees...)
}

// assertNoHTMLSinks is the reporting half, failing through a Reporter so a rule test can drive it
// against fixture trees. See Reporter in guard.go.
func assertNoHTMLSinks(r Reporter, allow []HTMLSinkAllowance, trees ...fs.FS) {
	r.Helper()

	var found []htmlSink
	for _, tree := range trees {
		f, n, err := findHTMLSinks(tree)
		if err != nil {
			r.Fatalf("walking for pages and scripts: %v", err)
		}
		if n == 0 {
			r.Fatalf("reached no .html or .js file in one of the trees; this guard is checking nothing")
		}
		found = append(found, f...)
	}

	unused := map[HTMLSinkAllowance]int{}
	for _, a := range allow {
		unused[a]++
	}
	for _, f := range found {
		key := HTMLSinkAllowance{File: f.path, Text: f.text}
		if unused[key] > 0 {
			unused[key]--
			continue
		}
		r.Errorf("%s:%d: %s\n\t%s. Put data into the page as text (textContent, value, "+
			"createElement) and bind a handler as a function (#120)", f.path, f.line, f.text, f.why)
	}
	for _, a := range allow {
		if unused[a] > 0 {
			unused[a]--
			r.Errorf("allowance {%s %q} matches nothing; a fixed site leaves the list", a.File, a.Text)
		}
	}
}

// htmlSink is one offending use of a sink, located.
type htmlSink struct {
	// path is the file as the walked fs.FS spells it.
	path string
	line int
	// text is the whole line the sink is on, trimmed, which is what an allowance names.
	text string
	why  string
}

// catalogLookupRe matches the one template action an innerHTML literal may carry: a catalog lookup
// with no arguments, which could otherwise carry data into the catalog sentence.
var catalogLookupRe = regexp.MustCompile(`^\{\{-?\s*T\s+\$?\.ctx\s+"[^"\\]*"\s*-?\}\}$`)

// findHTMLSinks walks fsys and returns every sink in its pages and scripts, with how many files it
// read, so the reporting half can tell "nothing to report" from "nothing was read".
func findHTMLSinks(fsys fs.FS) ([]htmlSink, int, error) {
	scripts, n, err := ReadScripts(fsys)
	var found []htmlSink
	for _, s := range scripts {
		found = append(found, sinksIn(s)...)
	}
	return found, n, err
}

// sinksIn applies the rules to one script's tokens.
func sinksIn(s Script) []htmlSink {
	toks := s.Tokens
	var found []htmlSink
	report := func(t ScriptToken, why string) {
		found = append(found, htmlSink{path: s.Path, line: t.Line, text: s.LineText(t.Line), why: why})
	}
	tok := func(i int) ScriptToken {
		if i >= 0 && i < len(toks) {
			return toks[i]
		}
		return ScriptToken{}
	}

	for i, t := range toks {
		if t.Kind != ScriptIdent {
			continue
		}
		switch {
		case t.Text == "innerHTML" && tok(i+1).Is(ScriptPunct, "="):
			if !catalogLiteral(tok(i+2)) || !endsStatement(tok(i+3)) {
				report(t, "innerHTML is written from something other than one catalog literal")
			}
		case t.Text == "innerHTML":
			report(t, "innerHTML is read, or written by an operator that reads it")
		case t.Text == "outerHTML" || t.Text == "insertAdjacentHTML":
			report(t, t.Text+" parses markup")
		case (t.Text == "write" || t.Text == "writeln") && tok(i-1).Is(ScriptPunct, ".") && tok(i-2).Is(ScriptIdent, "document"):
			report(t, "document."+t.Text+" parses markup")
		case t.Text == "setAttribute" && tok(i+1).Is(ScriptPunct, "("):
			name := tok(i + 2)
			if name.Kind != ScriptString {
				report(t, "setAttribute names its attribute through something other than a literal, which may be an on... handler")
			} else if strings.HasPrefix(strings.ToLower(name.Text), "on") {
				report(t, "setAttribute sets an on... attribute, which the browser compiles as code")
			}
		}
	}
	return found
}

// catalogLiteral reports whether t is a quoted string (not a template literal) whose template
// actions are all catalog lookups. A literal with no action at all is static text and passes.
func catalogLiteral(t ScriptToken) bool {
	if t.Kind != ScriptString {
		return false
	}
	for _, a := range t.Actions {
		if !catalogLookupRe.MatchString(a) {
			return false
		}
	}
	return true
}

// endsStatement reports whether t cannot continue the expression before it: a ";", a "}", the end
// of the code, or an identifier on a new line, where a semicolon is inserted.
func endsStatement(t ScriptToken) bool {
	return t.Kind == ScriptEnd || t.Is(ScriptPunct, ";") || t.Is(ScriptPunct, "}") || (t.Kind == ScriptIdent && t.Newline)
}
