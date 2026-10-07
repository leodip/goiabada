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
// such duty. So it refuses, in the code of every .js file and every <script> element of every .html
// file under each tree:
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
// The reading is lexical, over a small JavaScript tokenizer that knows strings, template literals,
// comments, regex literals and, in .html files only, template actions, so a sink named in a comment
// or a message string is not one. Its boundary: the code of inline on... attributes in markup is
// not read, and neither is a sink reached by a computed name, el["innerHTML"].
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

// scriptElementRe matches one <script> element's body in a page.
var scriptElementRe = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script\s*>`)

// catalogLookupRe matches the one template action an innerHTML literal may carry: a catalog lookup
// with no arguments, which could otherwise carry data into the catalog sentence.
var catalogLookupRe = regexp.MustCompile(`^\{\{-?\s*T\s+\$?\.ctx\s+"[^"\\]*"\s*-?\}\}$`)

// findHTMLSinks walks fsys and returns every sink in its pages and scripts, with how many files it
// read, so the reporting half can tell "nothing to report" from "nothing was read".
func findHTMLSinks(fsys fs.FS) ([]htmlSink, int, error) {
	var found []htmlSink
	n := 0
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		page := strings.HasSuffix(p, ".html")
		if d.IsDir() || (!page && !strings.HasSuffix(p, ".js")) {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		n++
		src := string(b)
		if !page {
			found = append(found, sinksIn(p, src, 0, len(src), false)...)
			return nil
		}
		for _, m := range scriptElementRe.FindAllStringSubmatchIndex(src, -1) {
			found = append(found, sinksIn(p, src, m[2], m[3], true)...)
		}
		return nil
	})
	return found, n, err
}

// sinksIn applies the rules to the code in src[start:end].
func sinksIn(path, src string, start, end int, page bool) []htmlSink {
	toks := tokenizeJS(src, start, end, page)
	var found []htmlSink
	report := func(at int, why string) {
		lineStart := strings.LastIndexByte(src[:at], '\n') + 1
		lineEnd := strings.IndexByte(src[at:], '\n')
		if lineEnd < 0 {
			lineEnd = len(src) - at
		}
		found = append(found, htmlSink{
			path: path,
			line: strings.Count(src[:at], "\n") + 1,
			text: strings.TrimSpace(src[lineStart : at+lineEnd]),
			why:  why,
		})
	}
	tok := func(i int) jsToken {
		if i < len(toks) {
			return toks[i]
		}
		return jsToken{kind: jsEOF}
	}

	for i, t := range toks {
		if t.kind != jsIdent {
			continue
		}
		switch {
		case t.text == "innerHTML" && tok(i+1).is(jsPunct, "="):
			if !catalogLiteral(tok(i+2)) || !endsStatement(tok(i+3)) {
				report(t.at, "innerHTML is written from something other than one catalog literal")
			}
		case t.text == "innerHTML":
			report(t.at, "innerHTML is read, or written by an operator that reads it")
		case t.text == "outerHTML" || t.text == "insertAdjacentHTML":
			report(t.at, t.text+" parses markup")
		case (t.text == "write" || t.text == "writeln") && i >= 2 && tok(i-1).is(jsPunct, ".") && tok(i-2).is(jsIdent, "document"):
			report(t.at, "document."+t.text+" parses markup")
		case t.text == "setAttribute" && tok(i+1).is(jsPunct, "("):
			name := tok(i + 2)
			if name.kind != jsString {
				report(t.at, "setAttribute names its attribute through something other than a literal, which may be an on... handler")
			} else if strings.HasPrefix(strings.ToLower(name.text), "on") {
				report(t.at, "setAttribute sets an on... attribute, which the browser compiles as code")
			}
		}
	}
	return found
}

// catalogLiteral reports whether t is a quoted string (not a template literal) whose template
// actions are all catalog lookups. A literal with no action at all is static text and passes.
func catalogLiteral(t jsToken) bool {
	if t.kind != jsString {
		return false
	}
	for _, a := range t.actions {
		if !catalogLookupRe.MatchString(a) {
			return false
		}
	}
	return true
}

// endsStatement reports whether t cannot continue the expression before it: a ";", a "}", the end
// of the code, or an identifier on a new line, where a semicolon is inserted.
func endsStatement(t jsToken) bool {
	return t.kind == jsEOF || t.is(jsPunct, ";") || t.is(jsPunct, "}") || (t.kind == jsIdent && t.newline)
}

type jsKind int

const (
	jsEOF jsKind = iota
	jsIdent
	jsPunct
	jsString   // '...' or "...": text is the contents
	jsTemplate // `...`
	jsValue    // a number, a regex literal or a template action outside a string
)

type jsToken struct {
	kind jsKind
	text string
	at   int
	// newline records a line break between this token and the one before it.
	newline bool
	// actions are the template actions inside a quoted string, in a page.
	actions []string
}

func (t jsToken) is(kind jsKind, text string) bool { return t.kind == kind && t.text == text }

// regexAfter lists the keywords after which a "/" opens a regex literal rather than dividing.
var regexAfter = map[string]bool{"return": true, "typeof": true, "case": true, "do": true, "else": true,
	"in": true, "of": true, "new": true, "delete": true, "void": true, "throw": true, "instanceof": true,
	"yield": true, "await": true}

// tokenizeJS splits src[start:end] into tokens, dropping whitespace and comments. In a page, a
// template action is one unit wherever it stands, since its own quotes are the template's and not
// the script's.
func tokenizeJS(src string, start, end int, page bool) []jsToken {
	var toks []jsToken
	newline := false
	i := start
	push := func(t jsToken) {
		t.newline = newline
		newline = false
		toks = append(toks, t)
	}
	// action returns the end of the template action at j, or -1 when there is none.
	action := func(j int) int {
		if !page || !strings.HasPrefix(src[j:end], "{{") {
			return -1
		}
		k := strings.Index(src[j:end], "}}")
		if k < 0 {
			return -1
		}
		return j + k + 2
	}
	regexAllowed := func() bool {
		if len(toks) == 0 {
			return true
		}
		last := toks[len(toks)-1]
		switch last.kind {
		case jsIdent:
			return regexAfter[last.text]
		case jsPunct:
			return last.text != ")" && last.text != "]"
		}
		return false
	}

	for i < end {
		c := src[i]
		switch {
		case c == '\n':
			newline = true
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case action(i) >= 0:
			j := action(i)
			push(jsToken{kind: jsValue, text: src[i:j], at: i})
			i = j
		case strings.HasPrefix(src[i:end], "//"):
			for i < end && src[i] != '\n' {
				i++
			}
		case strings.HasPrefix(src[i:end], "/*"):
			k := strings.Index(src[i+2:end], "*/")
			if k < 0 {
				i = end
			} else {
				i += 2 + k + 2
			}
		case c == '"' || c == '\'' || c == '`':
			t := jsToken{kind: jsString, at: i}
			if c == '`' {
				t.kind = jsTemplate
			}
			j := i + 1
			var text strings.Builder
			for j < end && src[j] != c && (c == '`' || src[j] != '\n') {
				if k := action(j); k >= 0 {
					t.actions = append(t.actions, src[j:k])
					text.WriteString(src[j:k])
					j = k
					continue
				}
				if src[j] == '\\' && j+1 < end {
					text.WriteByte(src[j])
					j++
				}
				text.WriteByte(src[j])
				j++
			}
			t.text = text.String()
			push(t)
			i = j + 1
		case c == '/' && regexAllowed():
			j, class := i+1, false
			for j < end && src[j] != '\n' && (class || src[j] != '/') {
				switch src[j] {
				case '\\':
					j++
				case '[':
					class = true
				case ']':
					class = false
				}
				j++
			}
			j++
			for j < end && isIdentByte(src[j]) {
				j++
			}
			push(jsToken{kind: jsValue, text: src[i:min(j, end)], at: i})
			i = j
		case isIdentByte(c):
			j := i
			for j < end && isIdentByte(src[j]) {
				j++
			}
			kind := jsIdent
			if c >= '0' && c <= '9' {
				kind = jsValue
			}
			push(jsToken{kind: kind, text: src[i:j], at: i})
			i = j
		case strings.IndexByte("=!<>+-*%&|^?~:", c) >= 0:
			j := i
			for j < end && strings.IndexByte("=!<>+-*%&|^?~:", src[j]) >= 0 {
				j++
			}
			push(jsToken{kind: jsPunct, text: src[i:j], at: i})
			i = j
		default:
			push(jsToken{kind: jsPunct, text: src[i : i+1], at: i})
			i++
		}
	}
	return toks
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
}
