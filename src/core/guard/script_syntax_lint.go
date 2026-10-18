package guard

import (
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf16"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// AssertScriptSyntax holds every static .js file under root in fsys, the vendored libraries
// included, to JavaScript every browser at the declared floor runs: Chrome and Edge 111, Safari 16.4
// and Firefox 128 (#617). Each file is parsed as a classic script with a real JavaScript parser, so a
// syntax error fails here rather than in a visitor's browser, and syntax newer than ES2020 is
// refused, the cap: logical assignment and numeric separators (ES2021), class fields, private
// names, static blocks, top-level await and the regular expression d flag (ES2022), a hashbang
// (ES2023), the v flag (ES2024) and inline modifiers (ES2025). A classic script cannot import,
// export, read import.meta or use for await outside an async function, so those are refused too.
//
// The parser accepts some scripts a browser refuses when it compiles them, the early errors of the
// language, and the walk refuses the ones a slip of the hand writes: an assignment or an increment
// whose target is not a variable, a property or a destructuring pattern, and a regular expression
// with an unknown or repeated flag, an unbalanced group, an unknown group syntax, a group name that
// is no identifier or is used twice, a character class range out of order, or a quantifier with
// nothing to repeat.
//
// The pages load these files as they are written: there is no build step that could translate one
// down, so the cap is the language the files are written in.
func AssertScriptSyntax(t *testing.T, fsys fs.FS, root string) {
	t.Helper()

	assertScriptSyntax(t, fsys, root)
}

// assertScriptSyntax is the reporting half, failing through a Reporter so a rule test can drive it
// against a fixture FS. See Reporter in guard.go.
func assertScriptSyntax(r Reporter, fsys fs.FS, root string) {
	r.Helper()

	n := 0
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".js") {
			return nil
		}
		src, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		n++
		for _, f := range findScriptSyntaxProblems(p, src) {
			r.Errorf("%s: %s", f.path, f.detail)
		}
		return nil
	})
	if err != nil {
		r.Fatalf("walking scripts under %s: %v", root, err)
	}
	if n == 0 {
		r.Fatalf("walked no .js files under %s; this guard is checking nothing", root)
	}
}

// findScriptSyntaxProblems returns a finding for a script that does not parse, and one for each
// construct newer than the cap.
func findScriptSyntaxProblems(path string, src []byte) []templateFinding {
	if strings.HasPrefix(string(src), "#!") {
		return []templateFinding{{path: path, detail: "line 1: a hashbang is ES2023"}}
	}
	ast, err := js.Parse(parse.NewInputBytes(src), js.Options{})
	if err != nil {
		return []templateFinding{{path: path, detail: "does not parse: " + firstLine(err.Error())}}
	}
	var found []string
	js.Walk(&syntaxCap{found: &found}, ast)
	out := make([]templateFinding, 0, len(found))
	seen := map[string]bool{}
	for _, f := range found {
		if !seen[f] {
			seen[f] = true
			out = append(out, templateFinding{path: path, detail: f})
		}
	}
	return out
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// syntaxCap is the walk that finds what the cap refuses. async records whether the nearest
// enclosing function is async, which is where an await belongs in a classic script; each function
// is walked by a visitor of its own, and every visitor appends to the one list of findings.
type syntaxCap struct {
	async bool
	found *[]string
}

func (v *syntaxCap) Enter(n js.INode) js.IVisitor {
	switch n := n.(type) {
	case *js.FuncDecl:
		return &syntaxCap{async: n.Async, found: v.found}
	case *js.ArrowFunc:
		return &syntaxCap{async: n.Async, found: v.found}
	case *js.MethodDecl:
		if n.Name.Private != nil {
			v.add("private class member %s is ES2022", n.Name.Private.Data)
		}
		return &syntaxCap{async: n.Async, found: v.found}
	case *js.ClassDecl:
		for _, item := range n.List {
			switch {
			case item.StaticBlock != nil:
				v.add("a class static block is ES2022")
			case item.Method == nil:
				v.add("class field %s is ES2022", item.Name.String())
			}
		}
	case *js.BinaryExpr:
		if assignmentOps[n.Op] && !assignmentTarget(n.X, n.Op == js.EqToken) {
			v.add("%s assigns to %s, which is not a variable, a property or a destructuring pattern", n.Op.String(), n.X.String())
		}
		switch n.Op {
		case js.AndEqToken, js.OrEqToken, js.NullishEqToken:
			v.add("the logical assignment %s is ES2021", n.Op.String())
		case js.InToken:
			if name, ok := privateName(n.X); ok {
				v.add("the private brand check %s in is ES2022", name)
			}
		}
	case *js.DotExpr:
		if name, ok := privateName(n.Y); ok {
			v.add("private member %s is ES2022", name)
		}
	case *js.LiteralExpr:
		v.literal(n)
	case *js.UnaryExpr:
		switch n.Op {
		case js.AwaitToken:
			if !v.async {
				v.add("await outside an async function is top-level await, ES2022, and a module's alone")
			}
		case js.PreIncrToken, js.PreDecrToken, js.PostIncrToken, js.PostDecrToken:
			if !simpleTarget(n.X) {
				v.add("%s changes %s, which is not a variable or a property", n.Op.String(), n.X.String())
			}
		}
	case *js.ForOfStmt:
		if n.Await && !v.async {
			v.add("for await outside an async function is a syntax error in a script")
		}
	case *js.ImportMetaExpr:
		v.add("import.meta is module syntax, which a classic script cannot use")
	case *js.ImportStmt:
		v.add("import is module syntax, which a classic script cannot use")
	case *js.ExportStmt:
		v.add("export is module syntax, which a classic script cannot use")
	}
	return v
}

func (v *syntaxCap) Exit(js.INode) {}

// privateName reports whether an expression is a private name, #x, which the parser writes as a
// variable or as a literal.
func privateName(e js.IExpr) (string, bool) {
	switch e := e.(type) {
	case *js.Var:
		return string(e.Data), strings.HasPrefix(string(e.Data), "#")
	case *js.LiteralExpr:
		return string(e.Data), e.TokenType == js.PrivateIdentifierToken
	}
	return "", false
}

// assignmentOps are the operators that assign to their left operand.
var assignmentOps = map[js.TokenType]bool{
	js.EqToken: true, js.AddEqToken: true, js.SubEqToken: true, js.MulEqToken: true, js.DivEqToken: true,
	js.ModEqToken: true, js.ExpEqToken: true, js.LtLtEqToken: true, js.GtGtEqToken: true,
	js.GtGtGtEqToken: true, js.BitAndEqToken: true, js.BitOrEqToken: true, js.BitXorEqToken: true,
	js.AndEqToken: true, js.OrEqToken: true, js.NullishEqToken: true,
}

// simpleTarget reports whether e is a variable or a property, what an increment or a compound
// assignment may change. A property read through an optional chain, anywhere in it, is not.
func simpleTarget(e js.IExpr) bool {
	switch e := e.(type) {
	case *js.Var:
		return true
	case *js.DotExpr:
		return !inOptionalChain(e)
	case *js.IndexExpr:
		return !inOptionalChain(e)
	case *js.GroupExpr:
		return simpleTarget(e.X)
	}
	return false
}

func inOptionalChain(e js.IExpr) bool {
	switch e := e.(type) {
	case *js.DotExpr:
		return e.Optional || inOptionalChain(e.X)
	case *js.IndexExpr:
		return e.Optional || inOptionalChain(e.X)
	case *js.CallExpr:
		return e.Optional || inOptionalChain(e.X)
	}
	return false
}

// assignmentTarget reports whether e may stand left of an assignment: a simple target, or for a
// plain = a destructuring pattern, every target in it valid in turn. A rest element comes last and
// has no default; an object's rest is a simple target.
func assignmentTarget(e js.IExpr, plain bool) bool {
	switch e := e.(type) {
	case *js.ArrayExpr:
		if !plain {
			return false
		}
		for i, el := range e.List {
			switch {
			case el.Value == nil:
			case el.Spread:
				if i != len(e.List)-1 || !assignmentTarget(el.Value, true) {
					return false
				}
			case !patternTarget(el.Value):
				return false
			}
		}
		return true
	case *js.ObjectExpr:
		if !plain {
			return false
		}
		for i, p := range e.List {
			switch {
			case p.Spread:
				if i != len(e.List)-1 || !simpleTarget(p.Value) {
					return false
				}
			case p.Value != nil && !patternTarget(p.Value):
				return false
			}
		}
		return true
	}
	return simpleTarget(e)
}

// patternTarget reports whether e may stand in a destructuring pattern: a target, with or without
// a default value.
func patternTarget(e js.IExpr) bool {
	if b, ok := e.(*js.BinaryExpr); ok && b.Op == js.EqToken {
		return assignmentTarget(b.X, true)
	}
	return assignmentTarget(e, true)
}

// regexpModifierStart matches an inline modifier group at the start of what follows "(?", such as
// "i:" or "-m:".
var regexpModifierStart = regexp.MustCompile(`^[ims]*-?[ims]*:`)

// regexpProblem reads a regular expression's pattern as a browser compiles it, character classes
// apart, with the u flag or without, and returns why one would refuse it, or "": an unbalanced
// group, an unknown group syntax, a group name that is no identifier or is used twice, a character
// class range out of order or not closed, or a quantifier with nothing to repeat. modifier reports
// an inline modifier group outside every class, syntax past the cap.
func regexpProblem(pattern string, unicodeMode bool) (problem string, modifier bool) {
	depth := 0
	canRepeat := false
	names := map[string]bool{}
	runes := []rune(pattern)
	for i := 0; i < len(runes); i++ {
		switch c := runes[i]; c {
		case '\\':
			i++
			canRepeat = true
		case '[':
			end, problem := regexpClass(runes, i+1, unicodeMode)
			if problem != "" {
				return problem, modifier
			}
			i = end
			canRepeat = true
		case '(':
			depth++
			canRepeat = false
			if i+1 >= len(runes) || runes[i+1] != '?' {
				continue
			}
			rest := string(runes[i+2:])
			switch {
			case regexpModifierStart.MatchString(rest) && len(regexpModifierStart.FindString(rest)) > 1:
				modifier = true
				i += 1 + len([]rune(regexpModifierStart.FindString(rest)))
			case strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, "=") || strings.HasPrefix(rest, "!"):
				i += 2
			case strings.HasPrefix(rest, "<=") || strings.HasPrefix(rest, "<!"):
				i += 3
			case strings.HasPrefix(rest, "<"):
				name, length, ok := regexpGroupName(runes[i+3:])
				if !ok {
					return "a group starts with an unknown (? syntax", modifier
				}
				if names[name] {
					return "the group name " + name + " is used twice", modifier
				}
				names[name] = true
				i += 3 + length
			default:
				return "a group starts with an unknown (? syntax", modifier
			}
		case ')':
			depth--
			if depth < 0 {
				return "a group is closed that was never opened", modifier
			}
			canRepeat = true
		case '|':
			canRepeat = false
		case '*', '+', '?':
			if !canRepeat {
				return "a quantifier has nothing to repeat", modifier
			}
			if i+1 < len(runes) && runes[i+1] == '?' {
				i++
			}
			canRepeat = false
		default:
			canRepeat = true
		}
	}
	if depth > 0 {
		return "a group is not closed", modifier
	}
	return "", modifier
}

// regexpGroupName reads a group's name up to its ">", and returns it with its escapes decoded and
// how many characters it spans: an identifier, each character written as itself or as a \u escape.
func regexpGroupName(runes []rune) (string, int, bool) {
	var name []rune
	for i := 0; i < len(runes); {
		r, next := runes[i], i+1
		if r == '>' {
			return string(name), i, len(name) > 0
		}
		if r == '\\' {
			var ok bool
			if r, next, ok = regexpUnicodeEscape(runes, i+1, true); !ok {
				return "", 0, false
			}
		}
		if !identifierChar(r, len(name) == 0) {
			return "", 0, false
		}
		name = append(name, r)
		i = next
	}
	return "", 0, false
}

// identifierChar reports whether r may start an identifier, or continue one, as ECMAScript reads
// Unicode's ID_Start and ID_Continue, with $ and _, and the two joiners after the start.
func identifierChar(r rune, start bool) bool {
	switch {
	case r == '$' || r == '_':
		return true
	case unicode.In(r, unicode.Pattern_Syntax, unicode.Pattern_White_Space):
		return false
	case unicode.IsLetter(r) || unicode.In(r, unicode.Nl, unicode.Other_ID_Start):
		return true
	case start:
		return false
	}
	return r == 0x200C || r == 0x200D || unicode.In(r, unicode.Mn, unicode.Mc, unicode.Nd, unicode.Pc, unicode.Other_ID_Continue)
}

// regexpUnicodeEscape reads the \u escape whose u is at i and returns its character and where it
// ends: four hex digits, or, with the u flag and in a group name, also a surrogate pair of two such
// escapes or a code point in braces.
func regexpUnicodeEscape(runes []rune, i int, unicodeMode bool) (rune, int, bool) {
	if i >= len(runes) || runes[i] != 'u' {
		return 0, 0, false
	}
	if unicodeMode && i+1 < len(runes) && runes[i+1] == '{' {
		for end := i + 2; end < len(runes); end++ {
			if runes[end] == '}' {
				v, ok := hexValue(runes[i+2 : end])
				return v, end + 1, ok
			}
		}
		return 0, 0, false
	}
	if i+5 > len(runes) {
		return 0, 0, false
	}
	v, ok := hexValue(runes[i+1 : i+5])
	if !ok {
		return 0, 0, false
	}
	if unicodeMode && v >= 0xD800 && v < 0xDC00 && i+11 <= len(runes) && runes[i+5] == '\\' && runes[i+6] == 'u' {
		if low, ok := hexValue(runes[i+7 : i+11]); ok && low >= 0xDC00 && low <= 0xDFFF {
			return utf16.DecodeRune(v, low), i + 11, true
		}
	}
	return v, i + 5, true
}

// hexValue reads hex digits as a code point: at least one digit, and at most U+10FFFF.
func hexValue(digits []rune) (rune, bool) {
	var v rune
	for _, d := range digits {
		switch {
		case d >= '0' && d <= '9':
			v = v*16 + d - '0'
		case d >= 'a' && d <= 'f':
			v = v*16 + d - 'a' + 10
		case d >= 'A' && d <= 'F':
			v = v*16 + d - 'A' + 10
		default:
			return 0, false
		}
		if v > unicode.MaxRune {
			return 0, false
		}
	}
	return v, len(digits) > 0
}

// regexpClass reads a character class from just after its "[" and returns where its "]" is, or why
// a browser refuses it: not closed, a range whose end comes before its start, or with the u flag a
// range with a set such as \d at one end, which without it reads as the set, a "-" and a character.
func regexpClass(runes []rune, from int, unicodeMode bool) (int, string) {
	i := from
	if i < len(runes) && runes[i] == '^' {
		i++
	}
	for i < len(runes) {
		if runes[i] == ']' {
			return i, ""
		}
		start, single, next := regexpClassAtom(runes, i, unicodeMode)
		if next+1 < len(runes) && runes[next] == '-' && runes[next+1] != ']' {
			end, endSingle, after := regexpClassAtom(runes, next+1, unicodeMode)
			switch {
			case !single || !endSingle:
				if unicodeMode {
					return 0, `a character class range has a set such as \d at one end`
				}
			case end < start:
				return 0, "a character class range is out of order"
			}
			i = after
			continue
		}
		i = next
	}
	return 0, "a character class is not closed"
}

// regexpClassAtom reads the class atom at i and returns the character it stands for, whether it
// stands for one character, which a set such as \d does not, and where it ends. An escape is decoded
// as a browser decodes it, without the u flag its legacy forms included: a lone \c as a backslash,
// \c with a digit or _, and octal escapes up to \377.
func regexpClassAtom(runes []rune, i int, unicodeMode bool) (rune, bool, int) {
	if runes[i] != '\\' || i+1 >= len(runes) {
		return runes[i], true, i + 1
	}
	c, next := runes[i+1], i+2
	switch c {
	case 'd', 'D', 'w', 'W', 's', 'S':
		return 0, false, next
	case 'p', 'P':
		if unicodeMode {
			for end := next; end < len(runes); end++ {
				if runes[end] == '}' {
					return 0, false, end + 1
				}
			}
		}
	case 'b':
		return '\b', true, next
	case 't':
		return '\t', true, next
	case 'n':
		return '\n', true, next
	case 'v':
		return '\v', true, next
	case 'f':
		return '\f', true, next
	case 'r':
		return '\r', true, next
	case 'c':
		if next < len(runes) {
			l := runes[next]
			if (l >= 'a' && l <= 'z') || (l >= 'A' && l <= 'Z') || (!unicodeMode && ((l >= '0' && l <= '9') || l == '_')) {
				return l % 32, true, next + 1
			}
		}
		if !unicodeMode {
			return '\\', true, i + 1
		}
	case 'x':
		if next+2 <= len(runes) {
			if v, ok := hexValue(runes[next : next+2]); ok {
				return v, true, next + 2
			}
		}
	case 'u':
		if v, end, ok := regexpUnicodeEscape(runes, i+1, unicodeMode); ok {
			return v, true, end
		}
	case '0', '1', '2', '3', '4', '5', '6', '7':
		v, end := c-'0', next
		for n := 1; !unicodeMode && n < 3 && end < len(runes) && runes[end] >= '0' && runes[end] <= '7' && (n < 2 || c <= '3'); n++ {
			v = v*8 + runes[end] - '0'
			end++
		}
		return v, true, end
	}
	return c, true, next
}

func (v *syntaxCap) literal(n *js.LiteralExpr) {
	data := string(n.Data)
	switch {
	case n.TokenType == js.RegExpToken:
		end := strings.LastIndexByte(data, '/')
		pattern, flags := data[1:end], data[end+1:]
		for i, f := range flags {
			if !strings.ContainsRune("dgimsuyv", f) {
				v.add("the regular expression %s has the unknown flag %c", data, f)
			} else if strings.ContainsRune(flags[:i], f) {
				v.add("the regular expression %s has the flag %c twice", data, f)
			}
		}
		problem, modifier := regexpProblem(pattern, strings.ContainsRune(flags, 'u'))
		if problem != "" {
			v.add("the regular expression %s is refused by a browser: %s", data, problem)
		}
		if strings.ContainsRune(flags, 'd') {
			v.add("the regular expression flag d, in %s, is ES2022", data)
		}
		if strings.ContainsRune(flags, 'v') {
			v.add("the regular expression flag v, in %s, is ES2024", data)
		}
		if modifier {
			v.add("an inline modifier group, in %s, is ES2025", data)
		}
	case js.IsNumeric(n.TokenType) && strings.ContainsRune(data, '_'):
		v.add("the numeric separator in %s is ES2021", data)
	}
}

func (v *syntaxCap) add(format string, args ...any) {
	*v.found = append(*v.found, fmt.Sprintf(format, args...))
}
