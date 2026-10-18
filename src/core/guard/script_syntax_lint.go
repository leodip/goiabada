package guard

import (
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"testing"

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
// with an unknown or repeated flag, an unbalanced group or character class, an unknown group
// syntax, or a quantifier with nothing to repeat.
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

// regexpModifier matches an inline modifier group, such as (?i:...) or (?-m:...).
var regexpModifier = regexp.MustCompile(`\(\?[ims]*-?[ims]+:`)

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
// assignment may change. An optional chain is neither.
func simpleTarget(e js.IExpr) bool {
	switch e := e.(type) {
	case *js.Var:
		return true
	case *js.DotExpr:
		return !e.Optional
	case *js.IndexExpr:
		return !e.Optional
	case *js.GroupExpr:
		return simpleTarget(e.X)
	}
	return false
}

// assignmentTarget reports whether e may stand left of an assignment: a simple target, or for a
// plain = a destructuring pattern.
func assignmentTarget(e js.IExpr, plain bool) bool {
	switch e.(type) {
	case *js.ArrayExpr, *js.ObjectExpr:
		return plain
	}
	return simpleTarget(e)
}

// regexpGroupStart matches what may follow "(?" in a group: a non-capturing group, a lookahead or a
// lookbehind, or a named group. An inline modifier is matched apart, as syntax past the cap.
var regexpGroupStart = regexp.MustCompile(`^(?::|=|!|<=|<!|<[A-Za-z_$][\w$]*>)`)

// regexpProblem returns why a browser refuses a regular expression's pattern, or "": an unbalanced
// group or character class, an unknown group syntax, or a quantifier with nothing to repeat.
func regexpProblem(pattern string) string {
	depth := 0
	canRepeat := false
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '\\':
			i++
			canRepeat = true
		case '[':
			end := i + 1
			for ; end < len(pattern) && pattern[end] != ']'; end++ {
				if pattern[end] == '\\' {
					end++
				}
			}
			if end >= len(pattern) {
				return "a character class is not closed"
			}
			i = end
			canRepeat = true
		case '(':
			depth++
			if strings.HasPrefix(pattern[i+1:], "?") {
				if m := regexpModifier.FindString(pattern[i:]); m != "" && strings.HasPrefix(pattern[i:], m) {
					i += len(m) - 1
				} else if m := regexpGroupStart.FindString(pattern[i+2:]); m != "" {
					i += 1 + len(m)
				} else {
					return "a group starts with an unknown (? syntax"
				}
			}
			canRepeat = false
		case ')':
			depth--
			if depth < 0 {
				return "a group is closed that was never opened"
			}
			canRepeat = true
		case '|':
			canRepeat = false
		case '*', '+', '?':
			if !canRepeat {
				return "a quantifier has nothing to repeat"
			}
			if i+1 < len(pattern) && pattern[i+1] == '?' {
				i++
			}
			canRepeat = false
		default:
			canRepeat = true
		}
	}
	if depth > 0 {
		return "a group is not closed"
	}
	return ""
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
		if problem := regexpProblem(pattern); problem != "" {
			v.add("the regular expression %s is refused by a browser: %s", data, problem)
		}
		if strings.ContainsRune(flags, 'd') {
			v.add("the regular expression flag d, in %s, is ES2022", data)
		}
		if strings.ContainsRune(flags, 'v') {
			v.add("the regular expression flag v, in %s, is ES2024", data)
		}
		if regexpModifier.MatchString(pattern) {
			v.add("an inline modifier group, in %s, is ES2025", data)
		}
	case js.IsNumeric(n.TokenType) && strings.ContainsRune(data, '_'):
		v.add("the numeric separator in %s is ES2021", data)
	}
}

func (v *syntaxCap) add(format string, args ...any) {
	*v.found = append(*v.found, fmt.Sprintf(format, args...))
}
