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
// (ES2023), the v flag (ES2024) and inline modifiers (ES2025). A classic script cannot import or
// export, so module syntax is refused too.
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
		if n.Op == js.AwaitToken && !v.async {
			v.add("await outside an async function is top-level await, ES2022, and a module's alone")
		}
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

func (v *syntaxCap) literal(n *js.LiteralExpr) {
	data := string(n.Data)
	switch {
	case n.TokenType == js.RegExpToken:
		end := strings.LastIndexByte(data, '/')
		pattern, flags := data[1:end], data[end+1:]
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
