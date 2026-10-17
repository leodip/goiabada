package guard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// AssertNoStaleDeferredBodyCloses holds every deferred func-literal close of a response body to
// closing the response it was registered for.
//
// A defer statement hands the closure the variable, not the value. The shape #591 measured:
//
//	resp, err := httpClient.Get(destUrl)
//	require.NoError(t, err)
//	defer func() { _ = resp.Body.Close() }()
//	redirectLocation := assertRedirect(t, resp, "/auth/level1")
//	resp = loadPage(t, httpClient, redirectLocation)
//	defer func() { _ = resp.Body.Close() }()
//
// registers two closures that both read `resp` when the test returns, so the last response
// is closed twice and the six before it, in the longer chains, never: a body left unclosed keeps
// the transport from reusing its connection, and every step of an authorization ceremony opens a
// new one. On the tree #591 was filed against, the walk finds 832 of them, all in
// src/authserver/tests/integration.
//
// The bodyclose linter of golangci-lint cannot hold this rule: .golangci.yml excludes _test.go
// files from it (1,612 noctx and 83 bodyclose findings there against 5 and 0 in the code a binary
// ships, which is what both are for), and the shape lives in test files only. The finder here
// resolves a reassignment by object identity rather than by name, so a shadowing `:=` in a
// nested block -- which declares a new variable the closure never reads -- is not a reassignment:
// that is the one finding of difference between this walk and the scan in #591, whose 833rd
// counted api_client_administrative_scopes_test.go:259, where the outer `resp` is never
// reassigned.
//
// The walk covers the whole source tree rather than the integration tier alone: production code
// holding the shape would be equally wrong, and the scope costs nothing, since the walk reads and
// parses files and nothing else. Files that do not parse are the build tier to report and are not
// counted as walked, so an empty verdict means an empty tree, not a broken one.
func AssertNoStaleDeferredBodyCloses(t *testing.T) {
	t.Helper()

	assertNoStaleDeferredBodyCloses(t, SourceRoot(t))
}

// assertNoStaleDeferredBodyCloses is the reporting half, taking the root as a parameter and
// failing through a Reporter so a rule test can drive it against a fixture tree. See Reporter in
// guard.go for why both halves exist.
func assertNoStaleDeferredBodyCloses(r Reporter, root string) {
	r.Helper()

	stale, files, err := findStaleDeferredBodyCloses(root)
	if err != nil {
		r.Fatalf("walking %s: %v", root, err)
	}
	if files == 0 {
		// A tree with nothing to read would otherwise pass vacuously, which is the one way a
		// guard like this fails silently in the direction that matters.
		r.Fatalf("walked no Go files under %s", root)
	}
	if len(stale) == 0 {
		return
	}

	lines := make([]string, 0, len(stale))
	for _, f := range stale {
		lines = append(lines, f.file+":"+strconv.Itoa(f.line)+": `"+f.variable+"` is reassigned at line "+
			strconv.Itoa(f.reassignedAt)+", so this defer closes only the last response")
	}

	r.Errorf("%d deferred close(s) read a variable reassigned after the defer is registered:\n\t%s\n\n"+
		"A defer hands the closure the variable, not the value, so every response before the "+
		"last is left unclosed and the last is closed once per defer. Hand each closure its own "+
		"value, the shape the review of #582 fixed its one instance of in bfbaedd8:\n"+
		"\tdefer func(r *http.Response) { _ = r.Body.Close() }(resp)\n"+
		"or close the response before the variable is reassigned.",
		len(stale), strings.Join(lines, "\n\t"))
}

// staleClose is one deferred close that reads a variable reassigned after the defer is registered.
type staleClose struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	// line is the line of the defer statement.
	line int
	// variable is the name of the response variable the closure reads.
	variable string
	// reassignedAt is the line of the first assignment that stales the defer: one after it, or one
	// anywhere in a loop around it that the variable is declared outside.
	reassignedAt int
}

// findStaleDeferredBodyCloses walks every Go file under root and reports each defer statement
// whose call is a func literal closing `x.Body` of a variable that the same function assigns
// after the defer has run: a later statement, a nested closure, or the next iteration of a loop
// around it (see staleDefersInUnit). It returns the number of files it reached a verdict on, so the
// reporting half can tell "nothing to report" from "nothing was read".
//
// A function unit is a FuncDecl or a FuncLit of its own: a defer inside a nested closure runs
// when that closure returns, and what stales it is a reassignment after it inside that closure,
// so a defer is weighed against its own unit and the closures that unit holds, never against the
// unit around it. A
// reassignment reaches the variable through the same object the closure reads -- parser
// resolution, not a name match -- so a shadowing `:=` in a nested block does not count.
func findStaleDeferredBodyCloses(root string) ([]staleClose, int, error) {
	var stale []staleClose
	files := 0
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, rErr := os.ReadFile(path)
		if rErr != nil {
			return rErr
		}
		file, pErr := parser.ParseFile(fset, path, src, 0)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns, and
			// reporting it here would send the reader to the wrong place. It is not
			// counted either, so an empty verdict still means an empty walk.
			return nil
		}
		files++
		stale = append(stale, staleDefersInFile(fset, file, path, root)...)
		return nil
	})
	if err != nil {
		return nil, 0, err
	}

	sort.Slice(stale, func(i, j int) bool {
		if stale[i].file != stale[j].file {
			return stale[i].file < stale[j].file
		}
		return stale[i].line < stale[j].line
	})
	return stale, files, nil
}

// staleDefersInFile reports the stale deferred closes of one parsed file.
func staleDefersInFile(fset *token.FileSet, file *ast.File, path, root string) []staleClose {
	rel, relErr := filepath.Rel(root, path)
	if relErr != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)

	var stale []staleClose
	ast.Inspect(file, func(n ast.Node) bool {
		var body *ast.BlockStmt
		switch v := n.(type) {
		case *ast.FuncDecl:
			body = v.Body
		case *ast.FuncLit:
			body = v.Body
		default:
			return true
		}
		if body == nil {
			return true
		}
		stale = append(stale, staleDefersInUnit(fset, body, rel)...)
		return true
	})
	return stale
}

// staleDefersInUnit reports the stale deferred closes of one function unit, a FuncDecl or a
// FuncLit. A defer in a nested FuncLit belongs to that literal's own unit and is skipped here, but
// an assignment in one is not: a nested closure that reassigns the variable after the defer, such
// as a subtest's callback, runs before the unit returns. Such a closure may never run, and a
// finding there costs only the value-capturing shape, which is correct either way.
//
// A defer is stale when an assignment to the variable it closes comes after it in the source, or
// sits anywhere in a loop around it that the variable is declared outside: the next iteration runs
// that assignment after the defer. A `:=` in the loop body declares a new variable on each
// iteration, so a closure over it is clean. A range clause with `=` assigns its key and value as
// an assignment statement does.
func staleDefersInUnit(fset *token.FileSet, body *ast.BlockStmt, rel string) []staleClose {
	type deferred struct {
		stmt     *ast.DeferStmt
		variable *ast.Ident
		loops    []ast.Stmt
	}
	var defers []deferred
	var assigned []*ast.Ident

	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range s.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					assigned = append(assigned, id)
				}
			}
		case *ast.RangeStmt:
			if s.Tok == token.ASSIGN {
				for _, e := range []ast.Expr{s.Key, s.Value} {
					if id, ok := e.(*ast.Ident); ok {
						assigned = append(assigned, id)
					}
				}
			}
		}
		return true
	})

	var enclosing []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			enclosing = enclosing[:len(enclosing)-1]
			return true
		}
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if s, ok := n.(*ast.DeferStmt); ok {
			if call, ok := s.Call.Fun.(*ast.FuncLit); ok {
				if v := closedBodyVariable(call); v != nil {
					var loops []ast.Stmt
					for _, e := range enclosing {
						switch l := e.(type) {
						case *ast.ForStmt, *ast.RangeStmt:
							loops = append(loops, l.(ast.Stmt))
						}
					}
					defers = append(defers, deferred{s, v, loops})
				}
			}
		}
		enclosing = append(enclosing, n)
		return true
	})

	var stale []staleClose
	for _, d := range defers {
		obj := identObject(d.variable)
		reassignedAt := 0
		for _, id := range assigned {
			if identObject(id) != obj {
				continue
			}
			stales := id.Pos() > d.stmt.Pos()
			for _, l := range d.loops {
				declaredOutside := obj.Pos() < l.Pos() || obj.Pos() >= l.End()
				if declaredOutside && id.Pos() >= l.Pos() && id.Pos() < l.End() {
					stales = true
				}
			}
			if stales {
				reassignedAt = fset.Position(id.Pos()).Line
				break
			}
		}
		if reassignedAt != 0 {
			stale = append(stale, staleClose{
				file:         rel,
				line:         fset.Position(d.stmt.Pos()).Line,
				variable:     d.variable.Name,
				reassignedAt: reassignedAt,
			})
		}
	}
	return stale
}

// identObject returns the parser-level object an identifier resolves to. The ast.Object family is
// deprecated (SA1019) because full identifier resolution needs type information, and this guard
// is built on exactly the resolution the parser gives without loading packages: same-file
// identity through the scope chain, which is what tells a reassignment of the variable a closure
// reads from a redeclaration of its name in a nested block, the distinction #591 turns on. It
// needs no importer and no type-check, and same-file scope resolution is exact for the
// function-local variables this rule reads. The go/types route the package's other resolving
// guards take would work too, at the cost of a type-check per directory. This is the one place in
// the package that names the deprecated API.
func identObject(id *ast.Ident) *ast.Object { //nolint:staticcheck // SA1019: the parser-level object is the identity this rule resolves by
	return id.Obj
}

// identIsVar reports whether an identifier resolves to a variable, which is what a response
// holding closure can read.
func identIsVar(id *ast.Ident) bool {
	return identObject(id).Kind == ast.Var
}

// closedBodyVariable returns the response variable a deferred func literal closes over, when its
// body calls `variable.Body.Close()` on a variable declared outside the literal. A variable
// declared within the literal's source range closes over nothing and reports nothing: its own
// parameter -- the fixed shape -- and a response the literal itself requests, such as a cleanup
// that makes a call and closes what it got.
func closedBodyVariable(fl *ast.FuncLit) *ast.Ident {
	var found *ast.Ident
	ast.Inspect(fl.Body, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		closeSel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || closeSel.Sel.Name != "Close" {
			return true
		}
		bodySel, ok := closeSel.X.(*ast.SelectorExpr)
		if !ok || bodySel.Sel.Name != "Body" {
			return true
		}
		id, ok := bodySel.X.(*ast.Ident)
		if !ok || identObject(id) == nil {
			return true
		}
		if declared := identObject(id).Pos(); (declared >= fl.Pos() && declared < fl.End()) || !identIsVar(id) {
			return true
		}
		found = id
		return false
	})
	return found
}
