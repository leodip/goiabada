package testutil

import (
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
)

// AssertNoLegacyErrors holds production code to one way of constructing an error: core/errs.
//
// Three shapes are refused, and each is a way the tree used to lose something:
//
//   - An import of github.com/pkg/errors. That package captured a new stack at every call, so one
//     failure crossing the data layer, a service and a handler printed three stacks and 27 lines
//     under %+v. Retiring it is the whole of #279, and the import is how it comes back.
//   - A call to stdlib errors.New, errors.Join or fmt.Errorf. Those produce an error with no
//     stack at all, so the 500 it eventually reaches logs a message and nothing to find it by.
//     errs.New, errs.Join and errs.Errorf are drop-in and capture at the caller. One of those
//     three named without being called is the same finding: a constructor assigned to a variable
//     or passed as a callback reaches the same stackless error one indirection later, and the
//     call that runs it has no package selector left to resolve.
//   - errs.WithStack(errs.New(...)) or errs.WithStack(errs.Errorf(...)). Both inner constructors
//     already capture, so the outer call is a no-op that reads like a decision.
//   - Any errs constructor a package-level var initializer runs, which is the exemption below read
//     in the other direction. This one is not hypothetical: #279's own core sweep moved four
//     sentinels from errors.New onto errs.New, and nothing here saw it, so five
//     errs.WithStack(<sentinel>) return sites silently recorded nothing and two distinct
//     compare-and-set failures in signing_key_rotator.go printed the same init stack. "Runs"
//     rather than "contains": an immediately invoked function literal and a helper declared in the
//     same file are followed into, and a constructor bound to a package variable is refused at the
//     binding, because all three run on the init goroutine while leaving the initializer looking
//     ordinary. packageLevelVarCalls carries the reasoning and the boundary.
//
// One exemption is a rule rather than a concession: a package-level var initializer keeps stdlib
// errors.New. A sentinel is built once during init, so a stack captured there records the
// initializing goroutine and then masquerades as the origin of every error that ever wraps the
// sentinel. Sentinels are matched with errors.Is and never printed for their frames, so they lose
// nothing by staying plain, and the exemption is therefore a requirement rather than a permission:
// an errs constructor in the same position is refused. The exemption stops at a function literal:
// a func assigned to a package variable is a function body that runs when it is called, not at
// init, and its calls are reported like any other.
//
// Resolution is by import path, not by the name written at the call site: core/data/mssqldb/db.go
// imports stdlib errors as goerrors, and a check that matched the literal text "errors." would
// walk straight past it while also catching every unrelated package that happens to be called
// errors. Parentheses around a callee are stripped for the same reason, since (errors.New)("x")
// constructs exactly what errors.New("x") constructs.
//
// The boundary is one file's own imports, which is what makes this a parsing test and not a type
// check: an unrelated package re-exporting a stdlib constructor under its own name would need
// interprocedural analysis to reach, and is out of scope here.
//
// Passing dirs restricts the walk to those subdirectories of the source root, forward slashes and
// relative to it ("core", "authserver"). That is what lets the sweep land one module at a time:
// each stage widens the call until the last one drops the arguments and the whole tree is held.
//
// Scope and shape follow AssertGofmted, which carries the reasoning for walking the source root
// rather than the calling module (#279).
func AssertNoLegacyErrors(t *testing.T, dirs ...string) {
	t.Helper()

	root := SourceRoot(t)

	uses, files, err := findLegacyErrorUses(root, dirs)
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	// A root that somehow held no Go files walks nothing and would otherwise pass, which is the
	// one way a guard like this fails silently in the direction that matters.
	if files == 0 {
		t.Fatalf("walked no non-test Go files under %s (dirs: %s)", root, strings.Join(dirs, ", "))
	}
	if len(uses) == 0 {
		return
	}

	lines := make([]string, 0, len(uses))
	for _, u := range uses {
		lines = append(lines, u.file+":"+strconv.Itoa(u.line)+": "+u.what+" -- "+u.fix)
	}
	t.Errorf("%d legacy error construction(s) in %d non-test file(s):\n\t%s\n\n"+
		"Construct every error through github.com/leodip/goiabada/core/errs, which captures one "+
		"stack per error tree at the origin, and match with errors.Is / errors.As. A package-level "+
		"sentinel is the one exception and keeps stdlib errors.New (#279).",
		len(uses), files, strings.Join(lines, "\n\t"))
}

// legacyErrorUse is one refused construction, located.
type legacyErrorUse struct {
	// file is relative to the source root, forward slashes.
	file string
	line int
	what string
	fix  string
}

const errsImportPath = "github.com/leodip/goiabada/core/errs"

// errsConstructors is every exported function in core/errs that can attach frames. All of them
// are wrong in a package-level var for the one reason: the frames would be init's.
var errsConstructors = map[string]bool{
	"New": true, "Errorf": true, "Wrap": true, "Wrapf": true, "WithStack": true, "Join": true,
}

// dotImportHidesTheRule lists the packages whose constructors this file refuses or restricts, and
// which a dot import would therefore make invisible to it: stdlib errors and fmt spell the refused
// New, Join and Errorf, and core/errs spells the constructors a package-level var may not call.
// github.com/pkg/errors is absent because its import is already the finding, whatever it is named.
var dotImportHidesTheRule = map[string]bool{
	"errors": true, "fmt": true, errsImportPath: true,
}

// findLegacyErrorUses parses every non-test Go file under root, or under the named subdirectories
// of root, and reports each refused construction along with the number of files it parsed.
func findLegacyErrorUses(root string, dirs []string) ([]legacyErrorUse, int, error) {
	roots := []string{root}
	if len(dirs) > 0 {
		roots = roots[:0]
		for _, dir := range dirs {
			roots = append(roots, filepath.Join(root, filepath.FromSlash(dir)))
		}
	}

	var uses []legacyErrorUse
	files := 0
	for _, start := range roots {
		err := filepath.WalkDir(start, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return errs.Wrapf(relErr, "relating %s to %s", path, root)
			}
			rel = filepath.ToSlash(rel)
			if exemptByPath(rel) {
				return nil
			}
			fset := token.NewFileSet()
			// ParseComments because the build constraint is a comment, and a file excluded from
			// every production build is exempt.
			file, pErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if pErr != nil {
				// A file that does not parse is a compile error the build tier owns, and
				// reporting it here would send the reader to the wrong place.
				return nil
			}
			if exemptByBuildConstraint(file, fset) {
				return nil
			}
			files++
			uses = append(uses, legacyErrorUsesInFile(file, fset, rel)...)
			return nil
		})
		if err != nil {
			return nil, files, err
		}
	}

	sort.Slice(uses, func(i, j int) bool {
		if uses[i].file != uses[j].file {
			return uses[i].file < uses[j].file
		}
		return uses[i].line < uses[j].line
	})
	return uses, files, nil
}

// exemptByPath covers the three directories and one suffix that are allowed to construct errors
// any way they like: core/errs is the replacement itself, a mocks directory is generated or
// hand-written scaffolding that no production path constructs errors from, and a test file is not
// production code.
func exemptByPath(rel string) bool {
	if strings.HasSuffix(rel, "_test.go") {
		return true
	}
	if rel == "core/errs" || strings.HasPrefix(rel, "core/errs/") {
		return true
	}
	for _, segment := range strings.Split(rel, "/") {
		if segment == "mocks" {
			return true
		}
	}
	return false
}

// exemptByBuildConstraint reports whether the file's //go:build expression cannot be true in any
// build that sets the production tag. Every other tag in the expression is free, so each
// assignment of them is evaluated with production true and the file is exempt only when all of
// them come out false.
//
// Evaluating with production alone would be wrong in both directions: it would exempt
// "linux || !production", which is true on every production Linux build, and it would walk
// "!production && tools", which can never be part of one.
func exemptByBuildConstraint(file *ast.File, fset *token.FileSet) bool {
	expr := buildConstraint(file, fset)
	if expr == nil {
		return false
	}
	free := freeTags(expr)
	// A pathological expression is walked rather than exempted: 2^n assignments is the cost of
	// the answer, and refusing to pay it must never be the permissive direction.
	if len(free) > 12 {
		return false
	}
	for assignment := 0; assignment < 1<<len(free); assignment++ {
		values := make(map[string]bool, len(free))
		for i, tag := range free {
			values[tag] = assignment&(1<<i) != 0
		}
		satisfied := expr.Eval(func(tag string) bool {
			if tag == "production" {
				return true
			}
			return values[tag]
		})
		if satisfied {
			return false
		}
	}
	return true
}

// buildConstraint returns the file's //go:build expression, or nil when it has none. Only comments
// above the package clause count, which is what go/build itself requires.
func buildConstraint(file *ast.File, fset *token.FileSet) constraint.Expr {
	packageLine := fset.Position(file.Package).Line
	for _, group := range file.Comments {
		if fset.Position(group.End()).Line >= packageLine {
			break
		}
		for _, comment := range group.List {
			if !constraint.IsGoBuild(comment.Text) {
				continue
			}
			expr, err := constraint.Parse(comment.Text)
			if err != nil {
				return nil
			}
			return expr
		}
	}
	return nil
}

// freeTags lists every tag in expr except production, deduplicated and in a stable order.
func freeTags(expr constraint.Expr) []string {
	seen := map[string]bool{}
	var tags []string
	var walk func(constraint.Expr)
	walk = func(e constraint.Expr) {
		switch x := e.(type) {
		case *constraint.TagExpr:
			if x.Tag == "production" || seen[x.Tag] {
				return
			}
			seen[x.Tag] = true
			tags = append(tags, x.Tag)
		case *constraint.NotExpr:
			walk(x.X)
		case *constraint.AndExpr:
			walk(x.X)
			walk(x.Y)
		case *constraint.OrExpr:
			walk(x.X)
			walk(x.Y)
		}
	}
	walk(expr)
	sort.Strings(tags)
	return tags
}

// legacyErrorUsesInFile reports every refused construction in one parsed file.
func legacyErrorUsesInFile(file *ast.File, fset *token.FileSet, rel string) []legacyErrorUse {
	var uses []legacyErrorUse

	// importPaths maps the name a file actually writes at a call site to the path it imports, so
	// the goerrors alias in core/data/mssqldb/db.go resolves like any other.
	importPaths := map[string]string{}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		if path == "github.com/pkg/errors" {
			uses = append(uses, legacyErrorUse{
				file: rel,
				line: fset.Position(spec.Pos()).Line,
				what: `import "github.com/pkg/errors"`,
				fix:  "import " + errsImportPath + " instead",
			})
		}
		name := defaultImportName(path)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "." {
			// A dot import binds the package's exported names unqualified, so errors.New is
			// written New and there is no selector left for qualifiedCall to resolve: the whole
			// rule below walks straight past the file. Refusing the import is the answer rather
			// than resolving unqualified calls, which would also have to model every local
			// declaration that shadows one. Nothing in this tree dot-imports any of the three,
			// and doing so could only hide a construction this rule exists to refuse (#279).
			if dotImportHidesTheRule[path] {
				uses = append(uses, legacyErrorUse{
					file: rel,
					line: fset.Position(spec.Pos()).Line,
					what: `dot import of "` + path + `"`,
					fix:  "import it under its own name; a dot import hides its constructors from this rule",
				})
			}
			continue
		}
		if name == "_" {
			continue
		}
		importPaths[name] = path
	}

	sentinels, initSelectors := packageLevelVarCalls(file)
	callees := calleeSelectors(file)

	ast.Inspect(file, func(n ast.Node) bool {
		// A constructor handed round as a value reaches the same stackless error one indirection
		// later, and the call that eventually runs it has no selector left to resolve, so the
		// rule below walks past it. Refusing the selector is the answer rather than following the
		// value to its call, which would mean tracking every assignment, parameter and field it
		// passes through. Nothing in this tree does it today; it is one keystroke away (#279).
		if sel, isSelector := n.(*ast.SelectorExpr); isSelector {
			if callees[sel] {
				return true
			}
			pkg, fn, resolved := qualifiedSelector(sel, importPaths)
			if !resolved {
				return true
			}
			what, fix := "", ""
			switch {
			case pkg == "errors" && (fn == "New" || fn == "Join"):
				what, fix = "stdlib errors."+fn, "use errs."+fn
			case pkg == "fmt" && fn == "Errorf":
				what, fix = "fmt.Errorf", "use errs.Errorf"
			case pkg == errsImportPath && errsConstructors[fn] && initSelectors[sel]:
				// The mirror image of the package-level rule below, and only in that position: an
				// errs constructor bound to a package variable is called through a bare identifier
				// with no selector left to resolve, so "var newErr = errs.New" followed by
				// "var ErrX = newErr(...)" builds a sentinel carrying init's frames and the call
				// rule cannot see it. Elsewhere the same value is fine, because the stack it
				// captures is its caller's, which is the whole point of errs; that is why this
				// arm asks where the name is bound rather than refusing the constructor as a
				// value everywhere (#279).
				what, fix = "errs."+fn, "call it where the error is made; bound to a package variable it can be run during package initialization, and its stack would be init's"
			default:
				return true
			}
			uses = append(uses, legacyErrorUse{file: rel, line: fset.Position(sel.Pos()).Line,
				what: what + " as a value", fix: fix})
			return true
		}

		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		pkg, fn, ok := qualifiedCall(call, importPaths)
		if !ok {
			return true
		}
		line := fset.Position(call.Pos()).Line
		switch {
		case pkg == "errors" && (fn == "New" || fn == "Join"):
			if sentinels[call] {
				return true
			}
			uses = append(uses, legacyErrorUse{file: rel, line: line,
				what: "stdlib errors." + fn, fix: "use errs." + fn})
		case pkg == "fmt" && fn == "Errorf":
			if sentinels[call] {
				return true
			}
			uses = append(uses, legacyErrorUse{file: rel, line: line,
				what: "fmt.Errorf", fix: "use errs.Errorf"})
		case pkg == errsImportPath && sentinels[call] && errsConstructors[fn]:
			uses = append(uses, legacyErrorUse{file: rel, line: line,
				what: "errs." + fn + " in a package-level var",
				fix:  "a sentinel keeps stdlib errors.New; errs captures the init goroutine's stack"})
		case pkg == errsImportPath && fn == "WithStack":
			if len(call.Args) != 1 {
				return true
			}
			inner, ok := unparen(call.Args[0]).(*ast.CallExpr)
			if !ok {
				return true
			}
			innerPkg, innerFn, ok := qualifiedCall(inner, importPaths)
			if !ok || innerPkg != errsImportPath || (innerFn != "New" && innerFn != "Errorf") {
				return true
			}
			uses = append(uses, legacyErrorUse{file: rel, line: line,
				what: "errs.WithStack(errs." + innerFn + "(...))",
				fix:  "errs." + innerFn + " already captures a stack; drop the WithStack"})
		}
		return true
	})

	return uses
}

// qualifiedCall resolves a call of the form pkg.Fn(...) to the imported path and the function
// name. A selector whose left side is not an imported package name, a method on a value or a
// deeper expression, is not one of ours.
func qualifiedCall(call *ast.CallExpr, importPaths map[string]string) (string, string, bool) {
	sel, ok := unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	return qualifiedSelector(sel, importPaths)
}

// qualifiedSelector is the same resolution for a selector reached anywhere, whether it is being
// called or passed around as a value.
func qualifiedSelector(sel *ast.SelectorExpr, importPaths map[string]string) (string, string, bool) {
	ident, ok := unparen(sel.X).(*ast.Ident)
	if !ok {
		return "", "", false
	}
	path, ok := importPaths[ident.Name]
	if !ok {
		return "", "", false
	}
	return path, sel.Sel.Name, true
}

// calleeSelectors collects the selector each call actually invokes, so the walk above can tell
// errors.New("x"), which it classifies as a call, from errors.New handed round as a value, which
// it classifies separately. Without it every direct call would be reported twice.
func calleeSelectors(file *ast.File) map[*ast.SelectorExpr]bool {
	callees := map[*ast.SelectorExpr]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, isSelector := unparen(call.Fun).(*ast.SelectorExpr); isSelector {
			callees[sel] = true
		}
		return true
	})
	return callees
}

// unparen strips the parentheses around an expression. (errors.New)("x") calls exactly what
// errors.New("x") calls, and a rule reading only the bare form is one pair of brackets away from
// being silent on it.
func unparen(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

// defaultImportName is the name an unaliased import binds, which for every path in this tree is
// its last element.
func defaultImportName(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// packageLevelVarCalls collects the calls that are evaluated during package initialization, which
// is the one place a stackless stdlib error is correct and the one place an errs constructor is
// not.
//
// Reaching them takes more than the initializer expression itself, because "runs at init" is a
// property of what the initializer eventually calls and not of where the call is written. Three
// shapes put an errs constructor on the init goroutine while leaving the initializer looking
// innocent, and all three ran during review with nothing reported:
//
//	var errFoo = func() error { return errs.New("x") }()   // immediately invoked
//	var newErr = errs.New                                  // the constructor as a value
//	var errBar = build()                                   // a helper in this same file
//
// So the walk follows an immediately invoked function literal into its body, and a call to a
// function declared in this file into that function's body, transitively. A function literal that
// is only assigned runs when it is called rather than at init, and is still not followed. The
// second shape is caught elsewhere, by refusing an errs constructor named without being called.
//
// The boundary is one file, which is what keeps this a parsing test: a helper in another package,
// or a constructor reached through a value this walk cannot resolve, needs type and call
// information to follow and is out of scope here, stated rather than discovered later.
func packageLevelVarCalls(file *ast.File) (map[*ast.CallExpr]bool, map[*ast.SelectorExpr]bool) {
	declared := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Recv == nil && fn.Body != nil {
			declared[fn.Name.Name] = fn
		}
	}

	exempt := map[*ast.CallExpr]bool{}
	selectors := map[*ast.SelectorExpr]bool{}
	entered := map[string]bool{}

	var walk func(node ast.Node)
	walk = func(node ast.Node) {
		ast.Inspect(node, func(n ast.Node) bool {
			switch it := n.(type) {
			case *ast.SelectorExpr:
				selectors[it] = true
				return true
			case *ast.FuncLit:
				// Reached as a value rather than as a callee: it runs when something calls it.
				return false
			case *ast.CallExpr:
				exempt[it] = true
				switch callee := unparen(it.Fun).(type) {
				case *ast.FuncLit:
					walk(callee.Body)
				case *ast.Ident:
					if fn, isLocal := declared[callee.Name]; isLocal && !entered[callee.Name] {
						entered[callee.Name] = true
						walk(fn.Body)
					}
				}
				// The arguments are still init-time expressions, so keep descending into them.
				for _, arg := range it.Args {
					walk(arg)
				}
				return false
			}
			return true
		})
	}

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, expr := range value.Values {
				walk(expr)
			}
		}
	}
	return exempt, selectors
}
