package ceremony

// The one place the auth server is held to "a request field is written at /auth/authorize and
// nowhere else".
//
// A request field is what the authorization request asked for, and Restart keeps it: a restarted
// ceremony re-authenticates somebody against the same request. That is only true while nothing
// after /auth/authorize rewrites one. Scope was the counter-example: it was narrowed in place by two
// later hops, so a restart carried the first user's narrowing to whoever signed in next, and it had
// to become an attempt field with RequestedScope beside it as the request (#436). The classification
// test in auth_context_fields_test.go says which fields are request fields; this guard holds every
// write to one to HandleAuthorizeGet, the handler that accepts the request, closures inside it
// included, and holds the setters that write one to being called from there too.
//
// Fields and methods are resolved as go/types objects, so a write is caught whatever the variable
// holding the context is called, through a pointer, a promoted field or a method expression. What it
// does not see: it follows fields, not data flow. UILocales is the one request field of a reference
// type, and a copy of it taken into a local, or passed to a callee, shares its backing array, so a
// write through that copy reaches the context unseen. Every other request field is a string.
//
// It reads, parses and type-checks files and nothing else: no database, no git, no network.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requestFieldScope is the tree the rule covers, relative to the source root, forward slashes.
// AuthContext is internal to the auth server, so no other module can name it.
const requestFieldScope = "authserver"

// requestFieldModuleParent is what a directory under the source root is prefixed with to make its
// import path. Every first-party package is read from source through it, so a context reached
// through any of them has a type the walk can see.
const requestFieldModuleParent = "github.com/leodip/goiabada/"

const (
	requestFieldCeremonyPath = requestFieldModuleParent + "authserver/internal/ceremony"
	requestFieldHandlersPath = requestFieldModuleParent + "authserver/internal/handlers"
)

// requestFieldSetters are the AuthContext methods that write a request field. A call to one is a
// write, refused outside the writer like an assignment, and its own body is where that write
// happens, so the body is exempt. A method writing a request field that is not listed here is
// therefore refused for the write in its body.
var requestFieldSetters = []string{"SetTargetAcrLevel"}

// requestFieldWriter names the one function whose body may write a request field: the handler that
// accepts the authorization request. Function literals inside it are inside it.
var requestFieldWriter = requestFieldFunc{pkg: requestFieldHandlersPath, name: "HandleAuthorizeGet"}

// requestFieldFunc is a function or method named by its package's import path, its receiver's type
// name (empty for a function) and its own.
type requestFieldFunc struct {
	pkg, recv, name string
}

// requestFieldWrite is one write the rule refuses, or one it could not judge.
type requestFieldWrite struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
	what string
}

// requestFieldWalk is what one walk found. The last three fields are how the reporting half tells
// "nothing to report" from "nothing was read": a walk that parsed no file, that never found
// AuthContext, or that was handed a field or setter AuthContext does not declare has checked nothing
// it was asked to check.
type requestFieldWalk struct {
	found, unresolved []requestFieldWrite
	files             int
	authContextFound  bool
	undeclared        []string
}

// findRequestFieldWrites walks root/scope for non-test Go files, type-checks every package it finds,
// and reports each write to a listed request field of ceremony.AuthContext outside the writer. The
// forms it refuses:
//
//   - `=`, `op=`, `++` and `--`, and a range clause assigning with `=`, whose target is a request
//     field or an index or slice expression rooted at one;
//   - `=` whose target is a whole AuthContext, such as `*ac = other`. A `:=` or a var declaration
//     makes a new value and writes nothing already stored;
//   - `&` of a request field or of an element of one;
//   - an AuthContext composite literal whose keys name a request field, or any non-empty positional
//     one, which sets every field;
//   - a request field, or an index or slice expression rooted at one, as the destination of copy,
//     the first argument of append, or the argument of clear;
//   - any reference to a listed setter: a call, a method value or a method expression.
//
// Each of those written on a receiver whose type the checker could not determine, and naming a
// request field or a setter, is returned as unresolved rather than guessed at.
func findRequestFieldWrites(
	root, scope string, fields, setters []string, writer requestFieldFunc,
) (requestFieldWalk, error) {
	var walk requestFieldWalk
	start := filepath.Join(root, filepath.FromSlash(scope))

	var dirs []string
	err := filepath.WalkDir(start, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if p != start && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if isProductionGoFile(d.Name()) && !slices.Contains(dirs, filepath.Dir(p)) {
			dirs = append(dirs, filepath.Dir(p))
		}
		return nil
	})
	if err != nil {
		return walk, err
	}
	sort.Strings(dirs)

	imp := newRequestFieldPackages(root)
	ceremonyPkg, err := imp.Import(requestFieldCeremonyPath)
	if err != nil {
		return walk, err
	}
	rule := requestFieldRule{
		fieldNames:  map[string]bool{},
		setterNames: map[string]bool{},
		fields:      map[*types.Var]string{},
		setters:     map[*types.Func]string{},
		writer:      writer,
	}
	for _, name := range fields {
		rule.fieldNames[name] = true
	}
	for _, name := range setters {
		rule.setterNames[name] = true
	}
	if typeName, ok := ceremonyPkg.Scope().Lookup("AuthContext").(*types.TypeName); ok {
		if named, isNamed := typeName.Type().(*types.Named); isNamed {
			walk.authContextFound = true
			rule.authContext = named
			walk.undeclared = rule.resolve(named, fields, setters)
		}
	}

	for _, dir := range dirs {
		relDir, rErr := filepath.Rel(root, dir)
		if rErr != nil {
			return walk, rErr
		}
		pkgPath := requestFieldModuleParent + filepath.ToSlash(relDir)
		if _, iErr := imp.Import(pkgPath); iErr != nil {
			return walk, iErr
		}
		info := imp.infos[pkgPath]
		for _, file := range imp.files[pkgPath] {
			walk.files++
			if !walk.authContextFound {
				continue
			}
			rel, rErr := filepath.Rel(root, imp.fset.Position(file.Pos()).Filename)
			if rErr != nil {
				return walk, rErr
			}
			found, unresolved := rule.check(file, imp.fset, filepath.ToSlash(rel), pkgPath, info)
			walk.found = append(walk.found, found...)
			walk.unresolved = append(walk.unresolved, unresolved...)
		}
	}
	return walk, nil
}

// requestFieldRule is the rule with every listed name resolved to the object the checker made for
// it, so a match is object identity and never a spelling.
type requestFieldRule struct {
	authContext *types.Named
	fieldNames  map[string]bool
	setterNames map[string]bool
	fields      map[*types.Var]string
	setters     map[*types.Func]string
	writer      requestFieldFunc
}

// resolve finds each listed field and setter on AuthContext and returns the names it does not
// declare, each of which guards nothing.
func (rule *requestFieldRule) resolve(named *types.Named, fields, setters []string) (undeclared []string) {
	st, _ := named.Underlying().(*types.Struct)
	for _, name := range fields {
		found := false
		for i := 0; st != nil && i < st.NumFields(); i++ {
			if st.Field(i).Name() == name {
				rule.fields[st.Field(i)] = name
				found = true
			}
		}
		if !found {
			undeclared = append(undeclared, "field "+name)
		}
	}
	for _, name := range setters {
		found := false
		for i := range named.NumMethods() {
			if named.Method(i).Name() == name {
				rule.setters[named.Method(i)] = name
				found = true
			}
		}
		if !found {
			undeclared = append(undeclared, "method "+name)
		}
	}
	return undeclared
}

// exempt reports whether a declaration's body may write a request field: the writer's, and each
// setter's own.
func (rule *requestFieldRule) exempt(decl ast.Decl, pkgPath string) bool {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok {
		return false
	}
	recv := ""
	if fn.Recv != nil && len(fn.Recv.List) == 1 {
		typ := fn.Recv.List[0].Type
		if star, isStar := typ.(*ast.StarExpr); isStar {
			typ = star.X
		}
		if ident, isIdent := typ.(*ast.Ident); isIdent {
			recv = ident.Name
		}
	}
	if pkgPath == rule.writer.pkg && recv == rule.writer.recv && fn.Name.Name == rule.writer.name {
		return true
	}
	return pkgPath == requestFieldCeremonyPath && recv == "AuthContext" && rule.setterNames[fn.Name.Name]
}

// check applies the rule to one file, skipping the exempt declarations whole.
func (rule *requestFieldRule) check(
	file *ast.File, fset *token.FileSet, rel, pkgPath string, info *types.Info,
) (found, unresolved []requestFieldWrite) {
	at := func(pos token.Pos, what string) requestFieldWrite {
		return requestFieldWrite{file: rel, line: fset.Position(pos).Line, what: what}
	}

	// target judges an expression something writes through: a request field, or an element or a
	// slice of one, is a finding; a field-named selector the checker could not type is unresolved.
	target := func(expr ast.Expr, verb string) {
		root := requestFieldRoot(expr)
		sel, ok := root.(*ast.SelectorExpr)
		if !ok {
			return
		}
		if v, isVar := info.Uses[sel.Sel].(*types.Var); isVar {
			if name, isRequest := rule.fields[v]; isRequest {
				found = append(found, at(expr.Pos(), verb+" "+name))
			}
			return
		}
		if rule.fieldNames[sel.Sel.Name] && info.Uses[sel.Sel] == nil && !requestFieldIsPackage(sel.X, info) {
			unresolved = append(unresolved, at(expr.Pos(), verb+" "+sel.Sel.Name))
		}
	}
	whole := func(expr ast.Expr) {
		if tv, ok := info.Types[expr]; ok && tv.Type != nil && types.Identical(tv.Type, rule.authContext) {
			found = append(found, at(expr.Pos(), "assigns a whole AuthContext"))
		}
	}

	for _, decl := range file.Decls {
		if rule.exempt(decl, pkgPath) {
			continue
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				if n.Tok == token.DEFINE {
					return true
				}
				verb := "assigns"
				if n.Tok != token.ASSIGN {
					verb = "applies " + n.Tok.String() + " to"
				}
				for _, lhs := range n.Lhs {
					target(lhs, verb)
					if n.Tok == token.ASSIGN {
						whole(lhs)
					}
				}
			case *ast.RangeStmt:
				if n.Tok != token.ASSIGN {
					return true
				}
				for _, lhs := range []ast.Expr{n.Key, n.Value} {
					if lhs != nil {
						target(lhs, "assigns by range")
						whole(lhs)
					}
				}
			case *ast.IncDecStmt:
				target(n.X, "applies "+n.Tok.String()+" to")
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					target(n.X, "takes the address of")
				}
			case *ast.CallExpr:
				fun, ok := ast.Unparen(n.Fun).(*ast.Ident)
				if !ok || len(n.Args) == 0 {
					return true
				}
				if builtin, isBuiltin := info.Uses[fun].(*types.Builtin); isBuiltin {
					switch builtin.Name() {
					case "copy", "append", "clear":
						target(n.Args[0], "passes to "+builtin.Name())
					}
				}
			case *ast.CompositeLit:
				tv, ok := info.Types[n]
				if !ok || tv.Type == nil || !types.Identical(tv.Type, rule.authContext) {
					return true
				}
				for _, elt := range n.Elts {
					kv, isKV := elt.(*ast.KeyValueExpr)
					if !isKV {
						found = append(found, at(n.Pos(), "builds an AuthContext literal positionally"))
						break
					}
					if key, isIdent := kv.Key.(*ast.Ident); isIdent {
						if v, isVar := info.Uses[key].(*types.Var); isVar {
							if name, isRequest := rule.fields[v]; isRequest {
								found = append(found, at(kv.Pos(), "sets "+name+" in an AuthContext literal"))
							}
						}
					}
				}
			case *ast.SelectorExpr:
				if fn, isFunc := info.Uses[n.Sel].(*types.Func); isFunc {
					if name, isSetter := rule.setters[fn]; isSetter {
						found = append(found, at(n.Pos(), "calls "+name))
					}
					return true
				}
				if rule.setterNames[n.Sel.Name] && info.Uses[n.Sel] == nil && !requestFieldIsPackage(n.X, info) {
					unresolved = append(unresolved, at(n.Pos(), "calls "+n.Sel.Name))
				}
			}
			return true
		})
	}
	return found, unresolved
}

// requestFieldRoot strips the parentheses, index and slice expressions off what a statement writes
// through, down to the operand they index: ac.UILocales[i] and ac.UILocales[1:] both write through
// ac.UILocales.
func requestFieldRoot(expr ast.Expr) ast.Expr {
	for {
		switch e := expr.(type) {
		case *ast.ParenExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.SliceExpr:
			expr = e.X
		default:
			return expr
		}
	}
}

// requestFieldIsPackage reports whether a selector's operand is a package name, which makes it a
// qualified identifier rather than a field or method on a receiver.
func requestFieldIsPackage(x ast.Expr, info *types.Info) bool {
	ident, ok := x.(*ast.Ident)
	if !ok {
		return false
	}
	_, isPkg := info.Uses[ident].(*types.PkgName)
	return isPkg
}

func isProductionGoFile(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
}

// requestFieldPackages is the importer the rule type-checks against, and the record of what it
// checked: every first-party package is read from the source root, once, with what the checker
// resolved in it kept for the walk, and every other path is an empty stub. One check per package is
// what makes a field reached through another package the same object as the one the rule resolved.
//
// A stubbed package's types are invalid, so a context could only hide behind one if a stdlib or
// third-party function returned it, which none can name. core/testutil's stubPackages and the
// discarded-error lint's importer in internal/server are the twins of the stub half.
type requestFieldPackages struct {
	root  string
	fset  *token.FileSet
	made  map[string]*types.Package
	infos map[string]*types.Info
	files map[string][]*ast.File
}

func newRequestFieldPackages(root string) *requestFieldPackages {
	return &requestFieldPackages{
		root:  root,
		fset:  token.NewFileSet(),
		made:  map[string]*types.Package{},
		infos: map[string]*types.Info{},
		files: map[string][]*ast.File{},
	}
}

func (p *requestFieldPackages) Import(importPath string) (*types.Package, error) {
	if made, ok := p.made[importPath]; ok {
		return made, nil
	}

	var files []*ast.File
	if strings.HasPrefix(importPath, requestFieldModuleParent) {
		dir := filepath.Join(p.root, filepath.FromSlash(strings.TrimPrefix(importPath, requestFieldModuleParent)))
		entries, err := os.ReadDir(dir)
		if err != nil && !os.IsNotExist(err) {
			return nil, errs.Wrapf(err, "reading %s from the source root", importPath)
		}
		clause := ""
		for _, entry := range entries {
			if entry.IsDir() || !isProductionGoFile(entry.Name()) {
				continue
			}
			file, pErr := parser.ParseFile(p.fset, filepath.Join(dir, entry.Name()), nil, parser.SkipObjectResolution)
			if pErr != nil {
				// A file that does not parse is a compile error the build tier owns.
				continue
			}
			// One package per directory; a stray clause would be a second package the build tier
			// refuses, and checking it with the first would only add errors.
			if clause == "" {
				clause = file.Name.Name
			}
			if file.Name.Name == clause {
				files = append(files, file)
			}
		}
	}
	if len(files) == 0 {
		// A path outside this repository, or one a fixture tree does not hold.
		pkg := types.NewPackage(importPath, requestFieldPackageName(importPath))
		pkg.MarkComplete()
		p.made[importPath] = pkg
		return pkg, nil
	}

	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{},
		Uses:  map[*ast.Ident]types.Object{},
	}
	conf := types.Config{
		Importer: p,
		// Every package outside this repository is a stub, so the checker has plenty to say about
		// members it never read. Discarding it keeps the check running to the end; what this guard
		// asks survives, because a receiver's type either came from a package that was read or is
		// reported as unresolved.
		Error:                    func(error) {},
		DisableUnusedImportCheck: true,
	}
	// The returned error is the first one Error already saw; info is filled in either way.
	pkg, _ := conf.Check(importPath, p.fset, files, info)
	if pkg == nil {
		return nil, errs.Errorf("type-checking %s produced no package", importPath)
	}
	pkg.MarkComplete()
	p.made[importPath] = pkg
	p.infos[importPath] = info
	p.files[importPath] = files
	return pkg, nil
}

// requestFieldMajorVersion is a module path's major-version element, which is never the name.
var requestFieldMajorVersion = regexp.MustCompile(`^v[0-9]+$`)

// requestFieldPackageName guesses a stubbed path's package name, and is harmless when wrong: a name
// that does not match only leaves that package's selectors unresolved, and a stub declares nothing
// to resolve anyway.
func requestFieldPackageName(importPath string) string {
	elems := strings.Split(importPath, "/")
	base := elems[len(elems)-1]
	if requestFieldMajorVersion.MatchString(base) && len(elems) > 1 {
		base = elems[len(elems)-2]
	}
	if i := strings.Index(base, "."); i > 0 {
		base = base[:i]
	}
	base = strings.ReplaceAll(base, "-", "")
	if base == "" {
		return "p"
	}
	return base
}

// TestRequestFields_WrittenOnlyAtAuthorize holds the real tree to the rule, with the request fields
// the classification test names.
func TestRequestFields_WrittenOnlyAtAuthorize(t *testing.T) {
	assertRequestFieldsWrittenOnce(t, testutil.SourceRoot(t), requestFieldScope, requestFields, requestFieldSetters, requestFieldWriter)
}

// assertRequestFieldsWrittenOnce is the reporting half, taking the root, the scope and the lists as
// parameters and failing through a testutil.Reporter so a rule test can drive it against a fixture
// tree.
func assertRequestFieldsWrittenOnce(r testutil.Reporter, root, scope string, fields, setters []string, writer requestFieldFunc) {
	r.Helper()

	walk, err := findRequestFieldWrites(root, scope, fields, setters, writer)
	if err != nil {
		r.Fatalf("walking %s: %v", filepath.Join(root, filepath.FromSlash(scope)), err)
	}
	if walk.files == 0 {
		r.Fatalf("read no production Go files under %s", scope)
	}
	if !walk.authContextFound {
		r.Fatalf("found no AuthContext type in %s, so no write could be recognised", requestFieldCeremonyPath)
	}
	if len(walk.undeclared) > 0 {
		r.Fatalf("AuthContext declares no %s, so the rule guards nothing under that name",
			strings.Join(walk.undeclared, ", "))
	}

	if len(walk.found) > 0 {
		r.Errorf("%d write(s) under %s to an AuthContext request field outside %s:\n\t%s\n\n"+
			"A request field is what /auth/authorize accepted, and a restart keeps it, which is only true "+
			"while nothing after /auth/authorize writes one. Write it in %s, or, if the value is something an "+
			"authentication decides, move the field to attemptFields in auth_context_fields_test.go so Restart "+
			"discards it (#436).",
			len(walk.found), scope, writer.name, requestFieldLines(walk.found), writer.name)
	}
	if len(walk.unresolved) > 0 {
		r.Errorf("%d write(s) under %s to a field or setter named like an AuthContext request field, on a "+
			"receiver whose type this walk cannot resolve:\n\t%s\n\n"+
			"Request fields are found by type, and a receiver typed through a package outside this repository "+
			"cannot be told from an AuthContext. Give the receiver a type the walk can see (#436).",
			len(walk.unresolved), scope, requestFieldLines(walk.unresolved))
	}
}

// requestFieldLines renders writes one per line, sorted, as file:line: what.
func requestFieldLines(writes []requestFieldWrite) string {
	lines := requestFieldStrings(writes)
	sort.Strings(lines)
	return strings.Join(lines, "\n\t")
}

// requestFieldStrings renders writes for comparison, unsorted.
func requestFieldStrings(writes []requestFieldWrite) []string {
	lines := make([]string, 0, len(writes))
	for _, w := range writes {
		lines = append(lines, w.file+":"+strconv.Itoa(w.line)+": "+w.what)
	}
	return lines
}

// requestFieldFixtureFields are the request fields a fixture's AuthContext declares, one string and
// the slice, which between them take every write form.
var requestFieldFixtureFields = []string{"State", "UILocales", "TargetAcrLevel"}

// requestFieldCeremonyFixture is the ceremony package in a fixture tree: AuthContext with the fixture
// request fields and one attempt field, the setter, and the reads production makes.
const requestFieldCeremonyFixture = `package ceremony

import "encoding/json"

type AuthContext struct {
	State          string
	UILocales      []string
	TargetAcrLevel string
	Scope          string
}

func (ac *AuthContext) SetTargetAcrLevel(level string) {
	ac.TargetAcrLevel = level
}

func (ac *AuthContext) SetScope(scope string) {
	ac.Scope = scope
}

type Store struct{ data string }

func (s *Store) GetAuthContext() (*AuthContext, error) {
	var authContext AuthContext
	if err := json.Unmarshal([]byte(s.data), &authContext); err != nil {
		return nil, err
	}
	return &authContext, nil
}

func (s *Store) UILocales() []string {
	authContext, err := s.GetAuthContext()
	if err != nil || len(authContext.UILocales) == 0 {
		return nil
	}
	return authContext.UILocales
}
`

// requestFieldAuthorizeFixture is the writer in a fixture tree, writing every request field by every
// form the rule refuses elsewhere, in its body and in the closure it returns.
const requestFieldAuthorizeFixture = `package handlers

import "github.com/leodip/goiabada/authserver/internal/ceremony"

func HandleAuthorizeGet(state string) func() *ceremony.AuthContext {
	ac := &ceremony.AuthContext{State: state}
	ac.State += "-suffix"
	ac.UILocales = append(ac.UILocales, "en")
	return func() *ceremony.AuthContext {
		ac.UILocales[0] = "pt-BR"
		copy(ac.UILocales, []string{"en"})
		p := &ac.State
		*p = "x"
		*ac = ceremony.AuthContext{"s", nil, "t", "u"}
		ac.SetTargetAcrLevel("urn:goiabada:level1")
		return ac
	}
}
`

// TestRequestFieldWrites_Finder_RefusesEveryWriteFormAndNoRead is the synthetic half: a fixture tree
// holding every form the rule refuses, each outside the writer, and every read and exempt write it
// must leave alone, so a finder that has quietly stopped matching anything is caught here rather
// than trusted.
func TestRequestFieldWrites_Finder_RefusesEveryWriteFormAndNoRead(t *testing.T) {
	root := t.TempDir()
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context.go", requestFieldCeremonyFixture)
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/handler_authorize.go", requestFieldAuthorizeFixture)

	// Refused: each form once, through differently named variables, a promoted field and a method
	// expression.
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/handler_auth_issue.go", `package handlers

import "github.com/leodip/goiabada/authserver/internal/ceremony"

type wrapped struct {
	*ceremony.AuthContext
}

func issue(authContext *ceremony.AuthContext, other ceremony.AuthContext, w wrapped, locales []string) {
	authContext.State = "a"
	authContext.State += "b"
	w.State = "c"
	authContext.UILocales[0] = "d"
	(authContext.UILocales)[1] = "e"
	*authContext = other
	for _, authContext.State = range locales {
	}
	p := &authContext.State
	q := &authContext.UILocales[0]
	copy(authContext.UILocales[1:], locales)
	_ = append(authContext.UILocales, "f")
	clear(authContext.UILocales)
	_ = ceremony.AuthContext{State: "g", Scope: "h"}
	_ = []ceremony.AuthContext{{TargetAcrLevel: "i"}}
	_ = &ceremony.AuthContext{"j", nil, "k", "l"}
	authContext.SetTargetAcrLevel("m")
	set := authContext.SetTargetAcrLevel
	(*ceremony.AuthContext).SetTargetAcrLevel(authContext, "n")
	_, _, _ = p, q, set
}
`)
	writeRequestFieldFixture(t, root, "authserver/internal/issuance/code_issuer.go", `package issuance

import "github.com/leodip/goiabada/authserver/internal/ceremony"

var restarts int

func narrow(ac *ceremony.AuthContext) {
	ac.UILocales = nil
	restarts++
}

var fixed = ceremony.AuthContext{UILocales: []string{"en"}}
`)

	// Passed: every read production makes, including the slice returned by Store.UILocales and a
	// spread of it into a variadic call; writes to an attempt field by every form; a copy of the
	// whole value into a new variable; an empty and an attempt-only literal; the address of the
	// whole context; a same-named field on another type; and a request field copied out and then
	// written through, which is the rule's stated limit.
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/handler_auth_completed.go", `package handlers

import (
	"strings"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
)

type cookie struct {
	State     string
	UILocales []string
}

func withLocale(locales ...string) {}

func completed(store *ceremony.Store, ac *ceremony.AuthContext, c *cookie) string {
	withLocale(store.UILocales()...)
	withLocale(ac.UILocales...)
	locales := ac.UILocales
	_ = append([]string{}, ac.UILocales...)
	copy(locales, ac.UILocales)
	if ac.State == "" || len(ac.UILocales) > 0 {
		return strings.Join(ac.UILocales, " ")
	}
	ac.Scope = "openid"
	ac.Scope += " profile"
	p := &ac.Scope
	ac.SetScope(*p)
	saved := *ac
	var empty ceremony.AuthContext
	_ = ceremony.AuthContext{}
	_ = ceremony.AuthContext{Scope: "openid"}
	_ = &empty
	c.State = "cookie"
	c.UILocales[0] = "en"
	c.UILocales = append(c.UILocales, "en")
	locales[0] = "copied out"
	return saved.State
}
`)
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/handler_auth_issue_test.go", `package handlers

import "github.com/leodip/goiabada/authserver/internal/ceremony"

func fixture(ac *ceremony.AuthContext) {
	ac.State = "a test may build any context it needs"
}
`)

	walk, err := findRequestFieldWrites(root, requestFieldScope, requestFieldFixtureFields, requestFieldSetters, requestFieldWriter)
	require.NoError(t, err)
	assert.Equal(t, 5, walk.files, "the test file is not read, the other five are")
	assert.True(t, walk.authContextFound)
	assert.Empty(t, walk.undeclared)

	assert.ElementsMatch(t, []string{
		"authserver/internal/handlers/handler_auth_issue.go:10: assigns State",
		"authserver/internal/handlers/handler_auth_issue.go:11: applies += to State",
		"authserver/internal/handlers/handler_auth_issue.go:12: assigns State",
		"authserver/internal/handlers/handler_auth_issue.go:13: assigns UILocales",
		"authserver/internal/handlers/handler_auth_issue.go:14: assigns UILocales",
		"authserver/internal/handlers/handler_auth_issue.go:15: assigns a whole AuthContext",
		"authserver/internal/handlers/handler_auth_issue.go:16: assigns by range State",
		"authserver/internal/handlers/handler_auth_issue.go:18: takes the address of State",
		"authserver/internal/handlers/handler_auth_issue.go:19: takes the address of UILocales",
		"authserver/internal/handlers/handler_auth_issue.go:20: passes to copy UILocales",
		"authserver/internal/handlers/handler_auth_issue.go:21: passes to append UILocales",
		"authserver/internal/handlers/handler_auth_issue.go:22: passes to clear UILocales",
		"authserver/internal/handlers/handler_auth_issue.go:23: sets State in an AuthContext literal",
		"authserver/internal/handlers/handler_auth_issue.go:24: sets TargetAcrLevel in an AuthContext literal",
		"authserver/internal/handlers/handler_auth_issue.go:25: builds an AuthContext literal positionally",
		"authserver/internal/handlers/handler_auth_issue.go:26: calls SetTargetAcrLevel",
		"authserver/internal/handlers/handler_auth_issue.go:27: calls SetTargetAcrLevel",
		"authserver/internal/handlers/handler_auth_issue.go:28: calls SetTargetAcrLevel",
		"authserver/internal/issuance/code_issuer.go:8: assigns UILocales",
		"authserver/internal/issuance/code_issuer.go:12: sets UILocales in an AuthContext literal",
	}, requestFieldStrings(walk.found), "the finder matched the wrong set")
	assert.Empty(t, walk.unresolved)
}

// TestRequestFieldWrites_Finder_ReportsAnUntypedReceiver pins the unresolved half: a write to a
// request field's name, or a call of a setter's, on a receiver typed through a package the walk
// stubs is not judged either way.
func TestRequestFieldWrites_Finder_ReportsAnUntypedReceiver(t *testing.T) {
	root := t.TempDir()
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context.go", requestFieldCeremonyFixture)
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/handler_auth_issue.go", `package handlers

import "example.com/thirdparty/flow"

func issue(f *flow.Context) {
	f.State = "a"
	f.Other = "b"
	f.SetTargetAcrLevel("c")
	flow.State = "d"
}
`)

	walk, err := findRequestFieldWrites(root, requestFieldScope, requestFieldFixtureFields, requestFieldSetters, requestFieldWriter)
	require.NoError(t, err)
	assert.Empty(t, walk.found)
	assert.ElementsMatch(t, []string{
		"authserver/internal/handlers/handler_auth_issue.go:6: assigns State",
		"authserver/internal/handlers/handler_auth_issue.go:8: calls SetTargetAcrLevel",
	}, requestFieldStrings(walk.unresolved), "the finder judged the wrong receivers unresolvable")
}

// TestRequestFieldWrites_Guard_FailsOnAWrite is the third half. The cases above assert on what the
// finder returned; the lines that turn a finding into a failure are reached only by the real tree's
// case, which passes.
func TestRequestFieldWrites_Guard_FailsOnAWrite(t *testing.T) {
	root := t.TempDir()
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context.go", requestFieldCeremonyFixture)
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/handler_auth_completed.go", `package handlers

import "github.com/leodip/goiabada/authserver/internal/ceremony"

func completed(ac *ceremony.AuthContext, effective string) {
	ac.State = effective
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertRequestFieldsWrittenOnce(r, root, requestFieldScope, requestFieldFixtureFields, requestFieldSetters, requestFieldWriter)
	})

	require.True(t, report.Failed(), "a request field written outside HandleAuthorizeGet passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/handlers/handler_auth_completed.go:6: assigns State")
	assert.Contains(t, report.Text(), "outside HandleAuthorizeGet")
	assert.Contains(t, report.Text(), "#436")
}

// TestRequestFieldWrites_Guard_FailsOnAnUntypedReceiver is the same through the unresolved half: a
// write the walk cannot judge fails rather than passing on a guess.
func TestRequestFieldWrites_Guard_FailsOnAnUntypedReceiver(t *testing.T) {
	root := t.TempDir()
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context.go", requestFieldCeremonyFixture)
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/handler_auth_issue.go", `package handlers

import "example.com/thirdparty/flow"

func issue(f *flow.Context) {
	f.UILocales = nil
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertRequestFieldsWrittenOnce(r, root, requestFieldScope, requestFieldFixtureFields, requestFieldSetters, requestFieldWriter)
	})

	require.True(t, report.Failed(), "a write on an unresolvable receiver passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/handlers/handler_auth_issue.go:6: assigns UILocales")
	assert.Contains(t, report.Text(), "whose type this walk cannot resolve")
}

// TestRequestFieldWrites_Guard_PassesTheWriterAndTheReads is the other direction: the writer writing
// every field by every form, and the reads and attempt-field writes everywhere else.
func TestRequestFieldWrites_Guard_PassesTheWriterAndTheReads(t *testing.T) {
	root := t.TempDir()
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context.go", requestFieldCeremonyFixture)
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/handler_authorize.go", requestFieldAuthorizeFixture)
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/handler_auth_completed.go", `package handlers

import "github.com/leodip/goiabada/authserver/internal/ceremony"

func completed(store *ceremony.Store, ac *ceremony.AuthContext) []string {
	ac.SetScope(ac.State)
	return append(store.UILocales(), ac.UILocales...)
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertRequestFieldsWrittenOnce(r, root, requestFieldScope, requestFieldFixtureFields, requestFieldSetters, requestFieldWriter)
	})

	assert.False(t, report.Failed(), "the writer or a read failed the guard: %s", report.Text())
}

// TestRequestFieldWrites_Guard_IsFatalOnAnEmptyRead pins the seam: a walk that read nothing is a
// failure, not a clean pass.
func TestRequestFieldWrites_Guard_IsFatalOnAnEmptyRead(t *testing.T) {
	root := t.TempDir()
	writeRequestFieldFixture(t, root, "authserver/README.md", "no Go here\n")
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context_test.go", "package ceremony\n")

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertRequestFieldsWrittenOnce(r, root, requestFieldScope, requestFieldFixtureFields, requestFieldSetters, requestFieldWriter)
	})

	require.True(t, report.Stopped, "an empty read must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "read no production Go files under authserver")
}

// TestRequestFieldWrites_Guard_IsFatalWithoutAnAuthContext is the same seam one step on: files were
// read but the type every match is made against was not among them, so every write would pass.
func TestRequestFieldWrites_Guard_IsFatalWithoutAnAuthContext(t *testing.T) {
	root := t.TempDir()
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/store.go", "package ceremony\n\ntype Store struct{}\n")
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/handler_auth_issue.go", `package handlers

type AuthContext struct{ State string }

func issue(ac *AuthContext) {
	ac.State = "a"
}
`)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertRequestFieldsWrittenOnce(r, root, requestFieldScope, requestFieldFixtureFields, requestFieldSetters, requestFieldWriter)
	})

	require.True(t, report.Stopped, "a walk that never found AuthContext must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "found no AuthContext type")
}

// TestRequestFieldWrites_Guard_IsFatalOnAnUndeclaredName pins the last seam: a listed field or setter
// that AuthContext no longer declares matches nothing, so the rule would pass every write to what
// replaced it.
func TestRequestFieldWrites_Guard_IsFatalOnAnUndeclaredName(t *testing.T) {
	root := t.TempDir()
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context.go", requestFieldCeremonyFixture)

	report := testutil.RunGuard(func(r testutil.Reporter) {
		assertRequestFieldsWrittenOnce(r, root, requestFieldScope,
			append(slices.Clone(requestFieldFixtureFields), "Nonce"), []string{"SetTargetAcrLevel", "SetNonce"}, requestFieldWriter)
	})

	require.True(t, report.Stopped, "an undeclared name must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "AuthContext declares no field Nonce, method SetNonce")
}

// writeRequestFieldFixture writes one file into a fixture tree, creating its directories.
func writeRequestFieldFixture(t *testing.T, root, rel, src string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(src), 0o644))
}
