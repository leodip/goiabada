//go:build !race

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
// write to one to authflow.Authorization.Run, the operation that accepts the request, closures
// inside it included, and holds the setters that write one to being called from there too.
//
// Fields and methods are resolved as go/types objects, so a write is caught whatever the variable
// holding the context is called, through a pointer, a promoted field or a method expression. What it
// does not see: it follows fields, not data flow. UILocales is the one request field of a reference
// type, and a copy of it taken into a local, or passed to a callee, shares its backing array, so a
// write through that copy reaches the context unseen. Every other request field is a string.
//
// It reads the auth server's module type-checked through core/pkgload and nothing else: no
// database, and no git of its own. The go command the loader runs reaches the network only to
// download a dependency missing from the module cache, as any build of the module would: from a
// module proxy, or from the dependency's own repository through git or whichever version-control
// tool hosts it, where GOPROXY, GOPRIVATE or GONOPROXY sends the go command there.

import (
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/pkgload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requestFieldScope is the tree the rule covers, relative to the source root, forward slashes: the
// auth server's module. AuthContext is internal to the auth server, so no other module can name it.
const requestFieldScope = "authserver"

// requestFieldModuleParent is what a directory under the source root is prefixed with to make its
// import path.
const requestFieldModuleParent = "github.com/leodip/goiabada/"

const (
	requestFieldCeremonyPath = requestFieldModuleParent + "authserver/internal/ceremony"
	requestFieldAuthflowPath = requestFieldModuleParent + "authserver/internal/authflow"
)

// requestFieldSetters are the AuthContext methods that write a request field. A call to one is a
// write, refused outside the writer like an assignment, and its own body is where that write
// happens, so the body is exempt. A method writing a request field that is not listed here is
// therefore refused for the write in its body.
var requestFieldSetters = []string{"SetTargetACRLevel", "ParkDeferredError"}

// requestFieldWriter names the one function whose body may write a request field: the operation
// that accepts the authorization request and creates its ceremony. Function literals inside it are
// inside it.
var requestFieldWriter = requestFieldFunc{pkg: requestFieldAuthflowPath, recv: "Authorization", name: "Run"}

// requestFieldFunc is a function or method named by its package's import path, its receiver's type
// name (empty for a function) and its own.
type requestFieldFunc struct {
	pkg, recv, name string
}

// String is the function as a reader names it: Recv.Name for a method, Name for a function.
func (f requestFieldFunc) String() string {
	if f.recv == "" {
		return f.name
	}
	return f.recv + "." + f.name
}

// requestFieldWrite is one write the rule refuses.
type requestFieldWrite struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
	what string
}

// requestFieldWalk is what one walk found. The last three fields are how the reporting half tells
// "nothing to report" from "nothing was read": a walk that read no file, that never found
// AuthContext, or that was handed a field or setter AuthContext does not declare has checked nothing
// it was asked to check.
type requestFieldWalk struct {
	found            []requestFieldWrite
	files            int
	authContextFound bool
	undeclared       []string
}

// findRequestFieldWrites reads the module at root/scope and reports each write, in a production
// file, to a listed request field of ceremony.AuthContext outside the writer. The forms it refuses:
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
// The module is read through pkgload as every release build selects its files, and as the test
// machine's default build does, and what they find is merged: a write in a file only Windows
// compiles is shipped all the same, and one in a development-only file runs in the development
// server (#420). A file only a race build or a custom tag selects is read by none of them. Each
// build is its own type-check, so the rule is resolved against each build's AuthContext. A package
// that does not load or type-check is an error naming it, since a write in it would go unseen.
func findRequestFieldWrites(
	root, scope string, fields, setters []string, writer requestFieldFunc,
) (requestFieldWalk, error) {
	var walk requestFieldWalk
	modRoot := filepath.Join(root, filepath.FromSlash(scope))

	// The first load error in build order is the one returned, and a build that selects no package of
	// the module adds nothing.
	loaded, err := pkgload.LoadBuilds(append(pkgload.ReleaseBuilds(), pkgload.Build{}), modRoot)
	if err != nil {
		return requestFieldWalk{}, err
	}

	readFiles := map[string]bool{}
	// seen holds each finding's physical position; a file several builds select is read once per build.
	seen := map[token.Position]bool{}
	// declared holds each listed name some build's AuthContext declares; a name no build declares
	// guards nothing.
	declared := map[string]bool{}
	for _, pkgs := range loaded {
		var rule *requestFieldRule
		for _, p := range pkgs {
			if p.PkgPath != requestFieldCeremonyPath {
				continue
			}
			if typeName, ok := p.Types.Scope().Lookup("AuthContext").(*types.TypeName); ok {
				if named, isNamed := typeName.Type().(*types.Named); isNamed {
					rule = newRequestFieldRule(named, fields, setters, writer, declared)
				}
			}
		}
		for _, p := range pkgs {
			for _, file := range p.Syntax {
				readFiles[p.Fset.File(file.Pos()).Name()] = true
				if rule == nil {
					continue
				}
				for _, w := range rule.check(file, p.PkgPath, p.TypesInfo) {
					// The physical position, not one a //line directive maps: two files that map a write to
					// the same template line are two writes, and the line reported is the file's own. A
					// file cgo generated is reported as the one it came from.
					at := pkgload.Position(p, w.pos)
					if seen[at] {
						continue
					}
					seen[at] = true
					rel, rErr := filepath.Rel(root, at.Filename)
					if rErr != nil {
						return requestFieldWalk{}, rErr
					}
					walk.found = append(walk.found, requestFieldWrite{file: filepath.ToSlash(rel), line: at.Line, what: w.what})
				}
			}
		}
		walk.authContextFound = walk.authContextFound || rule != nil
	}
	walk.files = len(readFiles)
	if walk.authContextFound {
		for _, name := range fields {
			if !declared["field "+name] {
				walk.undeclared = append(walk.undeclared, "field "+name)
			}
		}
		for _, name := range setters {
			if !declared["method "+name] {
				walk.undeclared = append(walk.undeclared, "method "+name)
			}
		}
	}
	return walk, nil
}

// requestFieldRule is the rule with every listed name resolved to the object one build's checker
// made for it, so a match is object identity and never a spelling.
type requestFieldRule struct {
	authContext *types.Named
	setterNames map[string]bool
	fields      map[*types.Var]string
	setters     map[*types.Func]string
	writer      requestFieldFunc
}

// newRequestFieldRule finds each listed field and setter on one build's AuthContext, and records in
// declared, as "field Name" or "method Name", each one it declares.
func newRequestFieldRule(
	named *types.Named, fields, setters []string, writer requestFieldFunc, declared map[string]bool,
) *requestFieldRule {
	rule := &requestFieldRule{
		authContext: named,
		setterNames: map[string]bool{},
		fields:      map[*types.Var]string{},
		setters:     map[*types.Func]string{},
		writer:      writer,
	}
	for _, name := range setters {
		rule.setterNames[name] = true
	}
	st, _ := named.Underlying().(*types.Struct)
	for _, name := range fields {
		for i := 0; st != nil && i < st.NumFields(); i++ {
			if st.Field(i).Name() == name {
				rule.fields[st.Field(i)] = name
				declared["field "+name] = true
			}
		}
	}
	for _, name := range setters {
		for i := range named.NumMethods() {
			if named.Method(i).Name() == name {
				rule.setters[named.Method(i)] = name
				declared["method "+name] = true
			}
		}
	}
	return rule
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

// requestFieldSite is one write within a file, before its position is made relative.
type requestFieldSite struct {
	pos  token.Pos
	what string
}

// check applies the rule to one type-checked file, skipping the exempt declarations whole.
func (rule *requestFieldRule) check(file *ast.File, pkgPath string, info *types.Info) (found []requestFieldSite) {
	at := func(pos token.Pos, what string) requestFieldSite {
		return requestFieldSite{pos: pos, what: what}
	}

	// target judges an expression something writes through: a request field, or an element or a
	// slice of one, is a finding.
	target := func(expr ast.Expr, verb string) {
		sel, ok := requestFieldRoot(expr).(*ast.SelectorExpr)
		if !ok {
			return
		}
		if v, isVar := info.Uses[sel.Sel].(*types.Var); isVar {
			if name, isRequest := rule.fields[v]; isRequest {
				found = append(found, at(expr.Pos(), verb+" "+name))
			}
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
				}
			}
			return true
		})
	}
	return found
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

// TestRequestFields_WrittenOnlyAtAuthorize holds the real tree to the rule, with the request fields
// the classification test names.
func TestRequestFields_WrittenOnlyAtAuthorize(t *testing.T) {
	assertRequestFieldsWrittenOnce(t, guard.SourceRoot(t), requestFieldScope, requestFields, requestFieldSetters, requestFieldWriter)
}

// assertRequestFieldsWrittenOnce is the reporting half, taking the root, the scope and the lists as
// parameters and failing through a guard.Reporter so a rule test can drive it against a fixture
// tree.
func assertRequestFieldsWrittenOnce(r guard.Reporter, root, scope string, fields, setters []string, writer requestFieldFunc) {
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
			len(walk.found), scope, writer, requestFieldLines(walk.found), writer)
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
var requestFieldFixtureFields = []string{"State", "UILocales", "TargetACRLevel"}

// requestFieldCeremonyFixture is the ceremony package in a fixture tree: AuthContext with the fixture
// request fields and one attempt field, the setter, and the reads production makes.
const requestFieldCeremonyFixture = `package ceremony

import "encoding/json"

type AuthContext struct {
	State          string
	UILocales      []string
	TargetACRLevel string
	Scope          string
}

func (ac *AuthContext) SetTargetACRLevel(level string) {
	ac.TargetACRLevel = level
}

func (ac *AuthContext) ParkDeferredError(code, description string) {
	ac.State = code + description
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
const requestFieldAuthorizeFixture = `package authflow

import "github.com/leodip/goiabada/authserver/internal/ceremony"

type Authorization struct{}

func (o *Authorization) Run(state string) func() *ceremony.AuthContext {
	ac := &ceremony.AuthContext{State: state}
	ac.State += "-suffix"
	ac.UILocales = append(ac.UILocales, "en")
	return func() *ceremony.AuthContext {
		ac.UILocales[0] = "pt-BR"
		copy(ac.UILocales, []string{"en"})
		p := &ac.State
		*p = "x"
		*ac = ceremony.AuthContext{"s", nil, "t", "u"}
		ac.SetTargetACRLevel("urn:goiabada:level1")
		ac.ParkDeferredError("invalid_request", "parked")
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
	writeRequestFieldModule(t, root)
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context.go", requestFieldCeremonyFixture)
	writeRequestFieldFixture(t, root, "authserver/internal/authflow/authorization.go", requestFieldAuthorizeFixture)

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
	_ = []ceremony.AuthContext{{TargetACRLevel: "i"}}
	_ = &ceremony.AuthContext{"j", nil, "k", "l"}
	authContext.SetTargetACRLevel("m")
	set := authContext.SetTargetACRLevel
	(*ceremony.AuthContext).SetTargetACRLevel(authContext, "n")
	authContext.ParkDeferredError("o", "p")
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
	// Refused too: a method of the writer's name on another receiver, and a function of that name,
	// in the writer's own package. The writer is the one method, not its name.
	writeRequestFieldFixture(t, root, "authserver/internal/authflow/silent_authentication.go", `package authflow

import "github.com/leodip/goiabada/authserver/internal/ceremony"

type SilentAuthentication struct{}

func (o *SilentAuthentication) Run(ac *ceremony.AuthContext) {
	ac.State = "a method named Run on another type"
}

func Run(ac *ceremony.AuthContext) {
	ac.State = "a function named Run"
}
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
	assert.Equal(t, 6, walk.files, "the test file is not read, the other six are")
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
		"authserver/internal/handlers/handler_auth_issue.go:24: sets TargetACRLevel in an AuthContext literal",
		"authserver/internal/handlers/handler_auth_issue.go:25: builds an AuthContext literal positionally",
		"authserver/internal/handlers/handler_auth_issue.go:26: calls SetTargetACRLevel",
		"authserver/internal/handlers/handler_auth_issue.go:27: calls SetTargetACRLevel",
		"authserver/internal/handlers/handler_auth_issue.go:28: calls SetTargetACRLevel",
		"authserver/internal/handlers/handler_auth_issue.go:29: calls ParkDeferredError",
		"authserver/internal/authflow/silent_authentication.go:8: assigns State",
		"authserver/internal/authflow/silent_authentication.go:12: assigns State",
		"authserver/internal/issuance/code_issuer.go:8: assigns UILocales",
		"authserver/internal/issuance/code_issuer.go:12: sets UILocales in an AuthContext literal",
	}, requestFieldStrings(walk.found), "the finder matched the wrong set")
}

// TestRequestFieldWrites_Guard_FailsOnAWrite is the third half. The cases above assert on what the
// finder returned; the lines that turn a finding into a failure are reached only by the real tree's
// case, which passes.
func TestRequestFieldWrites_Guard_FailsOnAWrite(t *testing.T) {
	root := t.TempDir()
	writeRequestFieldModule(t, root)
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context.go", requestFieldCeremonyFixture)
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/handler_auth_completed.go", `package handlers

import "github.com/leodip/goiabada/authserver/internal/ceremony"

func completed(ac *ceremony.AuthContext, effective string) {
	ac.State = effective
}
`)

	report := guard.Run(func(r guard.Reporter) {
		assertRequestFieldsWrittenOnce(r, root, requestFieldScope, requestFieldFixtureFields, requestFieldSetters, requestFieldWriter)
	})

	require.True(t, report.Failed(), "a request field written outside Authorization.Run passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "authserver/internal/handlers/handler_auth_completed.go:6: assigns State")
	assert.Contains(t, report.Text(), "outside Authorization.Run")
	assert.Contains(t, report.Text(), "#436")
}

// TestRequestFieldWrites_Guard_PassesTheWriterAndTheReads is the other direction: the writer writing
// every field by every form, and the reads and attempt-field writes everywhere else.
func TestRequestFieldWrites_Guard_PassesTheWriterAndTheReads(t *testing.T) {
	root := t.TempDir()
	writeRequestFieldModule(t, root)
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context.go", requestFieldCeremonyFixture)
	writeRequestFieldFixture(t, root, "authserver/internal/authflow/authorization.go", requestFieldAuthorizeFixture)
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/handler_auth_completed.go", `package handlers

import "github.com/leodip/goiabada/authserver/internal/ceremony"

func completed(store *ceremony.Store, ac *ceremony.AuthContext) []string {
	ac.SetScope(ac.State)
	return append(store.UILocales(), ac.UILocales...)
}
`)

	report := guard.Run(func(r guard.Reporter) {
		assertRequestFieldsWrittenOnce(r, root, requestFieldScope, requestFieldFixtureFields, requestFieldSetters, requestFieldWriter)
	})

	assert.False(t, report.Failed(), "the writer or a read failed the guard: %s", report.Text())
}

// A write in a file only one of the builds selects is still shipped, or runs in the development
// server, so the walk reads every release build and the default build and merges what they find
// (#420 decision 11).
func TestRequestFieldWrites_Finder_ReadsAFileOnlyOneBuildSelects(t *testing.T) {
	const write = `
package handlers

import "github.com/leodip/goiabada/authserver/internal/ceremony"

func completed(ac *ceremony.AuthContext, effective string) {
	ac.State = effective
}
`
	for _, tc := range []struct{ name, constraint string }{
		{"another platform's release build", "//go:build windows && production\n"},
		{"the production tag", "//go:build production\n"},
		{"the default build only", "//go:build !production\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeRequestFieldModule(t, root)
			writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context.go", requestFieldCeremonyFixture)
			writeRequestFieldFixture(t, root, "authserver/internal/handlers/handler_auth_completed.go", tc.constraint+write)

			walk, err := findRequestFieldWrites(root, requestFieldScope, requestFieldFixtureFields, requestFieldSetters, requestFieldWriter)
			require.NoError(t, err)

			assert.Equal(t, []string{"authserver/internal/handlers/handler_auth_completed.go:8: assigns State"},
				requestFieldStrings(walk.found), "found once however many builds select the file")
			assert.Equal(t, 2, walk.files, "the ceremony fixture and the handler, each counted once")
		})
	}
}

// Two files of different builds whose writes a //line directive maps to the same template line,
// at the same offset, are two writes, each reported at its own file's line.
func TestRequestFieldWrites_Finder_KeepsTwoFilesThatMapToTheSameLine(t *testing.T) {
	const generated = `package handlers

import "github.com/leodip/goiabada/authserver/internal/ceremony"

func completed(ac *ceremony.AuthContext, effective string) {
//line handler.tmpl:100
	ac.State = effective
}
`
	root := t.TempDir()
	writeRequestFieldModule(t, root)
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context.go", requestFieldCeremonyFixture)
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/completed_amd64.go", generated)
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/completed_arm64.go", generated)

	walk, err := findRequestFieldWrites(root, requestFieldScope, requestFieldFixtureFields, requestFieldSetters, requestFieldWriter)
	require.NoError(t, err)

	// Which of the two a build reads first depends on the test machine's architecture.
	assert.ElementsMatch(t, []string{
		"authserver/internal/handlers/completed_amd64.go:7: assigns State",
		"authserver/internal/handlers/completed_arm64.go:7: assigns State",
	}, requestFieldStrings(walk.found))
}

// A file that imports "C" is compiled from the file cmd/cgo generates from it, in the build cache, and
// a write in it is reported at the original file's line.
func TestRequestFieldWrites_Finder_ReportsAFileThatImportsCAtItsOwnLine(t *testing.T) {
	cgo, err := exec.Command("go", "env", "CGO_ENABLED").Output()
	require.NoError(t, err)
	if strings.TrimSpace(string(cgo)) != "1" {
		t.Skip("the default build has cgo off here, as it does without a C compiler")
	}
	root := t.TempDir()
	writeRequestFieldModule(t, root)
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context.go", requestFieldCeremonyFixture)
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/completed.go", `package handlers

/* static int one(void) { return 1; } */
import "C"

import "github.com/leodip/goiabada/authserver/internal/ceremony"

func completed(ac *ceremony.AuthContext, effective string) int {
	ac.State = effective
	return int(C.one())
}
`)

	walk, err := findRequestFieldWrites(root, requestFieldScope, requestFieldFixtureFields, requestFieldSetters, requestFieldWriter)
	require.NoError(t, err)

	assert.Equal(t, []string{"authserver/internal/handlers/completed.go:9: assigns State"}, requestFieldStrings(walk.found))
}

// A package that does not compile cannot be read whole, and a write in it would pass unseen, so the
// walk stops and names it (#420 decision 3).
func TestRequestFieldWrites_Guard_IsFatalOnAPackageThatDoesNotCompile(t *testing.T) {
	root := t.TempDir()
	writeRequestFieldModule(t, root)
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context.go", requestFieldCeremonyFixture)
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/handler_auth_completed.go", `package handlers

import "github.com/leodip/goiabada/authserver/internal/ceremony"

func completed(ac *ceremony.AuthContext) int {
	ac.State = "a"
	return "not an int"
}
`)

	report := guard.Run(func(r guard.Reporter) {
		assertRequestFieldsWrittenOnce(r, root, requestFieldScope, requestFieldFixtureFields, requestFieldSetters, requestFieldWriter)
	})

	require.True(t, report.Stopped, "a package that does not compile must be fatal rather than read in part")
	assert.Contains(t, report.Fatal, "github.com/leodip/goiabada/authserver/internal/handlers")
	assert.Contains(t, report.Fatal, "does not load or type-check")
}

// TestRequestFieldWrites_Guard_IsFatalOnAnEmptyRead pins the seam: a walk that read nothing is a
// failure, not a clean pass.
func TestRequestFieldWrites_Guard_IsFatalOnAnEmptyRead(t *testing.T) {
	root := t.TempDir()
	writeRequestFieldModule(t, root)
	writeRequestFieldFixture(t, root, "authserver/README.md", "no Go here\n")
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context_test.go", "package ceremony\n")

	report := guard.Run(func(r guard.Reporter) {
		assertRequestFieldsWrittenOnce(r, root, requestFieldScope, requestFieldFixtureFields, requestFieldSetters, requestFieldWriter)
	})

	require.True(t, report.Stopped, "an empty read must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "read no production Go files under authserver")
}

// TestRequestFieldWrites_Guard_IsFatalWithoutAnAuthContext is the same seam one step on: files were
// read but the type every match is made against was not among them, so every write would pass.
func TestRequestFieldWrites_Guard_IsFatalWithoutAnAuthContext(t *testing.T) {
	root := t.TempDir()
	writeRequestFieldModule(t, root)
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/store.go", "package ceremony\n\ntype Store struct{}\n")
	writeRequestFieldFixture(t, root, "authserver/internal/handlers/handler_auth_issue.go", `package handlers

type AuthContext struct{ State string }

func issue(ac *AuthContext) {
	ac.State = "a"
}
`)

	report := guard.Run(func(r guard.Reporter) {
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
	writeRequestFieldModule(t, root)
	writeRequestFieldFixture(t, root, "authserver/internal/ceremony/auth_context.go", requestFieldCeremonyFixture)

	report := guard.Run(func(r guard.Reporter) {
		assertRequestFieldsWrittenOnce(r, root, requestFieldScope,
			append(slices.Clone(requestFieldFixtureFields), "Nonce"), []string{"SetTargetACRLevel", "SetNonce"}, requestFieldWriter)
	})

	require.True(t, report.Stopped, "an undeclared name must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "AuthContext declares no field Nonce, method SetNonce")
}

// writeRequestFieldModule writes the auth server's module file into a fixture tree and makes the
// tree loadable, so a case adds only the packages it is about.
func writeRequestFieldModule(t *testing.T, root string) {
	t.Helper()
	writeRequestFieldFixture(t, root, "authserver/go.mod", "module github.com/leodip/goiabada/authserver\n")
	require.NoError(t, pkgload.MakeLoadable(root))
}

// writeRequestFieldFixture writes one file into a fixture tree, creating its directories.
func writeRequestFieldFixture(t *testing.T, root, rel, src string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(src), 0o644))
}
