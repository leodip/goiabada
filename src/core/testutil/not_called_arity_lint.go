package testutil

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
)

// testifyMockImportPath is testify's mock package, whose Mock every generated double embeds and
// whose AssertNotCalled is the assertion this guard holds.
const testifyMockImportPath = "github.com/stretchr/testify/mock"

// notCalledSelector is the method name the walk matches on. It is matched by spelling rather than
// by the object it binds to, because the receiver is what this guard resolves and the selector
// itself resolves to nothing in an error-tolerant check: testify is not read, so mock.Mock is an
// invalid embedded field and every promoted method of it is undefined. The spelling costs nothing
// here -- a method of this name on something that is not a mock cannot be resolved either, and is
// reported rather than passed over.
const notCalledSelector = "AssertNotCalled"

// notCalledWatchedImports is the one path this rule resolves a struct's embedded field against, so
// that "the field is testify's Mock" is answered by the import and not by the spelling mock.Mock,
// which any package called mock in this tree would also produce.
var notCalledWatchedImports = watchedImports{
	testifyMockImportPath: {name: "mock"},
}

// AssertNotCalledArity refuses a testify AssertNotCalled whose matcher count differs from the
// number of parameters the named method takes on the mock the assertion is made against.
//
// testify matches a recorded call on the method name AND the whole argument list:
// Arguments.Diff compares position by position and counts a length difference as a difference
// like any other. So AssertNotCalled(t, "Log") against a Log that takes three parameters asks
// whether a three-argument call equals a zero-argument one, the answer is no whatever the subject
// did, and the assertion passes. The compiler sees a variadic call and says nothing. The tier
// stays green. The test reads as a guarantee and is not one.
//
// This is verified rather than suspected. While landing #386 two such sites were given their real
// arity, and one failed at once: handler_auth_issue_test.go asserted GetUserById was not called on
// the empty-id_token_hint path, while the handler has read the user unconditionally since #241's
// live permission check. That assertion had been false since #241 landed and had never once said
// so (#421).
//
// The count it holds them to is the mock's own method, not the interface's, because the mock's
// method is what records the call: mockery generates a body that passes exactly its own parameters
// to Mock.Called, so the recorded argument list is that method's parameter list and nothing else.
// The two agree by construction today -- a generated double satisfies the interface it was
// generated from -- and when they ever disagree, the recorded list is the one testify compares
// against.
//
// Four shapes are reported rather than passed over, because each one is an assertion that cannot
// be shown to hold and a guard that skips what it cannot answer is a guard that narrows itself:
//
//   - a method named through anything but a string literal, which is an arity no walk can read.
//     The one such site in this tree was a helper looping over names its callers passed, and it
//     was vacuous at every one of them;
//   - a receiver whose type does not resolve, which means the walk is guessing about what was
//     asserted;
//   - a name the resolved type declares no method for, which is an assertion that can never match
//     anything and so passes unconditionally -- the same defect as a wrong count, reached by a
//     typo instead;
//   - a variadic method, whose recorded length testify's own matching rules decide rather than the
//     signature. There is none in this tree, which is what makes refusing one free.
//
// It does not widen to AssertCalled, whose failure mode is the opposite and is loud: an arity
// mismatch there makes the assertion fail on every run, so no such site can survive a green tier.
// Nor to On(...), where a stub that matches nothing makes the call panic. AssertNotCalled is the
// only one of the three that fails silently, which is the whole reason it needs a guard (#421).
//
// Passing dirs restricts the walk to those subdirectories of the source root, forward slashes and
// relative to it, exactly as AssertSlogConvention's and AssertNoDeadInterfaces' parameter does.
// Scope and shape otherwise follow AssertNoDeadInterfaces, which carries the reasoning for
// type-checking in error-tolerant mode against an importer that reads almost nothing.
func AssertNotCalledArity(t *testing.T, dirs ...string) {
	t.Helper()

	assertNotCalledArity(t, SourceRoot(t), dirs)
}

// assertNotCalledArity is the reporting half, taking the root as a parameter and failing through a
// Reporter so a rule test can drive it against a fixture tree. See Reporter in guard.go.
func assertNotCalledArity(r Reporter, root string, dirs []string) {
	r.Helper()

	findings, blocked, sites, err := findNotCalledArity(root, dirs)
	if err != nil {
		r.Fatalf("walking %s: %v", root, err)
	}
	// A walk that reached no assertion passes vacuously. That is the one way this guard stops
	// guarding with nothing going red, and it is reachable two ways: a dirs argument that no
	// longer names any Go source, and a tree that has stopped writing the assertion altogether.
	// The second wants the guard deleted rather than left standing over nothing.
	if sites == 0 {
		r.Fatalf("walked no %s call under %s (dirs: %s)",
			notCalledSelector, root, strings.Join(dirs, ", "))
	}

	// A shape this walk cannot resolve is reported rather than skipped: a false failure gets
	// investigated, a false pass is a guard that has quietly stopped guarding.
	for _, b := range blocked {
		r.Errorf("%s:%d: %s", b.file, b.line, b.why)
	}

	if len(findings) == 0 {
		return
	}

	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		lines = append(lines, f.file+":"+strconv.Itoa(f.line)+": "+
			notCalledSelector+"(t, \""+f.method+"\", ...) passes "+strconv.Itoa(f.given)+
			" matcher(s) to "+f.recv+"."+f.method+", which takes "+strconv.Itoa(f.want))
	}
	r.Errorf("%d %s assertion(s) that can never fail:\n\t%s\n\n"+
		"testify matches a recorded call on the method name and the whole argument list, so an "+
		"assertion carrying the wrong number of matchers compares lists that can never be equal "+
		"and passes whatever the subject did. Give each one a matcher per parameter -- "+
		"mock.Anything where the value does not matter -- and then read what the assertion says "+
		"once it is live, because a site that has been vacuous for months may be asserting "+
		"something the handler stopped doing long ago (#421).",
		len(findings), notCalledSelector, strings.Join(lines, "\n\t"))
}

// notCalledFinding is one assertion whose matcher count does not match the method it names.
type notCalledFinding struct {
	// file is relative to the source root, forward slashes.
	file string
	line int
	// recv is the receiver's type as the reader wrote it, qualified by package name.
	recv   string
	method string
	// given is the matcher count at the site, want the method's parameter count.
	given int
	want  int
}

// findNotCalledArity type-checks every package under root that writes the assertion and applies
// the rule to each site. It returns the findings, the shapes it could not resolve, and the number
// of assertions it reached.
func findNotCalledArity(root string, dirs []string) ([]notCalledFinding, []unresolvedShape, int, error) {
	imp, err := newMockPackages(root)
	if err != nil {
		return nil, nil, 0, err
	}

	targets, err := dirsWritingNotCalled(root, dirs)
	if err != nil {
		return nil, nil, 0, err
	}

	var findings []notCalledFinding
	var blocked []unresolvedShape
	sites := 0
	for _, dir := range targets {
		f, b, s, cErr := checkNotCalledIn(root, dir, imp)
		if cErr != nil {
			return nil, nil, sites, cErr
		}
		findings = append(findings, f...)
		blocked = append(blocked, b...)
		sites += s
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].file != findings[j].file {
			return findings[i].file < findings[j].file
		}
		return findings[i].line < findings[j].line
	})
	sort.Slice(blocked, func(i, j int) bool {
		if blocked[i].file != blocked[j].file {
			return blocked[i].file < blocked[j].file
		}
		return blocked[i].line < blocked[j].line
	})
	return findings, blocked, sites, nil
}

// dirsWritingNotCalled collects the directories holding at least one Go file that spells the
// assertion. Reading the text first is the sound pre-filter on type-checking, for the reason
// mentionsAny carries: a call site is spelled before it is resolved, so a directory whose files
// never carry the text cannot hold one, and the great majority of this repository is skipped
// without being checked.
func dirsWritingNotCalled(root string, dirs []string) ([]string, error) {
	starts := []string{root}
	if len(dirs) > 0 {
		starts = starts[:0]
		for _, dir := range dirs {
			starts = append(starts, filepath.Join(root, filepath.FromSlash(dir)))
		}
	}

	seen := map[string]bool{}
	var found []string
	for _, start := range starts {
		err := filepath.WalkDir(start, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if skippedDir(d.Name()) {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			dir := filepath.Dir(path)
			if seen[dir] {
				return nil
			}
			raw, rErr := os.ReadFile(path)
			if rErr != nil {
				return errs.Wrapf(rErr, "reading %s", path)
			}
			if !strings.Contains(string(raw), notCalledSelector) {
				return nil
			}
			seen[dir] = true
			found = append(found, dir)
			return nil
		})
		if err != nil {
			return nil, errs.Wrapf(err, "walking %s", start)
		}
	}
	sort.Strings(found)
	return found, nil
}

// checkNotCalledIn type-checks one directory and applies the rule to every assertion in it.
//
// The whole directory is checked, tests and production together and every file of it, because the
// question asked at each site is what the receiver's type is, and a receiver is almost always a
// local whose type comes from a constructor called somewhere else in the package -- or, in this
// tree, from a helper that builds a handler and hands its doubles back.
func checkNotCalledIn(root, dir string, imp *mockPackages) ([]notCalledFinding, []unresolvedShape, int, error) {
	modRoot, modPath, err := moduleFor(root, dir)
	if err != nil {
		return nil, nil, 0, err
	}
	pkgPath := modPath
	if rel, rErr := filepath.Rel(modRoot, dir); rErr == nil && rel != "." {
		pkgPath = modPath + "/" + filepath.ToSlash(rel)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, 0, errs.Wrapf(err, "reading %s", dir)
	}

	fset := token.NewFileSet()
	// Grouped by package clause, because a directory holds both foo and foo_test and go/types
	// checks one package at a time.
	byPackage := map[string][]*ast.File{}
	var packageOrder []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		file, pErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns, and reporting it
			// here would send the reader to the wrong place.
			continue
		}
		name := file.Name.Name
		if _, seen := byPackage[name]; !seen {
			packageOrder = append(packageOrder, name)
		}
		byPackage[name] = append(byPackage[name], file)
	}

	var findings []notCalledFinding
	var blocked []unresolvedShape
	sites := 0
	for _, name := range packageOrder {
		group := byPackage[name]
		checkPath := pkgPath
		if strings.HasSuffix(name, "_test") {
			checkPath = pkgPath + "_test"
		}

		info := &types.Info{
			Types: map[ast.Expr]types.TypeAndValue{},
			Defs:  map[*ast.Ident]types.Object{},
			Uses:  map[*ast.Ident]types.Object{},
		}
		conf := types.Config{
			Importer: imp,
			// Everything but the generated doubles is a stub, so most of what go/types has to say
			// about these files is that some package it never read has no such member. Collecting
			// the errors and discarding them is what keeps the checker running to the end; what
			// survives is what this guard asks for -- the type of the value the assertion was
			// made against, which comes from a constructor whose result type the checker did read.
			Error:                    func(error) {},
			DisableUnusedImportCheck: true,
		}
		// The returned error is the first one Error already saw. The package and the info are
		// filled in either way, which is the whole point of running in error-tolerant mode.
		pkg, _ := conf.Check(checkPath, fset, group, info)

		for _, file := range group {
			f, b, s := notCalledSitesIn(file, fset, info, pkg, root)
			findings = append(findings, f...)
			blocked = append(blocked, b...)
			sites += s
		}
	}

	return findings, blocked, sites, nil
}

// notCalledSitesIn applies the rule to every assertion in one checked file.
func notCalledSitesIn(
	file *ast.File, fset *token.FileSet, info *types.Info, pkg *types.Package, root string,
) ([]notCalledFinding, []unresolvedShape, int) {
	var findings []notCalledFinding
	var blocked []unresolvedShape
	sites := 0

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != notCalledSelector {
			return true
		}
		sites++

		position := fset.Position(call.Pos())
		rel := relativeTo(root, position.Filename)
		refuse := func(why string) {
			blocked = append(blocked, unresolvedShape{file: rel, line: position.Line, why: why})
		}

		if len(call.Args) < 2 {
			refuse(notCalledSelector + " names no method, so there is nothing to hold it to")
			return true
		}
		lit, ok := call.Args[1].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			refuse(notCalledSelector + " names its method through an expression rather than a " +
				"string literal, so no walk can read the arity it should carry; spell the name " +
				"at the site, or assert over the mock's recorded Calls, which match on the name " +
				"alone")
			return true
		}
		method, uErr := strconv.Unquote(lit.Value)
		if uErr != nil {
			refuse(notCalledSelector + " names its method through a string this walk cannot read")
			return true
		}

		recvType := typeOfReceiver(info, sel.X)
		if recvType == nil {
			refuse(notCalledSelector + "(t, \"" + method + "\", ...) is made against a value " +
				"whose type this walk cannot resolve, so the arity it should carry is unknowable")
			return true
		}

		obj, _, _ := types.LookupFieldOrMethod(recvType, true, pkg, method)
		fn, ok := obj.(*types.Func)
		if !ok {
			refuse(notCalledSelector + "(t, \"" + method + "\", ...) names a method " +
				typeName(recvType, pkg) + " does not declare, so it can never match a recorded " +
				"call and passes whatever the subject did")
			return true
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok {
			refuse(notCalledSelector + "(t, \"" + method + "\", ...) names something on " +
				typeName(recvType, pkg) + " that is not a method")
			return true
		}
		if sig.Variadic() {
			refuse(notCalledSelector + "(t, \"" + method + "\", ...) names a variadic method, " +
				"whose recorded argument list depends on what the double spreads into Called " +
				"rather than on its signature; assert over the mock's recorded Calls instead")
			return true
		}

		want := sig.Params().Len()
		given := len(call.Args) - 2
		if want != given {
			findings = append(findings, notCalledFinding{
				file:   rel,
				line:   position.Line,
				recv:   typeName(recvType, pkg),
				method: method,
				given:  given,
				want:   want,
			})
		}
		return true
	})

	return findings, blocked, sites
}

// typeOfReceiver gives the type of the value an assertion was made against, or nil when the check
// could not resolve it. An invalid type is nil here rather than a type, because "the checker gave
// up on this expression" and "this expression has a type" are the two answers that must not be
// confused: the first is a shape to report, the second is one to hold.
func typeOfReceiver(info *types.Info, expr ast.Expr) types.Type {
	typ := info.TypeOf(expr)
	if typ == nil || typ == types.Typ[types.Invalid] {
		return nil
	}
	if basic, ok := typ.(*types.Basic); ok && basic.Kind() == types.Invalid {
		return nil
	}
	return typ
}

// typeName renders a type the way the file that named it reads, qualified by package name rather
// than by import path, so a finding points at mocks_data.Database and not at the whole path.
func typeName(typ types.Type, pkg *types.Package) string {
	qualifier := func(p *types.Package) string {
		if pkg != nil && p == pkg {
			return ""
		}
		return p.Name()
	}
	return types.TypeString(typ, qualifier)
}

// repoModule is one module in this repository: where it is and what it is called.
type repoModule struct {
	// dir is absolute.
	dir string
	// path is the module line of its go.mod.
	path string
}

// mockPackages is the importer the rule type-checks against. Every path but one kind becomes an
// empty stub, exactly as AssertNoDeadInterfaces' importer does and for the same reason: identifier
// resolution is lexical and needs no import to be correct.
//
// The exception is a directory in this repository that declares a testify double, which is read
// from source. That is the one package whose contents this rule needs, because the arity it holds
// a site to is a method's parameter count, and a stub declares no methods. Reading only those
// keeps the walk to the twenty-odd generated files rather than the whole dependency graph, and
// their own imports -- context, database/sql, the model packages -- are stubbed in turn, which
// costs nothing: a parameter whose type did not resolve is still a parameter, and the count is
// what is being read.
type mockPackages struct {
	// modules is every module in the tree, longest path first, so a nested module wins over the
	// one above it.
	modules []repoModule
	stub    *stubPackages
	made    map[string]*types.Package
	// inflight breaks a cycle between two double-declaring packages by handing the second one a
	// stub. There is no such cycle in this tree; without the guard there would be no walk either.
	inflight map[string]bool
	fset     *token.FileSet
}

func newMockPackages(root string) (*mockPackages, error) {
	modules, err := repoModules(root)
	if err != nil {
		return nil, err
	}
	return &mockPackages{
		modules:  modules,
		stub:     newStubPackages(),
		made:     map[string]*types.Package{},
		inflight: map[string]bool{},
		fset:     token.NewFileSet(),
	}, nil
}

func (m *mockPackages) Import(path string) (*types.Package, error) {
	if made, ok := m.made[path]; ok {
		return made, nil
	}
	dir, ok := m.dirFor(path)
	if !ok || m.inflight[path] {
		return m.stub.Import(path)
	}
	files := parseDoubleDeclaringDir(m.fset, dir)
	if len(files) == 0 {
		return m.stub.Import(path)
	}

	m.inflight[path] = true
	conf := types.Config{
		Importer:                 m,
		Error:                    func(error) {},
		DisableUnusedImportCheck: true,
	}
	pkg, _ := conf.Check(path, m.fset, files, nil)
	delete(m.inflight, path)
	if pkg == nil {
		return m.stub.Import(path)
	}
	pkg.MarkComplete()
	m.made[path] = pkg
	return pkg, nil
}

// dirFor maps an import path to the directory declaring it, for a path inside this repository.
// The longest module path wins, so a module nested under another is not read as a package of it.
func (m *mockPackages) dirFor(path string) (string, bool) {
	for _, mod := range m.modules {
		if path == mod.path {
			return mod.dir, true
		}
		if rest, found := strings.CutPrefix(path, mod.path+"/"); found {
			return filepath.Join(mod.dir, filepath.FromSlash(rest)), true
		}
	}
	return "", false
}

// repoModules finds every module under root, reading each path from its own go.mod rather than
// hard-coding the four: a module renamed there is then a walk that stops resolving that module's
// doubles and starts reporting them, rather than one that silently answers with a stub.
func repoModules(root string) ([]repoModule, error) {
	var found []repoModule
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" {
			return nil
		}
		modPath, mErr := modulePath(path)
		if mErr != nil {
			return mErr
		}
		found = append(found, repoModule{dir: filepath.Dir(path), path: modPath})
		return nil
	})
	if err != nil {
		return nil, errs.Wrapf(err, "walking %s for modules", root)
	}
	sort.Slice(found, func(i, j int) bool {
		return len(found[i].path) > len(found[j].path)
	})
	return found, nil
}

// parseDoubleDeclaringDir parses a directory's non-test Go files and returns them only when one of
// them declares a struct embedding testify's Mock. Anything else is left to the stub importer, so
// the walk reads the packages whose method signatures it needs and no others.
//
// The embedded field is resolved through the file's imports rather than by the spelling mock.Mock,
// which is bindImports' whole reason for existing: a package of this tree named mock would
// otherwise be read as testify's.
func parseDoubleDeclaringDir(fset *token.FileSet, dir string) []*ast.File {
	entries, err := os.ReadDir(dir)
	if err != nil {
		// A path that names no directory is a package this walk does not have, which is what the
		// stub importer is for.
		return nil
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		if strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	var files []*ast.File
	declaresDouble := false
	clause := ""
	for _, name := range names {
		file, pErr := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if pErr != nil {
			continue
		}
		// One directory, one package clause for non-test files. A directory holding two is not
		// something the go tool builds, and checking the group would be checking a package that
		// does not exist.
		if clause == "" {
			clause = file.Name.Name
		} else if file.Name.Name != clause {
			return nil
		}
		files = append(files, file)
		if declaresTestifyDouble(file) {
			declaresDouble = true
		}
	}
	if !declaresDouble {
		return nil
	}
	return files
}

// declaresTestifyDouble reports whether a file declares a struct embedding testify's Mock, which
// is what every generated double in this tree is and the only shape whose methods this rule reads.
func declaresTestifyDouble(file *ast.File) bool {
	bound := bindImports(file, notCalledWatchedImports)
	if len(bound) == 0 {
		return false
	}

	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if found {
			return false
		}
		structType, ok := n.(*ast.StructType)
		if !ok || structType.Fields == nil {
			return true
		}
		for _, field := range structType.Fields.List {
			if len(field.Names) > 0 {
				continue
			}
			sel, ok := field.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Mock" {
				continue
			}
			base, ok := sel.X.(*ast.Ident)
			if !ok {
				continue
			}
			if bound[base.Name] == testifyMockImportPath {
				found = true
				return false
			}
		}
		return true
	})
	return found
}
