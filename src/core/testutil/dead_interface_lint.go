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

// AssertNoDeadInterfaces holds every interface declared under dirs to having at least one
// reference somewhere in its own module, production code or test.
//
// The defect it refuses shipped for months. adminconsole/internal/handlers/interfaces.go declared
// fourteen interfaces and nine of them had no consumer anywhere; four of the package's kernel
// imports existed only to spell their method signatures, and one of those nine was the only reason
// an entire package, adminconsole/internal/tcputils, was still in the tree. Nothing caught it:
// golangci-lint's unused reports nothing for an exported declaration, and the two settings that
// might have were measured on the unmodified tree and found zero of the nine (#333).
//
// Liveness here is object identity, never a matching spelling, and that distinction is the whole
// reason this is a type check rather than a grep. The census that grounded #333 got it wrong the
// first time in exactly that way: a bare-name search credited handlers.TCPConnectionTester with
// four references that in fact belonged to tcputils.TCPConnectionTester, a different type in a
// different package, and read a dead interface as live. Two more shapes fail the same way in the
// other direction. An unqualified name a local shadows -- EmailSender := 1 in a function body --
// is not a reference to the type, and neither is pkg.EmailSender at a site where a local value
// named pkg has shadowed the import. All three are resolved here by asking go/types which object
// an identifier actually binds to.
//
// What the search excludes is the interface's own declaration and nothing else -- the TypeSpec's
// name identifier, not the file it sits in. A file-level exclusion would report a live interface
// dead the moment a second declaration in the same file consumed it, by embedding it or naming it
// in a method signature, which is ordinary in a file whose whole job is declaring interfaces.
// Excluding just the declaration is free here: go/types records a defining identifier in Defs and
// never in Uses, so a scan of Uses cannot see it.
//
// Structural satisfaction deliberately does not count. A concrete type whose methods happen to
// line up with an interface nobody names is not a consumer of it; an interface nothing names is
// what "dead" means here, and the nine this guard was written for were all satisfied structurally
// by the concrete types the handlers actually used.
//
// Passing dirs restricts the declaring packages to those subdirectories of the source root,
// forward slashes and relative to it ("adminconsole/internal/handlers"). References are searched
// for across the whole module that owns each declaring directory, found by the nearest go.mod
// above it, because that is the largest scope that can hold one: an interface under internal/ is
// unreferenceable from outside its module, and this repository's four modules share a source root.
//
// ceiling: the search space is one module per declaring directory. An interface declared outside
// an internal/ tree could be referenced from a sibling module, and this walk would call it dead.
// Nothing in the tree is in that position today -- both call sites guard an internal/handlers
// package -- and widening the search to every module would cost the fourth-module scan on every
// run. Revisit when a caller names a directory outside internal/ (#333).
//
// Scope and shape follow AssertNoLegacyErrors and AssertGofmted, which carry the reasoning for
// walking the source root rather than the calling module.
func AssertNoDeadInterfaces(t *testing.T, dirs ...string) {
	t.Helper()

	root := SourceRoot(t)

	dead, blocked, files, err := findDeadInterfaces(root, dirs)
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	// A walk that reached no files passes vacuously, which is the one way a guard like this stops
	// guarding without anything going red.
	if files == 0 {
		t.Fatalf("walked no Go files under %s (dirs: %s)", root, strings.Join(dirs, ", "))
	}

	// A shape this walk cannot resolve is reported rather than skipped: a false failure gets
	// investigated, a false pass is a guard that has quietly stopped guarding.
	for _, b := range blocked {
		t.Errorf("%s:%d: %s", b.file, b.line, b.why)
	}

	if len(dead) == 0 {
		return
	}

	lines := make([]string, 0, len(dead))
	for _, d := range dead {
		lines = append(lines, d.file+":"+strconv.Itoa(d.line)+": "+d.pkg+"."+d.name)
	}
	t.Errorf("%d interface declaration(s) nothing in the module references:\n\t%s\n\n"+
		"Delete the declaration, along with any import that existed only to spell its method "+
		"signatures, or reference it from the code that was supposed to be consuming it. An "+
		"interface no code names abstracts nothing: it holds imports open, it reads to the next "+
		"person as a seam that exists, and the compiler cannot tell you it is gone (#333).",
		len(dead), strings.Join(lines, "\n\t"))
}

// deadInterface is one interface declaration with no reference, located.
type deadInterface struct {
	// pkg is the declaring package's import path.
	pkg string
	// file is relative to the source root, forward slashes.
	file string
	line int
	name string
}

// unresolvedShape is something the walk found and cannot answer for. It is reported as a finding
// because the alternative -- passing over it -- is a guard silently narrowing its own scope.
type unresolvedShape struct {
	file string
	line int
	why  string
}

// findDeadInterfaces collects every top-level interface declared under the named subdirectories of
// root, then searches each declaring package's whole module for a reference that binds to it. It
// returns the unreferenced declarations, the shapes it could not resolve, and the number of Go
// files it parsed in the declaring directories.
func findDeadInterfaces(root string, dirs []string) ([]deadInterface, []unresolvedShape, int, error) {
	declDirs, err := declaringDirs(root, dirs)
	if err != nil {
		return nil, nil, 0, err
	}

	// Group the declaring directories by the module that owns each, so one module is scanned once
	// however many of its packages are being guarded.
	byModule := map[string]*moduleTarget{}
	var order []string
	for _, dir := range declDirs {
		modRoot, modPath, mErr := moduleFor(root, dir)
		if mErr != nil {
			return nil, nil, 0, mErr
		}
		target, ok := byModule[modRoot]
		if !ok {
			target = &moduleTarget{root: modRoot, path: modPath}
			byModule[modRoot] = target
			order = append(order, modRoot)
		}
		target.declDirs = append(target.declDirs, dir)
	}
	sort.Strings(order)

	var dead []deadInterface
	var blocked []unresolvedShape
	files := 0
	for _, modRoot := range order {
		d, b, f, sErr := byModule[modRoot].scan(root)
		if sErr != nil {
			return nil, nil, files, sErr
		}
		dead = append(dead, d...)
		blocked = append(blocked, b...)
		files += f
	}

	sort.Slice(dead, func(i, j int) bool {
		if dead[i].file != dead[j].file {
			return dead[i].file < dead[j].file
		}
		return dead[i].line < dead[j].line
	})
	sort.Slice(blocked, func(i, j int) bool {
		if blocked[i].file != blocked[j].file {
			return blocked[i].file < blocked[j].file
		}
		return blocked[i].line < blocked[j].line
	})
	return dead, blocked, files, nil
}

// declaringDirs expands dirs into every directory beneath them that holds at least one Go file.
// No dirs means the whole source root, which is what lets a caller hold a module rather than a
// package if it ever needs to.
func declaringDirs(root string, dirs []string) ([]string, error) {
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
			if !seen[dir] {
				seen[dir] = true
				found = append(found, dir)
			}
			return nil
		})
		if err != nil {
			return nil, errs.Wrapf(err, "walking %s", start)
		}
	}
	sort.Strings(found)
	return found, nil
}

// skippedDir names the directories no Go package this repository builds can live under. They are
// skipped rather than parsed because a vendored tree would otherwise be searched for references,
// and a reference from vendored code is not a consumer of anything this repository declares.
func skippedDir(name string) bool {
	return name == "vendor" || name == "node_modules" || name == ".git" || name == "testdata"
}

// moduleFor finds the module that owns dir: the nearest ancestor holding a go.mod, at or below
// root. That is the search space for references, per the ceiling on AssertNoDeadInterfaces.
func moduleFor(root, dir string) (modRoot, modPath string, err error) {
	for d := dir; ; {
		goMod := filepath.Join(d, "go.mod")
		if _, sErr := os.Stat(goMod); sErr == nil {
			// modulePath is AssertArchitecture's, and sharing it is the point: a module renamed in
			// go.mod has to move both guards at once rather than one of them silently.
			path, pErr := modulePath(goMod)
			if pErr != nil {
				return "", "", pErr
			}
			return d, path, nil
		}
		if d == root {
			break
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	return "", "", errs.Errorf("no go.mod above %s (searched up to %s)", dir, root)
}

// moduleTarget is one module, with the directories inside it whose interfaces are being held.
type moduleTarget struct {
	root     string
	path     string
	declDirs []string
}

// importPathOf gives the import path of a directory inside this module.
func (m *moduleTarget) importPathOf(dir string) string {
	rel, err := filepath.Rel(m.root, dir)
	if err != nil || rel == "." {
		return m.path
	}
	return m.path + "/" + filepath.ToSlash(rel)
}

// scan type-checks the declaring packages, then every other package in the module that could
// possibly hold a reference, and reports the declarations nothing bound to.
func (m *moduleTarget) scan(root string) ([]deadInterface, []unresolvedShape, int, error) {
	stub := newStubPackages()

	// The stub importer invents a package name from the import path for everything it is asked
	// for, which is right for almost every package and irrelevant for the rest: a wrong name only
	// makes an unrelated package's selectors unresolvable, and this walk asks nothing of them. The
	// declaring packages are the exception, because a selector's base has to bind to one of them
	// for a cross-package reference to be seen at all, so their real names are read from their own
	// package clauses first.
	for _, dir := range m.declDirs {
		name, err := packageNameIn(dir)
		if err != nil {
			return nil, nil, 0, err
		}
		if name != "" {
			stub.names[m.importPathOf(dir)] = name
		}
	}

	var decls []declaredInterface
	var blocked []unresolvedShape
	files := 0
	declared := map[string]bool{}
	isDeclDir := map[string]bool{}

	qualified := map[string]bool{}
	localUsed := map[types.Object]bool{}

	for _, dir := range m.declDirs {
		isDeclDir[dir] = true
		d, b, f, err := m.checkDir(root, dir, stub, true, nil, qualified, localUsed)
		if err != nil {
			return nil, nil, files, err
		}
		decls = append(decls, d...)
		blocked = append(blocked, b...)
		files += f
	}
	for _, d := range decls {
		declared[d.name] = true
	}

	// Nothing else in the module can hold a reference unless one of its files literally spells a
	// declared interface's name: Go binds an identifier to a declaration by its text, so a file
	// that does not carry the text cannot carry the reference. That filter is what keeps a
	// module-wide walk cheap enough to run in a unit tier.
	if len(declared) > 0 {
		others, err := declaringDirs(m.root, nil)
		if err != nil {
			return nil, nil, files, err
		}
		for _, dir := range others {
			if isDeclDir[dir] {
				continue
			}
			_, b, _, cErr := m.checkDir(root, dir, stub, false, declared, qualified, localUsed)
			if cErr != nil {
				return nil, nil, files, cErr
			}
			blocked = append(blocked, b...)
		}
	}

	var dead []deadInterface
	for _, d := range decls {
		if localUsed[d.obj] || qualified[d.pkg+"."+d.name] {
			continue
		}
		dead = append(dead, deadInterface{pkg: d.pkg, file: d.file, line: d.line, name: d.name})
	}
	return dead, blocked, files, nil
}

// declaredInterface is one interface declaration, carrying the go/types object the walk compares
// same-package references against by pointer identity.
type declaredInterface struct {
	pkg  string
	file string
	line int
	name string
	obj  types.Object
}

// checkDir parses one directory's Go files, type-checks each package clause in it, and records
// what it found. When declaring is true every file is parsed and the directory's own interface
// declarations are collected; otherwise only files carrying a declared interface's spelling are
// parsed, and only references are recorded.
//
// qualified accumulates "<import path>.<Name>" for every selector whose base binds to an import,
// and localUsed accumulates the objects unqualified identifiers bound to inside a declaring
// package. Those two maps are the whole answer: a declaration absent from both is dead.
func (m *moduleTarget) checkDir(
	root, dir string,
	stub *stubPackages,
	declaring bool,
	declared map[string]bool,
	qualified map[string]bool,
	localUsed map[types.Object]bool,
) ([]declaredInterface, []unresolvedShape, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, 0, errs.Wrapf(err, "reading %s", dir)
	}

	fset := token.NewFileSet()
	// Grouped by package clause, because a directory holds both foo and foo_test and go/types
	// checks one package at a time.
	byPackage := map[string][]*ast.File{}
	var packageOrder []string
	var blocked []unresolvedShape
	files := 0

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		raw, rErr := os.ReadFile(path)
		if rErr != nil {
			return nil, nil, files, errs.Wrapf(rErr, "reading %s", path)
		}
		if !declaring && !mentionsAny(raw, declared) {
			continue
		}
		file, pErr := parser.ParseFile(fset, path, raw, parser.SkipObjectResolution)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns, and reporting it
			// here would send the reader to the wrong place.
			continue
		}
		if declaring {
			files++
		}
		rel := relativeTo(root, path)
		blocked = append(blocked, dotImportsIn(file, fset, rel)...)
		name := file.Name.Name
		if _, seen := byPackage[name]; !seen {
			packageOrder = append(packageOrder, name)
		}
		byPackage[name] = append(byPackage[name], file)
	}

	var decls []declaredInterface
	pkgPath := m.importPathOf(dir)
	for _, name := range packageOrder {
		group := byPackage[name]
		checkPath := pkgPath
		if strings.HasSuffix(name, "_test") {
			checkPath = pkgPath + "_test"
		}

		info := &types.Info{
			Defs: map[*ast.Ident]types.Object{},
			Uses: map[*ast.Ident]types.Object{},
		}
		conf := types.Config{
			Importer: stub,
			// Every import is a stub, so the great majority of what go/types has to say about
			// these files is that some invented package has no such member. Collecting the errors
			// and discarding them is what keeps the checker running to the end; what survives is
			// identifier resolution, which is lexical and needs no import to be correct.
			Error:                    func(error) {},
			DisableUnusedImportCheck: true,
		}
		// The returned error is the first one Error already saw. The package and the info are
		// filled in either way, which is the whole point of running in error-tolerant mode.
		_, _ = conf.Check(checkPath, fset, group, info)

		var groupObjs map[types.Object]bool
		if declaring {
			groupObjs = map[types.Object]bool{}
			for _, file := range group {
				d, b := interfaceDeclsIn(file, fset, info, root, pkgPath)
				decls = append(decls, d...)
				blocked = append(blocked, b...)
				for _, one := range d {
					groupObjs[one.obj] = true
				}
			}
		}

		recordReferences(group, info, groupObjs, qualified, localUsed)
	}

	return decls, blocked, files, nil
}

// interfaceDeclsIn collects the top-level interface declarations in one file. A declaration inside
// a function body is left alone: it is unreachable from outside that body by construction, so
// "nothing references it" is not a finding about the package's surface.
func interfaceDeclsIn(
	file *ast.File, fset *token.FileSet, info *types.Info, root, pkgPath string,
) ([]declaredInterface, []unresolvedShape) {
	var decls []declaredInterface
	var blocked []unresolvedShape

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			if _, ok := ts.Type.(*ast.InterfaceType); !ok {
				continue
			}
			position := fset.Position(ts.Name.Pos())
			rel := relativeTo(root, position.Filename)
			obj := info.Defs[ts.Name]
			if obj == nil {
				// No object means no identity to compare references against, so every answer
				// about this declaration would be a guess.
				blocked = append(blocked, unresolvedShape{
					file: rel,
					line: position.Line,
					why: "the declaration of " + ts.Name.Name + " did not resolve to a type, so " +
						"nothing can be said about whether anything references it",
				})
				continue
			}
			decls = append(decls, declaredInterface{
				pkg:  pkgPath,
				file: rel,
				line: position.Line,
				name: ts.Name.Name,
				obj:  obj,
			})
		}
	}
	return decls, blocked
}

// recordReferences walks one checked package and records every reference that binds to something
// this guard might be holding.
//
// Two shapes, and both are answered by the object an identifier actually bound to rather than by
// the text at the site:
//
//   - A selector whose base resolves to a *types.PkgName is a qualified reference, and the import
//     path comes off the PkgName rather than off the spelling. That is what tells handlers.X from
//     tcputils.X, and what makes an aliased import count. A base that resolved to anything else --
//     a local variable wearing the import's name, most often -- is not a reference to the package
//     at all, so nothing is recorded and the interface stays dead.
//   - An unqualified identifier that bound to one of this package's own interface declarations.
//     Identity is against the object, so a local of the same spelling records nothing. The
//     declaration's own name identifier cannot appear here: go/types puts a defining identifier in
//     Defs, never in Uses.
func recordReferences(
	files []*ast.File,
	info *types.Info,
	groupObjs map[types.Object]bool,
	qualified map[string]bool,
	localUsed map[types.Object]bool,
) {
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			base, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if pkgName, ok := info.Uses[base].(*types.PkgName); ok {
				qualified[pkgName.Imported().Path()+"."+sel.Sel.Name] = true
			}
			return true
		})
	}

	if len(groupObjs) == 0 {
		return
	}
	for _, obj := range info.Uses {
		if groupObjs[obj] {
			localUsed[obj] = true
		}
	}
}

// dotImportsIn reports a dot import as an unresolved shape. An unqualified name reaching this file
// from a dot-imported package binds to a declaration in a package this walk never named, so a file
// carrying one can neither be shown to reference an interface nor shown not to. There is no dot
// import anywhere in this tree today, which is why refusing it costs nothing and admitting it
// silently would cost the guard its meaning.
func dotImportsIn(file *ast.File, fset *token.FileSet, rel string) []unresolvedShape {
	var found []unresolvedShape
	for _, imp := range file.Imports {
		if imp.Name == nil || imp.Name.Name != "." {
			continue
		}
		found = append(found, unresolvedShape{
			file: rel,
			line: fset.Position(imp.Pos()).Line,
			why: "dot import of " + imp.Path.Value + ": an unqualified reference through a dot " +
				"import binds to a package this walk cannot name, so interface liveness in this " +
				"file is unknowable; give the import a name",
		})
	}
	return found
}

// mentionsAny reports whether the source text carries any of the names, which is the sound
// pre-filter on parsing: an identifier binds to a declaration by its text, so a file that never
// spells the name cannot reference it, whatever it imports.
func mentionsAny(src []byte, names map[string]bool) bool {
	text := string(src)
	for name := range names {
		if strings.Contains(text, name) {
			return true
		}
	}
	return false
}

// packageNameIn reads the package clause of the first non-test Go file in dir.
func packageNameIn(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", errs.Wrapf(err, "reading %s", dir)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	fset := token.NewFileSet()
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, pErr := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.PackageClauseOnly)
		if pErr != nil {
			continue
		}
		return file.Name.Name, nil
	}
	return "", nil
}

// relativeTo renders path relative to root with forward slashes, falling back to the path itself
// when the two share no prefix.
func relativeTo(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

// stubPackages is an importer that never reads a package. Every path it is asked for becomes an
// empty, complete types.Package, which is enough for the two questions this guard asks -- which
// object an identifier binds to, and which import path a package name came from -- because both
// are answered by lexical scoping rather than by anything inside the imported package.
type stubPackages struct {
	names map[string]string
	made  map[string]*types.Package
}

func newStubPackages() *stubPackages {
	return &stubPackages{names: map[string]string{}, made: map[string]*types.Package{}}
}

func (s *stubPackages) Import(path string) (*types.Package, error) {
	if made, ok := s.made[path]; ok {
		return made, nil
	}
	name, ok := s.names[path]
	if !ok {
		name = inventedPackageName(path)
	}
	pkg := types.NewPackage(path, name)
	pkg.MarkComplete()
	s.made[path] = pkg
	return pkg, nil
}

// inventedPackageName guesses the package name of a path this walk has not read, which is the last
// path element with any version suffix dropped. It is right for almost every package and harmless
// when it is wrong: a name that does not match only leaves that package's own selectors
// unresolved, and this guard asks nothing of a package it is not holding.
func inventedPackageName(path string) string {
	base := path
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
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
