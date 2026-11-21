package guard

import (
	"go/ast"
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
	"github.com/leodip/goiabada/core/internal/refgraph"
	"github.com/leodip/goiabada/core/pkgload"
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
// an identifier actually binds to, and so is a name a dot import brings in, which is a reference
// like any other.
//
// The module is read through pkgload as the test build of the machine the tests run on, so a
// test file is read like a production one. A reference the walk does not see shows up as a false
// finding, which is loud, and a test for another platform does not run there anyway (#420). A
// package anywhere in the module that does not load or type-check is fatal, naming it: its
// references would go unread, and an interface only it names would be reported dead.
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

	assertNoDeadInterfaces(t, SourceRoot(t), dirs)
}

// assertNoDeadInterfaces is the reporting half, taking the root as a parameter and failing through
// a Reporter so a rule test can drive it against a fixture tree. See Reporter in guard.go.
func assertNoDeadInterfaces(r Reporter, root string, dirs []string) {
	r.Helper()

	dead, files, err := findDeadInterfaces(root, dirs)
	if err != nil {
		r.Fatalf("walking %s: %v", root, err)
	}
	// A walk that reached no files passes vacuously, which is the one way a guard like this stops
	// guarding without anything going red.
	if files == 0 {
		r.Fatalf("walked no Go files under %s (dirs: %s)", root, strings.Join(dirs, ", "))
	}

	if len(dead) == 0 {
		return
	}

	lines := make([]string, 0, len(dead))
	for _, d := range dead {
		lines = append(lines, d.file+":"+strconv.Itoa(d.line)+": "+d.pkg+"."+d.name)
	}
	r.Errorf("%d interface declaration(s) nothing in the module references:\n\t%s\n\n"+
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
// because the alternative -- passing over it -- is a guard silently narrowing its own scope. The
// context-value and AssertNotCalled-arity guards report it; this guard reads type-checked
// packages, where every name resolves, and has none.
type unresolvedShape struct {
	file string
	line int
	why  string
}

// findDeadInterfaces collects every top-level interface declared under the named subdirectories of
// root, then searches each declaring package's whole module for a reference that binds to it. It
// returns the unreferenced declarations and the number of Go files the declaring directories'
// packages hold in the build it read.
func findDeadInterfaces(root string, dirs []string) ([]deadInterface, int, error) {
	declDirs, err := declaringDirs(root, dirs)
	if err != nil {
		return nil, 0, err
	}

	// Group the declaring directories by the module that owns each, so one module is loaded once
	// however many of its packages are being guarded.
	byModule := map[string]map[string]bool{}
	var order []string
	for _, dir := range declDirs {
		modRoot, _, mErr := moduleFor(root, dir)
		if mErr != nil {
			return nil, 0, mErr
		}
		if byModule[modRoot] == nil {
			byModule[modRoot] = map[string]bool{}
			order = append(order, modRoot)
		}
		byModule[modRoot][dir] = true
	}
	sort.Strings(order)

	var dead []deadInterface
	files := 0
	for _, modRoot := range order {
		d, f, sErr := deadInterfacesIn(root, modRoot, byModule[modRoot])
		if sErr != nil {
			return nil, files, sErr
		}
		dead = append(dead, d...)
		files += f
	}

	sort.Slice(dead, func(i, j int) bool {
		if dead[i].file != dead[j].file {
			return dead[i].file < dead[j].file
		}
		return dead[i].line < dead[j].line
	})
	return dead, files, nil
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
			// ModulePath is what AssertArchitecture's graph reads, and sharing it is the point: a
			// module renamed in go.mod has to move both guards at once rather than one of them
			// silently.
			path, pErr := refgraph.ModulePath(goMod)
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

// interfaceKey is a package-level type by the import path of its package and its name, which is
// the one identity a declaration keeps across the builds of its package. The test build
// type-checks a package a second time with its internal tests, and a package importing it there
// binds to that second copy, a different types.Object for the same declaration.
type interfaceKey struct {
	pkg, name string
}

// deadInterfacesIn loads the module rooted at modRoot, collects the top-level interfaces its
// packages in declDirs declare, and returns those no identifier anywhere in the module binds to,
// with the number of Go files those packages hold.
//
// A reference is an identifier go/types resolved to a package-level type: the object it bound
// to, not its text, which is what tells handlers.X from tcputils.X and a local spelled X from the
// type. The declaration's own name cannot count, because go/types records a defining identifier
// in Defs and never in Uses.
//
// A declaration inside a function body is left alone: it is unreachable from outside that body by
// construction, so "nothing references it" is not a finding about the package's surface.
func deadInterfacesIn(root, modRoot string, declDirs map[string]bool) ([]deadInterface, int, error) {
	pkgs, err := pkgload.Load(modRoot, pkgload.Build{Tests: true})
	if err != nil {
		return nil, 0, err
	}

	declared := map[interfaceKey]deadInterface{}
	used := map[interfaceKey]bool{}
	read := map[string]bool{}
	for _, p := range pkgs {
		for _, obj := range p.TypesInfo.Uses {
			// A type declared in a function body is no package-level declaration, whatever its
			// spelling, and the universe's error and any belong to no package.
			tn, ok := obj.(*types.TypeName)
			if ok && tn.Pkg() != nil && tn.Pkg().Scope().Lookup(tn.Name()) == tn {
				used[interfaceKey{pkg: tn.Pkg().Path(), name: tn.Name()}] = true
			}
		}

		// A test binary's generated main has its files outside the module and declares nothing.
		if len(p.GoFiles) == 0 || !declDirs[filepath.Dir(p.GoFiles[0])] {
			continue
		}
		for _, f := range p.GoFiles {
			read[f] = true
		}
		for _, file := range p.Syntax {
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
					key := interfaceKey{pkg: p.PkgPath, name: ts.Name.Name}
					position := p.Fset.Position(ts.Name.Pos())
					declared[key] = deadInterface{
						pkg:  p.PkgPath,
						file: relativeTo(root, position.Filename),
						line: position.Line,
						name: ts.Name.Name,
					}
				}
			}
		}
	}

	var dead []deadInterface
	for key, d := range declared {
		if !used[key] {
			dead = append(dead, d)
		}
	}
	return dead, len(read), nil
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
// empty, complete types.Package, which is enough for the two questions the context-value and
// AssertNotCalled-arity guards ask of it -- which object an identifier binds to, and which import
// path a package name came from -- because both are answered by lexical scoping rather than by
// anything inside the imported package.
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
// unresolved, and neither guard asks anything of a package it is not holding.
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
