package refgraph

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// moduleDirs are the four go.mod directories, relative to the source root, in the order a reader
// expects them. root.go's modules list identifies the source root while ascending; this one is
// what the graph resolves import paths against, and the two are deliberately the same set.
var moduleDirs = []string{"core", "authserver", "adminconsole", "cmd/goiabada-setup"}

// ImportGraph is the tree as the compiler sees it: one entry per package directory holding at least
// one Go file, mapping its import path to the paths it imports. Production and test files are kept
// apart because the rules treat them differently — a test may import a mock or a fixture from
// anywhere, and holding test code to the production graph would make core/testutil unusable from
// the very tiers that call its guards.
type ImportGraph struct {
	Prod     map[string][]string
	Test     map[string][]string
	Modules  map[string]string // directory relative to the source root -> module import path
	CorePkgs []string          // top-level core packages on disk, as "core/<name>"
}

// BuildImportGraph parses every Go file under root for its imports alone and groups them by package
// directory. Imports are read from the AST rather than matched in the text, so an import path
// inside a comment or a string literal is not an edge and an aliased import still is one.
func BuildImportGraph(root string) (*ImportGraph, error) {
	graph := &ImportGraph{
		Prod:    map[string][]string{},
		Test:    map[string][]string{},
		Modules: map[string]string{},
	}

	for _, dir := range moduleDirs {
		path, err := ModulePath(filepath.Join(root, filepath.FromSlash(dir), "go.mod"))
		if err != nil {
			return nil, err
		}
		graph.Modules[dir] = path
	}

	prod := map[string]map[string]bool{}
	test := map[string]map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return errs.Wrapf(relErr, "relating %s to %s", path, root)
		}
		rel = filepath.ToSlash(rel)

		pkg, ok := graph.ImportPath(filepath.ToSlash(filepath.Dir(rel)))
		if !ok {
			// A Go file outside the four modules belongs to no package this guard can name.
			return nil
		}

		fset := token.NewFileSet()
		// ParseComments because the build constraint is a comment, and a file excluded from every
		// production build is not part of the production graph.
		file, pErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.ParseComments)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns, and reporting it
			// here would send the reader to the wrong place.
			return nil
		}

		isTest := strings.HasSuffix(rel, "_test.go")
		if !isTest && ExemptByBuildConstraint(file, fset) {
			return nil
		}

		into := prod
		if isTest {
			into = test
		}
		if into[pkg] == nil {
			into[pkg] = map[string]bool{}
		}
		for _, imported := range importPaths(file) {
			into[pkg][imported] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	graph.Prod = Flatten(prod)
	graph.Test = Flatten(test)

	graph.CorePkgs, err = topLevelCorePackages(root)
	if err != nil {
		return nil, err
	}

	return graph, nil
}

// Flatten turns a set of edges per package into a sorted list per package.
func Flatten(in map[string]map[string]bool) map[string][]string {
	out := make(map[string][]string, len(in))
	for pkg, imports := range in {
		list := make([]string, 0, len(imports))
		for i := range imports {
			list = append(list, i)
		}
		sort.Strings(list)
		out[pkg] = list
	}
	return out
}

func importPaths(file *ast.File) []string {
	paths := make([]string, 0, len(file.Imports))
	for _, spec := range file.Imports {
		if spec.Path == nil {
			continue
		}
		paths = append(paths, strings.Trim(spec.Path.Value, `"`))
	}
	return paths
}

// ModulePath reads the module line out of a go.mod. Reading it rather than hard-coding the four
// paths means a module renamed in go.mod is a failure here rather than a graph that silently stops
// recognising half the tree as first-party.
func ModulePath(goMod string) (string, error) {
	content, err := os.ReadFile(goMod)
	if err != nil {
		return "", errs.Wrapf(err, "reading %s", goMod)
	}
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if after, found := strings.CutPrefix(trimmed, "module "); found {
			return strings.TrimSpace(after), nil
		}
	}
	return "", errs.Errorf("%s has no module line", goMod)
}

// ImportPath turns a directory relative to the source root into the import path the compiler gives
// it, and reports whether the directory belongs to one of the four modules. The longest module
// directory wins, so cmd/goiabada-setup is not read as a subdirectory of anything.
func (g *ImportGraph) ImportPath(dir string) (string, bool) {
	best := ""
	for moduleDir := range g.Modules {
		if dir != moduleDir && !strings.HasPrefix(dir, moduleDir+"/") {
			continue
		}
		if len(moduleDir) > len(best) {
			best = moduleDir
		}
	}
	if best == "" {
		return "", false
	}
	path := g.Modules[best]
	if dir != best {
		path += "/" + strings.TrimPrefix(dir, best+"/")
	}
	return path, true
}

// ModuleDir returns the module directory an import path belongs to, or "" when the path is not
// first-party.
func (g *ImportGraph) ModuleDir(importPath string) string {
	best, bestLen := "", -1
	for dir, path := range g.Modules {
		if importPath != path && !strings.HasPrefix(importPath, path+"/") {
			continue
		}
		if len(path) > bestLen {
			best, bestLen = dir, len(path)
		}
	}
	return best
}

// RelPath returns the import path as a directory relative to the source root, which is how the
// exception table names both ends of an edge. An exception is granted to the package that holds the
// import, never to its module or to its parent: guidance point 4 of #332 asks for exact package
// edges, and a module-wide grant would let a second package acquire the same dependency in silence.
func (g *ImportGraph) RelPath(importPath string) string {
	dir := g.ModuleDir(importPath)
	if dir == "" {
		return importPath
	}
	module := g.Modules[dir]
	if importPath == module {
		return dir
	}
	return dir + "/" + strings.TrimPrefix(importPath, module+"/")
}

// TopCorePackage returns the top-level core package an import path belongs to, as "core/<name>", or
// "" when the path is not under core. Ownership is recorded per top-level package because that is
// the granularity the epic moves things at.
func (g *ImportGraph) TopCorePackage(importPath string) string {
	corePath := g.Modules["core"]
	if !strings.HasPrefix(importPath, corePath+"/") {
		return ""
	}
	return "core/" + strings.Split(strings.TrimPrefix(importPath, corePath+"/"), "/")[0]
}

// topLevelCorePackages lists the directories directly under core that hold at least one production
// Go file at any depth. That is the set the ownership table must cover exactly: core/audit holds
// nothing but a mocks directory and is still a directory whose fate has to be recorded.
func topLevelCorePackages(root string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, "core"))
	if err != nil {
		return nil, errs.Wrapf(err, "reading the core module directory")
	}

	var pkgs []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		holds := false
		wErr := filepath.WalkDir(filepath.Join(root, "core", entry.Name()), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				holds = true
			}
			return nil
		})
		if wErr != nil {
			return nil, wErr
		}
		if holds {
			pkgs = append(pkgs, "core/"+entry.Name())
		}
	}
	sort.Strings(pkgs)
	return pkgs, nil
}
