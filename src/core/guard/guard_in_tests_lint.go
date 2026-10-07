package guard

import (
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/internal/refgraph"
)

// AssertNoGuardInTestsReachedFrom holds every test of every package moduleDir reaches to naming no
// import of core/guard, directly or through a first-party package whose production code reaches it.
//
// go mod tidy reads the tests of every package a module imports, not only that module's own, and
// records a checksum in its go.sum for every module those tests need. A test anywhere in that set
// importing core/guard therefore puts core/guard's own dependencies in the module's go.sum: TOML,
// which it reads ARCHITECTURE.md's tables with, and chi, through core/metrics. The auth server and
// the admin console call the guards from their own tiers and need those modules anyway. The setup
// wizard does not: its tier calls none of the tree-wide guards, and it imports four core packages
// and needs nothing of theirs but what they compile. #500 moved the admin password rule into a leaf
// package to keep i18n, TOML and JWT out of the wizard, and then put the leak straight back through
// the leaf's own import-list test, which tidy alone noticed. This is the rule that review stated,
// held.
//
// moduleDir is a module directory relative to the source root, forward slashes. The walk starts at
// its packages, follows their production imports and their tests' imports one step, and from there
// production imports over first-party edges: a test of a package the module reaches only through
// its own tests is read by tidy too. Every package so reached has its _test.go files parsed for
// their imports, which is what lets a finding name the file and line rather than only the package.
//
// It reads and parses files and nothing else: no database, no git, no network.
func AssertNoGuardInTestsReachedFrom(t *testing.T, moduleDir string) {
	t.Helper()

	assertNoGuardInTestsReachedFrom(t, SourceRoot(t), moduleDir)
}

// assertNoGuardInTestsReachedFrom is the reporting half, taking the root as a parameter and failing
// through a Reporter so a rule test can drive it against a fixture tree. See Reporter in guard.go.
func assertNoGuardInTestsReachedFrom(r Reporter, root, moduleDir string) {
	r.Helper()

	found, reached, err := findGuardInTests(root, moduleDir)
	if err != nil {
		r.Fatalf("reading the import graph under %s: %v", root, err)
	}
	// A module directory holding no production package, or one that names no module at all,
	// reaches nothing and would otherwise pass, which is the one way a guard like this fails
	// silently in the direction that matters.
	if reached == 0 {
		r.Fatalf("reached no package from %s", moduleDir)
	}

	if len(found) == 0 {
		return
	}
	lines := make([]string, 0, len(found))
	for _, f := range found {
		lines = append(lines, f.file+":"+strconv.Itoa(f.line)+": "+strings.Join(f.chain, " -> "))
	}

	r.Errorf("%d test import(s) reach core/guard from a package %s reaches:\n\t%s\n\n"+
		"go mod tidy reads the tests of every package a module imports, so each of these puts "+
		"core/guard's dependencies, chi and TOML among them, in %s's go.sum, for modules none of its "+
		"packages use (#500). Call the guard from a test in core/guard, as "+
		"TestAdminPassword_ImportsNothingButErrsAndTheStandardLibrary does, or from a module that "+
		"needs core/guard anyway.",
		len(found), moduleDir, strings.Join(lines, "\n\t"), moduleDir)
}

// guardInTest is one import in a test file that reaches core/guard.
type guardInTest struct {
	// file is relative to the root the walk started from, forward slashes.
	file string
	line int
	// chain runs from the imported path to core/guard, one element when the test names it directly.
	chain []string
}

// findGuardInTests walks what moduleDir reaches and reports every test import that reaches
// core/guard. It returns the number of packages it reached, so the reporting half can tell
// "nothing to report" from "nothing was read".
func findGuardInTests(root, moduleDir string) ([]guardInTest, int, error) {
	graph, err := refgraph.BuildImportGraph(root)
	if err != nil {
		return nil, 0, err
	}
	guardPath := graph.Modules["core"] + "/guard"

	reached := reachedFrom(graph, moduleDir)

	pkgs := make([]string, 0, len(reached))
	for pkg := range reached {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)

	var found []guardInTest
	for _, pkg := range pkgs {
		// core/guard's own tests are not a leak: whatever reaches core/guard has its dependencies
		// already, and rule 9 refuses a shipped main that does.
		if pkg == guardPath {
			continue
		}
		dir := graph.RelPath(pkg)
		entries, rErr := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		if errors.Is(rErr, fs.ErrNotExist) {
			// An import of a first-party path with no directory is a compile error the build
			// tier owns, like a file that does not parse.
			continue
		}
		if rErr != nil {
			return nil, 0, rErr
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			file, pErr := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(dir), entry.Name()), nil, parser.ImportsOnly)
			if pErr != nil {
				// A file that does not parse is a compile error the build tier owns, and
				// reporting it here would send the reader to the wrong place.
				continue
			}
			for _, spec := range file.Imports {
				imported, uErr := strconv.Unquote(spec.Path.Value)
				if uErr != nil {
					continue
				}
				chain := chainToGuard(graph, imported, guardPath)
				if chain == nil {
					continue
				}
				found = append(found, guardInTest{
					file:  dir + "/" + entry.Name(),
					line:  fset.Position(spec.Pos()).Line,
					chain: chain,
				})
			}
		}
	}
	return found, len(reached), nil
}

// reachedFrom is every first-party package moduleDir reaches: its own packages, what their
// production code and their tests import, and from there everything reached over production
// edges. A test's imports are followed one step only, at the module itself: past it, what a
// dependency's test imports is the finding this guard reports, not more of the walk.
func reachedFrom(graph *refgraph.ImportGraph, moduleDir string) map[string]bool {
	seen := map[string]bool{}
	var stack []string
	for _, edges := range []map[string][]string{graph.Prod, graph.Test} {
		for pkg, imports := range edges {
			if graph.ModuleDir(pkg) != moduleDir {
				continue
			}
			stack = append(stack, pkg)
			for _, imported := range imports {
				if graph.ModuleDir(imported) != "" {
					stack = append(stack, imported)
				}
			}
		}
	}

	for len(stack) > 0 {
		pkg := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		for _, imported := range graph.Prod[pkg] {
			if graph.ModuleDir(imported) != "" {
				stack = append(stack, imported)
			}
		}
	}
	return seen
}

// chainToGuard returns the shortest chain of production imports from start to guardPath, both ends
// included, or nil when start does not reach it. A breadth-first walk, so the chain a failure names
// is the shortest one to break.
func chainToGuard(graph *refgraph.ImportGraph, start, guardPath string) []string {
	if start == guardPath {
		return []string{start}
	}
	if graph.ModuleDir(start) == "" {
		return nil
	}
	parent := map[string]string{start: ""}
	queue := []string{start}
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		for _, imported := range graph.Prod[pkg] {
			if _, ok := parent[imported]; ok || graph.ModuleDir(imported) == "" {
				continue
			}
			parent[imported] = pkg
			if imported == guardPath {
				var chain []string
				for at := imported; at != ""; at = parent[at] {
					chain = append([]string{at}, chain...)
				}
				return chain
			}
			queue = append(queue, imported)
		}
	}
	return nil
}
