package guard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/internal/refgraph"
)

// AssertArchitecture holds the repository's module and package ownership rules to the tree they
// describe. The rules themselves are not written here: they are the five tables in
// ARCHITECTURE.md at the repository root, which this function parses and then checks against the
// real tree — four against the import graph, and the fifth against the production references to
// core/builtin. That file names each rule and carries the reasoning; this one decides.
//
// Putting the data in the document rather than in Go is the same choice AssertAgentDocs made for
// the ceremony's state roster (#252). A dependency rule is prose about code, and prose about code
// is the one thing nothing else in this repository checks. The direction between these modules is
// invisible at every call site and is not a compile error until the day it becomes an import cycle,
// so it decays without anything going red: core grew an application inside it exactly that way, one
// reasonable-looking import at a time, until the admin console's binary linked four database
// drivers it has no use for.
//
// The checks run in both directions, which is what makes the document a burn-down list rather than
// a wish. An edge the tables do not allow is a finding. So is an exception listed for an edge that
// no longer exists: when #335 moves the settings middleware, the exception rows it was granted stop
// matching anything and the tier fails until they are deleted. Without that half, the exception list
// would only ever grow, and a waiver nobody is forced to revisit is indistinguishable from a rule
// that was never written.
//
// Scope is the source root for the graph and its parent for the document, because SourceRoot
// returns the directory holding the four go.mod files and ARCHITECTURE.md sits one level above it.
// Each module's unit tier calls this, so the guard fires whichever tier is run.
func AssertArchitecture(t *testing.T) {
	t.Helper()

	assertArchitecture(t, SourceRoot(t))
}

// assertArchitecture is the reporting half, taking the root as a parameter and failing through a
// Reporter so a rule test can drive it against a fixture tree. See Reporter in guard.go.
func assertArchitecture(r Reporter, root string) {
	r.Helper()

	doc, err := os.ReadFile(filepath.Join(filepath.Dir(root), architectureDoc))
	if err != nil {
		r.Fatalf("reading %s: %v", architectureDoc, err)
	}

	tables, findings := parseArchitectureDoc(string(doc))

	graph, err := refgraph.BuildImportGraph(root)
	if err != nil {
		r.Fatalf("reading the import graph under %s: %v", root, err)
	}
	// A graph that somehow held no packages would satisfy every rule below, which is the one way a
	// guard like this fails silently in the direction that matters.
	if len(graph.Prod) == 0 {
		r.Fatalf("found no production Go packages under %s", root)
	}

	census, err := buildBuiltinCensus(root, graph)
	if err != nil {
		r.Fatalf("reading the %s census under %s: %v", builtinPkgDir, root, err)
	}
	// The same silent failure as the empty graph, one table down. A census that read no
	// declaration satisfies "every symbol has a row" for nothing at all, and a census that found no
	// reference would rest every justification on an empty set.
	if len(census.declared) == 0 {
		r.Fatalf("found no exported declarations in %s under %s", builtinPkgDir, root)
	}
	if len(census.refs) == 0 {
		r.Fatalf("found no production reference to any %s symbol under %s", builtinPkgDir, root)
	}

	// Rule 9's walk that reached nothing. A tree in which no shipped main is found links no test
	// framework into any of them, so a source root resolved somewhere else, or all three mains
	// renamed, would read as a clean tree. One missing of three is a finding instead: the other two
	// are still walked, and the reader is owed what they say too.
	var missing []string
	for _, dir := range shippedMains {
		if _, ok := shippedMainPackage(graph, dir); !ok {
			missing = append(missing, dir)
		}
	}
	if len(missing) == len(shippedMains) {
		r.Fatalf("found none of the shipped mains %s under %s", strings.Join(shippedMains, ", "), root)
	}
	for _, dir := range missing {
		findings = append(findings, fmt.Sprintf(
			"test code: the shipped main %s holds no production Go file, so rule 9 walks nothing for it; if it moved, shippedMains in core/guard/architecture.go moves with it",
			dir))
	}

	external, loadFindings, err := compiledClosure(root, graph)
	if err != nil {
		r.Fatalf("listing the shipped mains' dependencies under %s: %v", root, err)
	}
	findings = append(findings, loadFindings...)

	findings = append(findings, checkArchitecture(tables, graph, external)...)
	findings = append(findings, checkBuiltinOwnership(tables, graph, census)...)

	sort.Strings(findings)
	for _, f := range findings {
		r.Errorf("%s", f)
	}
}

// architectureDoc is the file holding the rules, relative to the repository root.
const architectureDoc = "ARCHITECTURE.md"

// The headings whose tables are data. Each is the deepest heading of its section, so the
// prose above it is free to change without touching the parser. The fifth, builtinHeading,
// is declared beside the checks that read it in builtin_ownership.go.
const (
	ownershipHeading     = "### Package ownership"
	exceptionHeading     = "### Temporary exceptions"
	foreignHeading       = "### Foreign modules"
	testFrameworkHeading = "### Test frameworks"
)

// shippedMains are the binaries a release ships, as directories relative to the source root: the
// auth server, the admin console and the setup wizard, the three release.yml builds and nothing
// else. Rule 9 walks the production closure of each. They are listed here rather than found by
// looking for package main, because schemadump, droptestdb, ownershipdump and the two generators
// are main packages too, ship in no release, and may link what they like. Every release build of
// all three sets the production tag, which is what lets rule 9 read each with production set;
// TestReleaseBuilds_TheRealReleaseBuildsSetProduction holds the release scripts and Dockerfiles to
// that, and fails while a main listed here has no release build listed there (#463).
var shippedMains = []string{
	"authserver/cmd/goiabada-authserver",
	"adminconsole/cmd/goiabada-adminconsole",
	"cmd/goiabada-setup",
}

// releaseTargets are the platforms every shipped main is built for: the five build_platform calls
// in src/build/build-binaries.sh and in the setup tool's build-binaries.sh, the Docker images being
// the first of them. Rule 9 asks the go command for each main's dependencies on every one, because
// a package outside the four modules may import differently on each.
// TestReleaseBuilds_TheRealReleaseBuildsSetProduction fails when either script's build_platform
// calls differ from this list as a set (#463).
var releaseTargets = []struct{ goos, goarch string }{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
}

// The owner values a package row may carry. Their meanings are in ARCHITECTURE.md; what matters
// here is that kernel is the only one that may not name an issue, and delete is the only one whose
// package must have no importer at all.
const (
	ownerKernel       = "kernel"
	ownerAuthserver   = "authserver"
	ownerAdminconsole = "adminconsole"
	ownerSplit        = "split"
	ownerDelete       = "delete"
)

type ownerRow struct {
	pkg   string
	owner string
	issue string
	line  int
}

type exceptionRow struct {
	from  string
	to    string
	issue string
	line  int
}

type foreignRow struct {
	module    string
	reachable bool
	clearedBy string
	line      int
}

// testFrameworkRow names a package rule 9 refuses in a shipped binary, together with every package
// under it.
type testFrameworkRow struct {
	pkg  string
	line int
}

type architectureTables struct {
	owners         []ownerRow
	exceptions     []exceptionRow
	foreign        []foreignRow
	testFrameworks []testFrameworkRow
	builtin        []builtinRow
}

// parseArchitectureDoc reads the five data tables. A malformed row is a finding rather than a
// parse failure, so one bad cell reports itself instead of silently shortening a table and turning
// every edge it covered into a violation.
func parseArchitectureDoc(doc string) (architectureTables, []string) {
	var tables architectureTables
	var findings []string

	lines := strings.Split(doc, "\n")

	ownership, ok := refgraph.TableUnder(lines, ownershipHeading)
	if !ok {
		findings = append(findings, fmt.Sprintf("%s has no %q table", architectureDoc, ownershipHeading))
	}
	for _, row := range ownership {
		if len(row.Cells) != 3 {
			findings = append(findings, fmt.Sprintf("%s:%d: an ownership row needs 3 cells, found %d", architectureDoc, row.Line, len(row.Cells)))
			continue
		}
		tables.owners = append(tables.owners, ownerRow{pkg: row.Cells[0], owner: row.Cells[1], issue: row.Cells[2], line: row.Line})
	}

	exceptions, ok := refgraph.TableUnder(lines, exceptionHeading)
	if !ok {
		findings = append(findings, fmt.Sprintf("%s has no %q table", architectureDoc, exceptionHeading))
	}
	for _, row := range exceptions {
		if len(row.Cells) != 3 {
			findings = append(findings, fmt.Sprintf("%s:%d: an exception row needs 3 cells, found %d", architectureDoc, row.Line, len(row.Cells)))
			continue
		}
		tables.exceptions = append(tables.exceptions, exceptionRow{from: row.Cells[0], to: row.Cells[1], issue: row.Cells[2], line: row.Line})
	}

	foreign, ok := refgraph.TableUnder(lines, foreignHeading)
	if !ok {
		findings = append(findings, fmt.Sprintf("%s has no %q table", architectureDoc, foreignHeading))
	}
	for _, row := range foreign {
		if len(row.Cells) != 4 {
			findings = append(findings, fmt.Sprintf("%s:%d: a foreign-module row needs 4 cells, found %d", architectureDoc, row.Line, len(row.Cells)))
			continue
		}
		reachable, rErr := parseYesNo(row.Cells[2])
		if rErr != nil {
			findings = append(findings, fmt.Sprintf("%s:%d: the %q row's reachability is %q, which is neither yes nor no", architectureDoc, row.Line, row.Cells[0], row.Cells[2]))
			continue
		}
		tables.foreign = append(tables.foreign, foreignRow{module: row.Cells[0], reachable: reachable, clearedBy: row.Cells[3], line: row.Line})
	}

	frameworks, ok := refgraph.TableUnder(lines, testFrameworkHeading)
	if !ok {
		findings = append(findings, fmt.Sprintf("%s has no %q table", architectureDoc, testFrameworkHeading))
	}
	// The exception table may be empty, since an empty burn-down list is where it is meant to end.
	// This one empty is rule 9 refusing nothing, which passes every tree.
	if ok && len(frameworks) == 0 {
		findings = append(findings, fmt.Sprintf("%s has an empty %q table, so rule 9 refuses nothing", architectureDoc, testFrameworkHeading))
	}
	for _, row := range frameworks {
		if len(row.Cells) != 2 {
			findings = append(findings, fmt.Sprintf("%s:%d: a test-framework row needs 2 cells, found %d", architectureDoc, row.Line, len(row.Cells)))
			continue
		}
		tables.testFrameworks = append(tables.testFrameworks, testFrameworkRow{pkg: row.Cells[0], line: row.Line})
	}

	builtinRows, ok := refgraph.TableUnder(lines, builtinHeading)
	if !ok {
		findings = append(findings, fmt.Sprintf("%s has no %q table", architectureDoc, builtinHeading))
	}
	for _, row := range builtinRows {
		if len(row.Cells) != 3 {
			findings = append(findings, fmt.Sprintf("%s:%d: a built-in identifiers row needs 3 cells, found %d", architectureDoc, row.Line, len(row.Cells)))
			continue
		}
		tables.builtin = append(tables.builtin, builtinRow{symbol: row.Cells[0], justification: row.Cells[1], issue: row.Cells[2], line: row.Line})
	}

	return tables, findings
}

func parseYesNo(cell string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(cell)) {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	}
	return false, errs.Errorf("%q is neither yes nor no", cell)
}

// issueRef matches the "#332" form every issue cell uses.
var issueRef = regexp.MustCompile(`^#\d+$`)

// noIssue reports whether a cell means "no issue". The document writes an em dash; a hyphen and an
// empty cell are accepted because they mean the same thing to a reader and refusing them would be a
// finding about typography rather than about the tree.
func noIssue(cell string) bool {
	switch strings.TrimSpace(cell) {
	case "—", "–", "-", "":
		return true
	}
	return false
}

// edge is one package-level dependency, named the way the exception table names it: the source is
// either a top-level core package or a module directory, and the target is always a top-level core
// package.
type edge struct {
	from string
	to   string
}

// checkArchitecture runs rules 1 to 6 and 9 over the graph and returns their findings. external holds the imports of the packages outside the four modules that the shipped
// mains reach, as compiledClosure reads them; rule 9 walks through them, and nil stops its walk at
// the edge of the four modules.
func checkArchitecture(tables architectureTables, graph *refgraph.ImportGraph, external map[string][]string) []string {
	findings := checkTableHygiene(tables, graph)

	owners := map[string]string{}
	for _, row := range tables.owners {
		owners[row.pkg] = row.owner
	}

	violations := map[edge]bool{}
	for e := range kernelPurityViolations(owners, graph) {
		violations[e] = true
	}
	for e := range processIsolationViolations(owners, graph) {
		violations[e] = true
	}

	findings = append(findings, checkModuleDirection(graph)...)
	findings = append(findings, checkDeadPackages(tables, graph)...)
	findings = append(findings, checkForeignClosure(tables, graph)...)
	findings = append(findings, checkTestCode(tables, graph, external)...)
	findings = append(findings, reconcileExceptions(tables, violations)...)

	return findings
}

// checkModuleDirection holds the one rule with no exceptions: core depends on neither process, and
// the two processes never link each other's code. Test files are checked too, because a test that
// imports across a forbidden edge still proves the two modules are coupled.
func checkModuleDirection(graph *refgraph.ImportGraph) []string {
	var findings []string
	for _, kind := range []string{"production", "test"} {
		source := graph.Prod
		if kind == "test" {
			source = graph.Test
		}
		for pkg, imports := range source {
			from := graph.ModuleDir(pkg)
			for _, imported := range imports {
				to := graph.ModuleDir(imported)
				if to == "" || to == from {
					continue
				}
				if to == "core" && from != "core" {
					continue
				}
				findings = append(findings, fmt.Sprintf(
					"module direction: %s (%s) imports %s; %s may not import %s",
					pkg, kind, imported, from, to))
			}
		}
	}
	return findings
}

// kernelPurityViolations reports every edge from a kernel package into a package owned by one of
// the processes or already marked for deletion. A split package is not a target: until its issue
// draws the line, there is nothing at package granularity to check.
func kernelPurityViolations(owners map[string]string, g *refgraph.ImportGraph) map[edge]bool {
	violations := map[edge]bool{}
	for pkg, imports := range g.Prod {
		from := g.TopCorePackage(pkg)
		if from == "" || owners[from] != ownerKernel {
			continue
		}
		for _, imported := range imports {
			to := g.TopCorePackage(imported)
			if to == "" || to == from {
				continue
			}
			switch owners[to] {
			case ownerAuthserver, ownerAdminconsole, ownerDelete:
				violations[edge{from: g.RelPath(pkg), to: g.RelPath(imported)}] = true
			}
		}
	}
	return violations
}

// processIsolationViolations reports every edge from one module into a core package owned by the
// other, and every edge from the setup wizard into a core package owned by either. The wizard ships
// as a standalone binary, so a package it pulls in is a package a user downloads.
func processIsolationViolations(owners map[string]string, g *refgraph.ImportGraph) map[edge]bool {
	forbidden := map[string][]string{
		"adminconsole":       {ownerAuthserver},
		"authserver":         {ownerAdminconsole},
		"cmd/goiabada-setup": {ownerAuthserver, ownerAdminconsole},
	}

	violations := map[edge]bool{}
	for pkg, imports := range g.Prod {
		from := g.ModuleDir(pkg)
		refused, ok := forbidden[from]
		if !ok {
			continue
		}
		for _, imported := range imports {
			to := g.TopCorePackage(imported)
			if to == "" {
				continue
			}
			for _, owner := range refused {
				if owners[to] == owner {
					violations[edge{from: g.RelPath(pkg), to: g.RelPath(imported)}] = true
				}
			}
		}
	}
	return violations
}

// checkDeadPackages holds a delete row to its claim. A package with an importer is not dead, and
// the row rather than the importer is what is wrong.
func checkDeadPackages(tables architectureTables, graph *refgraph.ImportGraph) []string {
	var findings []string
	for _, row := range tables.owners {
		if row.owner != ownerDelete {
			continue
		}
		for _, kind := range []string{"production", "test"} {
			source := graph.Prod
			if kind == "test" {
				source = graph.Test
			}
			for pkg, imports := range source {
				for _, imported := range imports {
					if graph.TopCorePackage(imported) != row.pkg {
						continue
					}
					findings = append(findings, fmt.Sprintf(
						"dead package: %s:%d records %s as %s, but %s imports %s (%s)",
						architectureDoc, row.line, row.pkg, ownerDelete, pkg, imported, kind))
				}
			}
		}
	}
	return findings
}

// checkForeignClosure asserts the declared reachability of each third-party module against the real
// transitive closure of the admin console's production packages. This is the rule that measures the
// harm the epic exists to remove: the admin console opens no database, and every driver in its
// binary arrived through core.
func checkForeignClosure(tables architectureTables, graph *refgraph.ImportGraph) []string {
	reachable := foreignClosure(graph, "adminconsole")

	var findings []string
	for _, row := range tables.foreign {
		via, hit := reachable[row.module]
		switch {
		case hit && !row.reachable:
			findings = append(findings, fmt.Sprintf(
				"foreign closure: %s:%d records %s as unreachable from the admin console, but %s imports it",
				architectureDoc, row.line, row.module, via))
		case !hit && row.reachable:
			findings = append(findings, fmt.Sprintf(
				"foreign closure: %s:%d records %s as reachable from the admin console, but nothing reaches it any more; delete the row (%s)",
				architectureDoc, row.line, row.module, row.clearedBy))
		}
	}
	return findings
}

// foreignClosure walks the module's production packages over first-party edges and reports, for
// every third-party import path found anywhere in that closure, one package that imports it. The
// importer is carried so a failure can name where the dependency entered rather than only that it
// did.
func foreignClosure(graph *refgraph.ImportGraph, moduleDir string) map[string]string {
	seen := map[string]bool{}
	var stack []string
	for pkg := range graph.Prod {
		if graph.ModuleDir(pkg) == moduleDir {
			stack = append(stack, pkg)
		}
	}

	found := map[string]string{}
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
				continue
			}
			if isStdlib(imported) {
				continue
			}
			// Longest declared prefix wins, so github.com/jackc/pgx/v5/stdlib is recorded against
			// the module that ships it rather than as a module of its own.
			if existing, ok := found[imported]; !ok || pkg < existing {
				found[imported] = pkg
			}
		}
	}

	// Collapse import paths onto the module prefixes the table declares.
	return foreignByPrefix(found)
}

// foreignByPrefix lets a table row name a module prefix and match every package under it.
func foreignByPrefix(found map[string]string) map[string]string {
	out := map[string]string{}
	for path, importer := range found {
		out[path] = importer
		for i := len(path) - 1; i > 0; i-- {
			if path[i] != '/' {
				continue
			}
			prefix := path[:i]
			if existing, ok := out[prefix]; !ok || importer < existing {
				out[prefix] = importer
			}
		}
	}
	return out
}

// isStdlib reports whether an import path is part of the standard library, which is decided by the
// absence of a dot in its first segment. That is the same rule the go command uses to tell a
// standard package from a module path.
func isStdlib(importPath string) bool {
	first, _, _ := strings.Cut(importPath, "/")
	return !strings.Contains(first, ".")
}

// checkTestCode is rule 9: no shipped main links a package the test-framework table refuses. Test
// code is defined by the frameworks rather than by where a helper lives or what it is called, so the
// rule needs no list of first-party helpers: a helper reaching testing or testify is caught through
// the framework behind it, the moment it gains one (#331).
//
// The walk starts at each shipped main rather than at every production package of its module, which
// is the difference from rule 5. The graph counts core/guard's untagged files as production, so a
// module-wide walk would find testing in core itself; what ships is what a main reaches.
//
// The walk does not stop at the edge of the four modules: past it, it follows external, the
// imports the go command reports for every third-party and standard package a shipped main
// reaches, so a framework that a dependency imports is refused like one a first-party helper does.
func checkTestCode(tables architectureTables, graph *refgraph.ImportGraph, external map[string][]string) []string {
	var findings []string
	for _, dir := range shippedMains {
		main, ok := shippedMainPackage(graph, dir)
		if !ok {
			// Reported by the reporting half, which knows whether any main was found at all.
			continue
		}
		reached := testFrameworksReached(graph, external, main, tables.testFrameworks)
		for i, row := range tables.testFrameworks {
			chain, hit := reached[i]
			if !hit {
				continue
			}
			rel := make([]string, 0, len(chain))
			for _, pkg := range chain {
				rel = append(rel, graph.RelPath(pkg))
			}
			findings = append(findings, fmt.Sprintf(
				"test code: %s links %s, which %s:%d refuses in a shipped binary: %s",
				dir, chain[len(chain)-1], architectureDoc, row.line, strings.Join(rel, " -> ")))
		}
	}
	return findings
}

// shippedMainPackage returns the import path of the shipped main at dir, and whether any production
// Go file sits there.
func shippedMainPackage(graph *refgraph.ImportGraph, dir string) (string, bool) {
	main, ok := graph.ImportPath(dir)
	if !ok {
		return "", false
	}
	_, ok = graph.Prod[main]
	return main, ok
}

// testFrameworksReached walks main's production closure breadth first and returns, per row of the
// test-framework table, the chain of packages from main to the first refused import the walk met:
// the main, each package between, and the refused path itself. A first-party package's imports are
// the graph's, read from source with every tag but production free; any other package's are
// external's. Breadth first makes that chain a shortest one, which is the edge a reader has to cut,
// and sorted import lists make it the same chain on every run.
func testFrameworksReached(graph *refgraph.ImportGraph, external map[string][]string, main string, rows []testFrameworkRow) map[int][]string {
	parent := map[string]string{main: ""}
	queue := []string{main}
	found := map[int][]string{}

	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		imports := graph.Prod[pkg]
		if graph.ModuleDir(pkg) == "" {
			imports = external[pkg]
		}
		for _, imported := range imports {
			for i, row := range rows {
				if _, done := found[i]; done || !underPath(imported, row.pkg) {
					continue
				}
				found[i] = append(chainTo(parent, pkg), imported)
			}
			if _, seen := parent[imported]; seen {
				continue
			}
			parent[imported] = pkg
			queue = append(queue, imported)
		}
	}
	return found
}

// compiledClosure asks the go command for the production dependencies of every shipped main on
// every release target, and returns the imports of each package outside the four modules, merged
// across mains and targets. The source graph cannot supply those: it reads the four modules and
// nothing else, so without this a test framework that a third-party dependency imports would be
// linked into a release with nothing going red. First-party packages are left to the graph, which
// reads them with every tag but production free rather than one target at a time.
//
// A package the go command cannot load is a finding rather than a skipped package, since rule 9
// cannot see what it imports; on this tree that is a dependency missing from the module cache or a
// build broken for one target, either of which the release would meet too. A main missing from
// the graph is skipped here, because the reporting half already accounts for it.
func compiledClosure(root string, graph *refgraph.ImportGraph) (map[string][]string, []string, error) {
	edges := map[string]map[string]bool{}
	reported := map[string]bool{}
	var findings []string

	for _, dir := range shippedMains {
		if _, ok := shippedMainPackage(graph, dir); !ok {
			continue
		}
		for _, target := range releaseTargets {
			pkgs, err := goListDeps(filepath.Join(root, filepath.FromSlash(dir)), target.goos, target.goarch)
			if err != nil {
				return nil, nil, errs.Wrapf(err, "%s on %s/%s", dir, target.goos, target.goarch)
			}
			for _, p := range pkgs {
				if p.Error != nil {
					key := dir + " " + p.ImportPath
					if !reported[key] {
						reported[key] = true
						findings = append(findings, fmt.Sprintf(
							"test code: the go command cannot load %s for %s on %s/%s, so rule 9 cannot see what it imports: %s",
							p.ImportPath, dir, target.goos, target.goarch, strings.TrimSpace(p.Error.Err)))
					}
					continue
				}
				if graph.ModuleDir(p.ImportPath) != "" {
					continue
				}
				if edges[p.ImportPath] == nil {
					edges[p.ImportPath] = map[string]bool{}
				}
				for _, imported := range p.Imports {
					edges[p.ImportPath][imported] = true
				}
			}
		}
	}
	return refgraph.Flatten(edges), findings, nil
}

// listedPackage is the part of `go list -json` output compiledClosure reads.
type listedPackage struct {
	ImportPath string
	Imports    []string
	Error      *struct{ Err string }
}

// goListDeps runs `go list -e -deps` over the main package in dir with the release builds' tag and
// cgo setting, for one target. -e makes a package that fails to load a record carrying its error
// rather than the end of the listing; -mod=readonly keeps the listing from editing a go.mod.
func goListDeps(dir, goos, goarch string) ([]listedPackage, error) {
	cmd := exec.Command("go", "list", "-e", "-deps", "-tags", "production", "-json=ImportPath,Imports,Error", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0", "GOFLAGS=-mod=readonly", "GOWORK=off")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, errs.Wrapf(err, "go list: %s", strings.TrimSpace(stderr.String()))
	}

	var pkgs []listedPackage
	dec := json.NewDecoder(&stdout)
	for {
		var p listedPackage
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			return pkgs, nil
		}
		if err != nil {
			return nil, errs.Wrap(err, "decoding go list output")
		}
		pkgs = append(pkgs, p)
	}
}

// chainTo follows parent links from pkg back to the walk's start and returns them in walk order.
func chainTo(parent map[string]string, pkg string) []string {
	var chain []string
	for p := pkg; p != ""; p = parent[p] {
		chain = append(chain, p)
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// underPath reports whether importPath is root or a package under it. The boundary is a slash, so
// testing covers testing/fstest and not a package called testingx.
func underPath(importPath, root string) bool {
	return importPath == root || strings.HasPrefix(importPath, root+"/")
}

// reconcileExceptions is the burn-down. Every violation must be listed, and every listed exception
// must still be a violation: an exception that stopped matching anything is the signal that the
// issue which removed the edge forgot to remove its row.
func reconcileExceptions(tables architectureTables, violations map[edge]bool) []string {
	listed := map[edge]exceptionRow{}
	var findings []string

	for _, row := range tables.exceptions {
		e := edge{from: row.from, to: row.to}
		if _, duplicate := listed[e]; duplicate {
			findings = append(findings, fmt.Sprintf(
				"table hygiene: %s:%d lists the exception %s -> %s twice",
				architectureDoc, row.line, row.from, row.to))
			continue
		}
		listed[e] = row
		if !issueRef.MatchString(row.issue) {
			findings = append(findings, fmt.Sprintf(
				"table hygiene: %s:%d: the exception %s -> %s names %q where an issue like #332 belongs; a temporary dependency with no issue is a waiver",
				architectureDoc, row.line, row.from, row.to, row.issue))
		}
		if _, still := violations[e]; !still {
			findings = append(findings, fmt.Sprintf(
				"table hygiene: %s:%d lists %s -> %s as a temporary exception, but that edge no longer exists; delete the row (%s)",
				architectureDoc, row.line, row.from, row.to, row.issue))
		}
	}

	for e := range violations {
		if _, ok := listed[e]; ok {
			continue
		}
		rule := "kernel purity"
		if !strings.HasPrefix(e.from, "core/") {
			rule = "process isolation"
		}
		findings = append(findings, fmt.Sprintf(
			"%s: %s imports %s, and %s lists no exception for that edge; move the code or add a row naming the issue that will",
			rule, e.from, e.to, architectureDoc))
	}

	return findings
}

// checkTableHygiene holds the ownership table to the tree: one row per top-level core package,
// every owner a value the rules understand, and an issue on exactly the rows that need one. The
// completeness half is what makes a new core package a decision rather than a default.
func checkTableHygiene(tables architectureTables, graph *refgraph.ImportGraph) []string {
	var findings []string

	seen := map[string]int{}
	for _, row := range tables.owners {
		if first, duplicate := seen[row.pkg]; duplicate {
			findings = append(findings, fmt.Sprintf(
				"table hygiene: %s:%d gives %s a second ownership row; the first is at line %d",
				architectureDoc, row.line, row.pkg, first))
			continue
		}
		seen[row.pkg] = row.line

		switch row.owner {
		case ownerKernel:
			if !noIssue(row.issue) {
				findings = append(findings, fmt.Sprintf(
					"table hygiene: %s:%d gives kernel package %s the issue %s; a package that is not moving has no issue",
					architectureDoc, row.line, row.pkg, row.issue))
			}
		case ownerAuthserver, ownerAdminconsole, ownerSplit, ownerDelete:
			if !issueRef.MatchString(row.issue) {
				findings = append(findings, fmt.Sprintf(
					"table hygiene: %s:%d says %s becomes %s but names %q where an issue like #332 belongs",
					architectureDoc, row.line, row.pkg, row.owner, row.issue))
			}
		default:
			findings = append(findings, fmt.Sprintf(
				"table hygiene: %s:%d gives %s the owner %q, which is none of %s, %s, %s, %s, %s",
				architectureDoc, row.line, row.pkg, row.owner,
				ownerKernel, ownerAuthserver, ownerAdminconsole, ownerSplit, ownerDelete))
		}
	}

	onDisk := map[string]bool{}
	for _, pkg := range graph.CorePkgs {
		onDisk[pkg] = true
		if _, ok := seen[pkg]; !ok {
			findings = append(findings, fmt.Sprintf(
				"table hygiene: %s holds no ownership row for %s; every top-level core package needs one, so that adding a package is a decision about where it belongs",
				architectureDoc, pkg))
		}
	}
	for pkg, line := range seen {
		if !onDisk[pkg] {
			findings = append(findings, fmt.Sprintf(
				"table hygiene: %s:%d records ownership for %s, which holds no production Go file; delete the row",
				architectureDoc, line, pkg))
		}
	}

	frameworks := map[string]int{}
	for _, row := range tables.testFrameworks {
		if first, duplicate := frameworks[row.pkg]; duplicate {
			findings = append(findings, fmt.Sprintf(
				"table hygiene: %s:%d lists the test framework %s twice; the first is at line %d",
				architectureDoc, row.line, row.pkg, first))
			continue
		}
		frameworks[row.pkg] = row.line
	}

	for _, row := range tables.foreign {
		if row.reachable && !issueRef.MatchString(row.clearedBy) {
			findings = append(findings, fmt.Sprintf(
				"table hygiene: %s:%d says %s is reachable from the admin console but names %q where the issue that clears it belongs",
				architectureDoc, row.line, row.module, row.clearedBy))
		}
	}

	return findings
}
