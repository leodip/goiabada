package testutil

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
)

// AssertArchitecture holds the repository's module and package ownership rules to the tree they
// describe. The rules themselves are not written here: they are the three tables in
// ARCHITECTURE.md at the repository root, which this function parses and then checks against the
// real import graph. That file names each rule and carries the reasoning; this one decides.
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

	root := SourceRoot(t)

	doc, err := os.ReadFile(filepath.Join(filepath.Dir(root), architectureDoc))
	if err != nil {
		t.Fatalf("reading %s: %v", architectureDoc, err)
	}

	tables, findings := parseArchitectureDoc(string(doc))

	graph, err := buildImportGraph(root)
	if err != nil {
		t.Fatalf("reading the import graph under %s: %v", root, err)
	}
	// A graph that somehow held no packages would satisfy every rule below, which is the one way a
	// guard like this fails silently in the direction that matters.
	if len(graph.prod) == 0 {
		t.Fatalf("found no production Go packages under %s", root)
	}

	findings = append(findings, checkArchitecture(tables, graph)...)

	sort.Strings(findings)
	for _, f := range findings {
		t.Error(f)
	}
}

// architectureDoc is the file holding the rules, relative to the repository root.
const architectureDoc = "ARCHITECTURE.md"

// The three headings whose tables are data. Each is the deepest heading of its section, so the
// prose above it is free to change without touching the parser.
const (
	ownershipHeading = "### Package ownership"
	exceptionHeading = "### Temporary exceptions"
	foreignHeading   = "### Foreign modules"
)

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

// moduleDirs are the four go.mod directories, relative to the source root, in the order a reader
// expects them. gofmt.go's modules list identifies the source root while ascending; this one is
// what the graph resolves import paths against, and the two are deliberately the same set.
var moduleDirs = []string{"core", "authserver", "adminconsole", "cmd/goiabada-setup"}

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

type architectureTables struct {
	owners     []ownerRow
	exceptions []exceptionRow
	foreign    []foreignRow
}

// importGraph is the tree as the compiler sees it: one entry per package directory holding at least
// one Go file, mapping its import path to the paths it imports. Production and test files are kept
// apart because the rules treat them differently — a test may import a mock or a fixture from
// anywhere, and holding test code to the production graph would make core/testutil unusable from
// the very tiers that call this guard.
type importGraph struct {
	prod     map[string][]string
	test     map[string][]string
	modules  map[string]string // directory relative to the source root -> module import path
	corePkgs []string          // top-level core packages on disk, as "core/<name>"
}

// parseArchitectureDoc reads the three data tables. A malformed row is a finding rather than a
// parse failure, so one bad cell reports itself instead of silently shortening a table and turning
// every edge it covered into a violation.
func parseArchitectureDoc(doc string) (architectureTables, []string) {
	var tables architectureTables
	var findings []string

	lines := strings.Split(doc, "\n")

	ownership, ok := tableUnder(lines, ownershipHeading)
	if !ok {
		findings = append(findings, fmt.Sprintf("%s has no %q table", architectureDoc, ownershipHeading))
	}
	for _, row := range ownership {
		if len(row.cells) != 3 {
			findings = append(findings, fmt.Sprintf("%s:%d: an ownership row needs 3 cells, found %d", architectureDoc, row.line, len(row.cells)))
			continue
		}
		tables.owners = append(tables.owners, ownerRow{pkg: row.cells[0], owner: row.cells[1], issue: row.cells[2], line: row.line})
	}

	exceptions, ok := tableUnder(lines, exceptionHeading)
	if !ok {
		findings = append(findings, fmt.Sprintf("%s has no %q table", architectureDoc, exceptionHeading))
	}
	for _, row := range exceptions {
		if len(row.cells) != 3 {
			findings = append(findings, fmt.Sprintf("%s:%d: an exception row needs 3 cells, found %d", architectureDoc, row.line, len(row.cells)))
			continue
		}
		tables.exceptions = append(tables.exceptions, exceptionRow{from: row.cells[0], to: row.cells[1], issue: row.cells[2], line: row.line})
	}

	foreign, ok := tableUnder(lines, foreignHeading)
	if !ok {
		findings = append(findings, fmt.Sprintf("%s has no %q table", architectureDoc, foreignHeading))
	}
	for _, row := range foreign {
		if len(row.cells) != 4 {
			findings = append(findings, fmt.Sprintf("%s:%d: a foreign-module row needs 4 cells, found %d", architectureDoc, row.line, len(row.cells)))
			continue
		}
		reachable, rErr := parseYesNo(row.cells[2])
		if rErr != nil {
			findings = append(findings, fmt.Sprintf("%s:%d: the %q row's reachability is %q, which is neither yes nor no", architectureDoc, row.line, row.cells[0], row.cells[2]))
			continue
		}
		tables.foreign = append(tables.foreign, foreignRow{module: row.cells[0], reachable: reachable, clearedBy: row.cells[3], line: row.line})
	}

	return tables, findings
}

type docRow struct {
	cells []string
	line  int
}

// tableUnder returns the body rows of the first markdown table following the heading, with the
// header and its separator dropped. The table ends at the first line that is not a table row, so
// the prose after it is never read as data.
func tableUnder(lines []string, heading string) ([]docRow, bool) {
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == heading {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil, false
	}

	var rows []docRow
	seen := 0
	for i := start; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" {
			if seen > 0 {
				break
			}
			continue
		}
		if !strings.HasPrefix(trimmed, "|") {
			break
		}
		seen++
		// The header row and the |---|---| separator under it carry no data.
		if seen <= 2 {
			continue
		}
		rows = append(rows, docRow{cells: splitRow(trimmed), line: i + 1})
	}
	return rows, true
}

// splitRow turns "| `core/api` | kernel | — |" into its three cells, with the pipes, the padding
// and the backticks removed. Backticks are stripped because every identifier in the document is
// written as code and none of them contain one.
func splitRow(line string) []string {
	trimmed := strings.Trim(strings.TrimSpace(line), "|")
	parts := strings.Split(trimmed, "|")
	cells := make([]string, 0, len(parts))
	for _, p := range parts {
		cells = append(cells, strings.TrimSpace(strings.ReplaceAll(p, "`", "")))
	}
	return cells
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

// buildImportGraph parses every Go file under root for its imports alone and groups them by package
// directory. Imports are read from the AST rather than matched in the text, so an import path
// inside a comment or a string literal is not an edge and an aliased import still is one.
func buildImportGraph(root string) (*importGraph, error) {
	graph := &importGraph{
		prod:    map[string][]string{},
		test:    map[string][]string{},
		modules: map[string]string{},
	}

	for _, dir := range moduleDirs {
		path, err := modulePath(filepath.Join(root, filepath.FromSlash(dir), "go.mod"))
		if err != nil {
			return nil, err
		}
		graph.modules[dir] = path
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

		pkg, ok := graph.importPath(filepath.ToSlash(filepath.Dir(rel)))
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
		if !isTest && exemptByBuildConstraint(file, fset) {
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

	graph.prod = flatten(prod)
	graph.test = flatten(test)

	graph.corePkgs, err = topLevelCorePackages(root)
	if err != nil {
		return nil, err
	}

	return graph, nil
}

func flatten(in map[string]map[string]bool) map[string][]string {
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

// modulePath reads the module line out of a go.mod. Reading it rather than hard-coding the four
// paths means a module renamed in go.mod is a failure here rather than a graph that silently stops
// recognising half the tree as first-party.
func modulePath(goMod string) (string, error) {
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

// importPath turns a directory relative to the source root into the import path the compiler gives
// it, and reports whether the directory belongs to one of the four modules. The longest module
// directory wins, so cmd/goiabada-setup is not read as a subdirectory of anything.
func (g *importGraph) importPath(dir string) (string, bool) {
	best := ""
	for moduleDir := range g.modules {
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
	path := g.modules[best]
	if dir != best {
		path += "/" + strings.TrimPrefix(dir, best+"/")
	}
	return path, true
}

// moduleDir returns the module directory an import path belongs to, or "" when the path is not
// first-party.
func (g *importGraph) moduleDir(importPath string) string {
	best, bestLen := "", -1
	for dir, path := range g.modules {
		if importPath != path && !strings.HasPrefix(importPath, path+"/") {
			continue
		}
		if len(path) > bestLen {
			best, bestLen = dir, len(path)
		}
	}
	return best
}

// relPath returns the import path as a directory relative to the source root, which is how the
// exception table names both ends of an edge. An exception is granted to the package that holds the
// import, never to its module or to its parent: guidance point 4 of #332 asks for exact package
// edges, and a module-wide grant would let a second package acquire the same dependency in silence.
func (g *importGraph) relPath(importPath string) string {
	dir := g.moduleDir(importPath)
	if dir == "" {
		return importPath
	}
	module := g.modules[dir]
	if importPath == module {
		return dir
	}
	return dir + "/" + strings.TrimPrefix(importPath, module+"/")
}

// topCorePackage returns the top-level core package an import path belongs to, as "core/<name>", or
// "" when the path is not under core. Ownership is recorded per top-level package because that is
// the granularity the epic moves things at.
func (g *importGraph) topCorePackage(importPath string) string {
	corePath := g.modules["core"]
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

// edge is one package-level dependency, named the way the exception table names it: the source is
// either a top-level core package or a module directory, and the target is always a top-level core
// package.
type edge struct {
	from string
	to   string
}

func checkArchitecture(tables architectureTables, graph *importGraph) []string {
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
	findings = append(findings, reconcileExceptions(tables, violations)...)

	return findings
}

// checkModuleDirection holds the one rule with no exceptions: core depends on neither process, and
// the two processes never link each other's code. Test files are checked too, because a test that
// imports across a forbidden edge still proves the two modules are coupled.
func checkModuleDirection(graph *importGraph) []string {
	var findings []string
	for _, kind := range []string{"production", "test"} {
		source := graph.prod
		if kind == "test" {
			source = graph.test
		}
		for pkg, imports := range source {
			from := graph.moduleDir(pkg)
			for _, imported := range imports {
				to := graph.moduleDir(imported)
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
func kernelPurityViolations(owners map[string]string, g *importGraph) map[edge]bool {
	violations := map[edge]bool{}
	for pkg, imports := range g.prod {
		from := g.topCorePackage(pkg)
		if from == "" || owners[from] != ownerKernel {
			continue
		}
		for _, imported := range imports {
			to := g.topCorePackage(imported)
			if to == "" || to == from {
				continue
			}
			switch owners[to] {
			case ownerAuthserver, ownerAdminconsole, ownerDelete:
				violations[edge{from: g.relPath(pkg), to: g.relPath(imported)}] = true
			}
		}
	}
	return violations
}

// processIsolationViolations reports every edge from one module into a core package owned by the
// other, and every edge from the setup wizard into a core package owned by either. The wizard ships
// as a standalone binary, so a package it pulls in is a package a user downloads.
func processIsolationViolations(owners map[string]string, g *importGraph) map[edge]bool {
	forbidden := map[string][]string{
		"adminconsole":       {ownerAuthserver},
		"authserver":         {ownerAdminconsole},
		"cmd/goiabada-setup": {ownerAuthserver, ownerAdminconsole},
	}

	violations := map[edge]bool{}
	for pkg, imports := range g.prod {
		from := g.moduleDir(pkg)
		refused, ok := forbidden[from]
		if !ok {
			continue
		}
		for _, imported := range imports {
			to := g.topCorePackage(imported)
			if to == "" {
				continue
			}
			for _, owner := range refused {
				if owners[to] == owner {
					violations[edge{from: g.relPath(pkg), to: g.relPath(imported)}] = true
				}
			}
		}
	}
	return violations
}

// checkDeadPackages holds a delete row to its claim. A package with an importer is not dead, and
// the row rather than the importer is what is wrong.
func checkDeadPackages(tables architectureTables, graph *importGraph) []string {
	var findings []string
	for _, row := range tables.owners {
		if row.owner != ownerDelete {
			continue
		}
		for _, kind := range []string{"production", "test"} {
			source := graph.prod
			if kind == "test" {
				source = graph.test
			}
			for pkg, imports := range source {
				for _, imported := range imports {
					if graph.topCorePackage(imported) != row.pkg {
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
func checkForeignClosure(tables architectureTables, graph *importGraph) []string {
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
func foreignClosure(graph *importGraph, moduleDir string) map[string]string {
	seen := map[string]bool{}
	var stack []string
	for pkg := range graph.prod {
		if graph.moduleDir(pkg) == moduleDir {
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
		for _, imported := range graph.prod[pkg] {
			if graph.moduleDir(imported) != "" {
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
func checkTableHygiene(tables architectureTables, graph *importGraph) []string {
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
	for _, pkg := range graph.corePkgs {
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

	for _, row := range tables.foreign {
		if row.reachable && !issueRef.MatchString(row.clearedBy) {
			findings = append(findings, fmt.Sprintf(
				"table hygiene: %s:%d says %s is reachable from the admin console but names %q where the issue that clears it belongs",
				architectureDoc, row.line, row.module, row.clearedBy))
		}
	}

	return findings
}
