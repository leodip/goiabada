package testutil

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/internal/refgraph"
)

// AssertArchitecture holds the repository's module and package ownership rules to the tree they
// describe. The rules themselves are not written here: they are the four tables in
// ARCHITECTURE.md at the repository root, which this function parses and then checks against the
// real tree — three against the import graph, and the fourth against the production references to
// core/constants. That file names each rule and carries the reasoning; this one decides.
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

	census, err := buildConstantsCensus(root, graph)
	if err != nil {
		r.Fatalf("reading the %s census under %s: %v", coreConstantsPkg, root, err)
	}
	// The same silent failure as the empty graph, one table down. A census that read no
	// declaration satisfies "every symbol has a row" for nothing at all, and a census that found no
	// reference would rest every justification on an empty set.
	if len(census.declared) == 0 {
		r.Fatalf("found no exported declarations in %s under %s", coreConstantsPkg, root)
	}
	if len(census.refs) == 0 {
		r.Fatalf("found no production reference to any %s symbol under %s", coreConstantsPkg, root)
	}

	findings = append(findings, checkArchitecture(tables, graph)...)
	findings = append(findings, checkConstantsOwnership(tables, graph, census)...)

	sort.Strings(findings)
	for _, f := range findings {
		r.Errorf("%s", f)
	}
}

// architectureDoc is the file holding the rules, relative to the repository root.
const architectureDoc = "ARCHITECTURE.md"

// The headings whose tables are data. Each is the deepest heading of its section, so the
// prose above it is free to change without touching the parser. The fourth, constantsHeading,
// is declared beside the checks that read it in constants_ownership.go.
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
	constants  []constantsRow
}

// parseArchitectureDoc reads the three data tables. A malformed row is a finding rather than a
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

	constants, ok := refgraph.TableUnder(lines, constantsHeading)
	if !ok {
		findings = append(findings, fmt.Sprintf("%s has no %q table", architectureDoc, constantsHeading))
	}
	for _, row := range constants {
		if len(row.Cells) != 3 {
			findings = append(findings, fmt.Sprintf("%s:%d: a core constants row needs 3 cells, found %d", architectureDoc, row.Line, len(row.Cells)))
			continue
		}
		tables.constants = append(tables.constants, constantsRow{symbol: row.Cells[0], justification: row.Cells[1], issue: row.Cells[2], line: row.Line})
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

func checkArchitecture(tables architectureTables, graph *refgraph.ImportGraph) []string {
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

	for _, row := range tables.foreign {
		if row.reachable && !issueRef.MatchString(row.clearedBy) {
			findings = append(findings, fmt.Sprintf(
				"table hygiene: %s:%d says %s is reachable from the admin console but names %q where the issue that clears it belongs",
				architectureDoc, row.line, row.module, row.clearedBy))
		}
	}

	return findings
}
