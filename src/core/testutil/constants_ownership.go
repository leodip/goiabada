package testutil

import (
	"bytes"
	"fmt"
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

// The fourth ARCHITECTURE.md table: one row per symbol surviving in core/constants, naming why it
// is there. It is checked here, beside the three import tables, because it answers the same
// question at a finer grain — the package ownership table can only say "split", and the line a
// split runs along is drawn per symbol.
//
// The three import rules cannot see this at all. A constant is a string, so an auth-server-only
// name sitting in core costs nothing at compile time and breaks no rule: core/constants reached
// 139 symbols exactly that way, one reasonable-looking declaration at a time, until 108 of them
// were named by a single process. Nothing would have gone red at any point (#351).
//
// The check runs in both directions, like the others. A symbol with no row fails, so adding one to
// core is a decision rather than a default; a row for a symbol that has moved fails, so the table
// cannot outlive what it describes; and a row claiming less than the tree supports fails, so the
// escape hatch stays the last resort rather than the easy answer.
const constantsHeading = "### Core constants ownership"

// The justification a row may carry, strongest first. A row states the strongest claim the tree
// backs, which is what keeps contract honest: it is reachable only when none of the other three
// holds, so writing it is a claim a reviewer can argue with rather than a shrug.
const (
	// justificationKernel: a kernel core package references it in production, so rule 2 forbids it
	// leaving whatever the applications do.
	justificationKernel = "kernel"
	// justificationBothApps: both applications reference it in production.
	justificationBothApps = "both-apps"
	// justificationMoving: the only core packages referencing it are ones on their way out of core,
	// so the answer expires with them. The issue cell names the move that ends it.
	justificationMoving = "moving"
	// justificationContract: none of the above, but it is an intentionally stable cross-process
	// value. Nothing can check this, which is exactly why somebody has to write the word.
	justificationContract = "contract"
)

// coreConstantsPkg is the package the table governs, as a directory relative to the source root.
const coreConstantsPkg = "core/constants"

type constantsRow struct {
	symbol        string
	justification string
	issue         string
	line          int
}

// constantsCensus is what the tree says, against which the table is checked: every exported symbol
// core/constants declares, and for each, the packages naming it in production.
type constantsCensus struct {
	declared []string
	refs     map[string][]string // symbol -> import paths of the packages referencing it
}

// buildConstantsCensus reads the declarations, then the references to them.
//
// References are read from the AST, so a symbol named in a comment or a string literal is not a
// reference and an aliased import still is one — which this change made load-bearing, since the
// files naming both packages import core's as coreconstants. Only files whose text carries the
// import path are parsed, which keeps a second full-body walk of the tree off every unit tier: a
// file not containing the path cannot import the package, so it cannot name a symbol from it.
//
// Production files only, because that is what the justifications are about. A test may name
// anything it likes from anywhere, exactly as rules 2 and 3 allow.
//
// ceiling: a reference is a selector on the identifier the import binds, resolved by name within
// the file. A package-level declaration shadowing that name is caught, because the parser resolves
// it; a local variable inside a function shadowing it would be read as the package. Nothing in this
// tree does that, and closing it means type-checking every package rather than parsing it. Revisit
// if a row ever rests on a reference that turns out to be a false one; go/types object identity is
// the next shape, as AssertNoDeadInterfaces already uses for one package at a time (#351).
func buildConstantsCensus(root string, graph *importGraph) (*constantsCensus, error) {
	coreModule, ok := graph.modules["core"]
	if !ok {
		return nil, errs.Errorf("the import graph knows no core module")
	}
	importPath := coreModule + "/constants"

	pkgDir := filepath.Join(root, filepath.FromSlash(coreConstantsPkg))
	declared, err := exportedDeclarations(pkgDir)
	if err != nil {
		return nil, err
	}
	pkgName := declaredPackageName(pkgDir)

	refs := map[string]map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return errs.Wrapf(relErr, "relating %s to %s", path, root)
		}
		dir := filepath.ToSlash(filepath.Dir(rel))
		if dir == coreConstantsPkg {
			// A symbol named by its own package proves nothing about who consumes it.
			return nil
		}
		pkg, known := graph.importPath(dir)
		if !known {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return errs.Wrapf(readErr, "reading %s", path)
		}
		if !bytes.Contains(content, []byte(importPath)) {
			return nil
		}

		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, path, content, parser.ParseComments)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns, and reporting it
			// here would send the reader to the wrong place.
			return nil
		}
		if exemptByBuildConstraint(file, fset) {
			return nil
		}

		local, imports := localImportName(file, importPath, pkgName)
		if !imports {
			return nil
		}
		for _, symbol := range selectedNames(file, local) {
			if refs[symbol] == nil {
				refs[symbol] = map[string]bool{}
			}
			refs[symbol][pkg] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &constantsCensus{declared: declared, refs: flatten(refs)}, nil
}

// exportedDeclarations lists the exported constants, variables, types and functions a package's
// production files declare.
func exportedDeclarations(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, errs.Wrapf(err, "reading %s", dir)
	}

	var names []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, parser.ParseComments)
		if pErr != nil {
			return nil, errs.Wrapf(pErr, "parsing %s", entry.Name())
		}
		if exemptByBuildConstraint(file, fset) {
			continue
		}
		for _, decl := range file.Decls {
			names = append(names, exportedNames(decl)...)
		}
	}

	sort.Strings(names)
	return names, nil
}

// exportedNames returns the exported names one declaration introduces. A method is not one: it is
// reached through its receiver, which has a row of its own.
func exportedNames(decl ast.Decl) []string {
	var names []string
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Recv == nil && d.Name.IsExported() {
			names = append(names, d.Name.Name)
		}
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.ValueSpec:
				for _, name := range s.Names {
					if name.IsExported() {
						names = append(names, name.Name)
					}
				}
			case *ast.TypeSpec:
				if s.Name.IsExported() {
					names = append(names, s.Name.Name)
				}
			}
		}
	}
	return names
}

// declaredPackageName returns the package clause a directory's production files carry, or "" when
// none of them parses. It is what an unaliased import of that directory binds, and the two guards
// that read references by selector need it to know what to look for.
func declaredPackageName(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, parser.PackageClauseOnly)
		if pErr != nil {
			continue
		}
		return file.Name.Name
	}
	return ""
}

// localImportName returns the identifier a file binds an import path to. A blank or dot import
// binds no identifier a selector can name, so neither counts as a reference.
//
// declared is the package clause of the imported package, which is what Go binds when the import
// carries no alias -- the last segment of the path is only the usual spelling of it, not the rule.
// A caller that does not know the name passes "" and gets that usual spelling; the two differ
// exactly when a package is named for something other than its directory, and there every
// reference to it would otherwise be read as no reference at all. Final review round 3, finding 5.
func localImportName(file *ast.File, importPath, declared string) (string, bool) {
	for _, spec := range file.Imports {
		if spec.Path == nil || strings.Trim(spec.Path.Value, `"`) != importPath {
			continue
		}
		if spec.Name == nil {
			if declared != "" {
				return declared, true
			}
			return importPath[strings.LastIndex(importPath, "/")+1:], true
		}
		if spec.Name.Name == "_" || spec.Name.Name == "." {
			return "", false
		}
		return spec.Name.Name, true
	}
	return "", false
}

// selectedNames lists the exported symbols selected off the given identifier.
func selectedNames(file *ast.File, local string) []string {
	seen := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != local {
			return true
		}
		// A non-nil Obj means the parser resolved the name to a declaration in this file, so it is
		// something shadowing the import rather than the package.
		if ident.Obj != nil {
			return true
		}
		if sel.Sel.IsExported() {
			seen[sel.Sel.Name] = true
		}
		return true
	})

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// checkConstantsOwnership holds the table and the tree to each other, in both directions.
func checkConstantsOwnership(tables architectureTables, graph *importGraph, census *constantsCensus) []string {
	var findings []string

	owners := map[string]ownerRow{}
	for _, row := range tables.owners {
		owners[row.pkg] = row
	}

	rows := map[string]constantsRow{}
	for _, row := range tables.constants {
		if first, duplicate := rows[row.symbol]; duplicate {
			findings = append(findings, fmt.Sprintf(
				"core constants: %s:%d gives %s a second row; the first is at line %d",
				architectureDoc, row.line, row.symbol, first.line))
			continue
		}
		rows[row.symbol] = row
	}

	declared := map[string]bool{}
	for _, symbol := range census.declared {
		declared[symbol] = true
		if _, ok := rows[symbol]; !ok {
			findings = append(findings, fmt.Sprintf(
				"core constants: %s holds no row for %s, which %s declares; every symbol left in core says why it is there, so that leaving one behind is a decision rather than a default",
				architectureDoc, symbol, coreConstantsPkg))
		}
	}

	for _, row := range tables.constants {
		if !declared[row.symbol] {
			findings = append(findings, fmt.Sprintf(
				"core constants: %s:%d records %s, which %s no longer declares; delete the row",
				architectureDoc, row.line, row.symbol, coreConstantsPkg))
			continue
		}
		if rows[row.symbol].line != row.line {
			// Already reported as a duplicate; checking it twice would say the same thing twice.
			continue
		}
		findings = append(findings, checkConstantsRow(row, owners, graph, census.refs[row.symbol])...)
	}

	return findings
}

// symbolBacking is what the tree says about one symbol: which kernel packages name it, which
// applications name it, and which core packages on their way out of core name it.
type symbolBacking struct {
	kernelPkgs []string
	apps       map[string]bool
	movingPkgs []string
	// movingIssues are the "moves in" issues of those packages' ownership rows, which is what a
	// moving row has to name.
	movingIssues map[string]bool
}

// backingFor classifies every production reference to a symbol.
func backingFor(owners map[string]ownerRow, graph *importGraph, refs []string) symbolBacking {
	backing := symbolBacking{apps: map[string]bool{}, movingIssues: map[string]bool{}}

	for _, pkg := range refs {
		top := graph.topCorePackage(pkg)
		if top == "" {
			switch graph.moduleDir(pkg) {
			case "authserver":
				backing.apps["authserver"] = true
			case "adminconsole":
				backing.apps["adminconsole"] = true
			}
			continue
		}
		if top == coreConstantsPkg {
			continue
		}
		if owners[top].owner == ownerKernel {
			backing.kernelPkgs = append(backing.kernelPkgs, graph.relPath(pkg))
			continue
		}
		backing.movingPkgs = append(backing.movingPkgs, graph.relPath(pkg))
		backing.movingIssues[owners[top].issue] = true
	}

	sort.Strings(backing.kernelPkgs)
	sort.Strings(backing.movingPkgs)
	return backing
}

// checkConstantsRow holds one row to what the tree backs for its symbol.
func checkConstantsRow(row constantsRow, owners map[string]ownerRow, graph *importGraph, refs []string) []string {
	switch row.justification {
	case justificationKernel, justificationBothApps, justificationMoving, justificationContract:
	default:
		return []string{fmt.Sprintf(
			"core constants: %s:%d gives %s the justification %q, which is none of %s, %s, %s, %s",
			architectureDoc, row.line, row.symbol, row.justification,
			justificationKernel, justificationBothApps, justificationMoving, justificationContract)}
	}

	backing := backingFor(owners, graph, refs)
	want, because := strongestJustification(backing)
	if row.justification != want {
		return []string{fmt.Sprintf(
			"core constants: %s:%d records %s as %s, but the tree backs %s: %s; a row states the strongest claim that holds",
			architectureDoc, row.line, row.symbol, row.justification, want, because)}
	}

	if want != justificationMoving {
		if !noIssue(row.issue) {
			return []string{fmt.Sprintf(
				"core constants: %s:%d gives %s the issue %s; only a %s row names one, because it is the only justification that expires",
				architectureDoc, row.line, row.symbol, row.issue, justificationMoving)}
		}
		return nil
	}
	return checkMovingIssue(row, backing)
}

// strongestJustification reports the strongest claim the tree backs for a symbol, and the evidence
// for it, which the finding carries so a reader can check the answer rather than trust it.
func strongestJustification(backing symbolBacking) (string, string) {
	switch {
	case len(backing.kernelPkgs) > 0:
		return justificationKernel, strings.Join(backing.kernelPkgs, ", ") + " references it in production"
	case backing.apps["authserver"] && backing.apps["adminconsole"]:
		return justificationBothApps, "both applications reference it in production"
	case len(backing.movingPkgs) > 0:
		return justificationMoving, "in core only " + strings.Join(backing.movingPkgs, ", ") + " references it, and that is leaving core"
	case len(backing.apps) == 1:
		for app := range backing.apps {
			return justificationContract, "only " + app + " references it"
		}
	}
	return justificationContract, "no production package references it"
}

// checkMovingIssue holds a moving row's issue to the ownership rows of the packages pinning the
// symbol. That is what makes the row expire: when the named issue carries those packages out of
// core, nothing in core references the symbol, the row stops being backed, and the tier fails until
// somebody decides where the symbol belongs.
func checkMovingIssue(row constantsRow, backing symbolBacking) []string {
	if !issueRef.MatchString(row.issue) {
		return []string{fmt.Sprintf(
			"core constants: %s:%d records %s as %s but names %q where an issue like #359 belongs; a justification that expires has to say when",
			architectureDoc, row.line, row.symbol, justificationMoving, row.issue)}
	}
	if backing.movingIssues[row.issue] {
		return nil
	}

	expected := make([]string, 0, len(backing.movingIssues))
	for issue := range backing.movingIssues {
		expected = append(expected, issue)
	}
	sort.Strings(expected)
	return []string{fmt.Sprintf(
		"core constants: %s:%d says %s stops being core's in %s, but the packages pinning it (%s) move in %s; the row expires with them or not at all",
		architectureDoc, row.line, row.symbol, row.issue,
		strings.Join(backing.movingPkgs, ", "), strings.Join(expected, ", "))}
}
