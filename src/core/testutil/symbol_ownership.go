package testutil

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
)

// The fifth table, and the first one that is not in ARCHITECTURE.md: one row per exported symbol
// every core package declares, saying why core declares it. It lives in src/core/OWNERSHIP.md
// because it is data rather than prose -- some four hundred rows, which would bury the module
// graph, the definitions and the rules that are ARCHITECTURE.md's actual value (#385 decision 14).
//
// It exists because the package ownership table cannot see inside a package and the constants
// table only watches one. A package both processes genuinely share can still hide an
// implementation only one of them uses, and nothing goes red while it does: core/constants reached
// 139 symbols, 108 named by a single process, with every import rule green at every step (#351).
// That table closed the hole for one package; this one closes it for the rest.
//
// The seven justifications are described in OWNERSHIP.md's own header. What matters here is that a
// row states the strongest claim the tree backs, that the check runs in both directions, and that
// an asserted row carries a note -- a word with nothing behind it is what turns an escape hatch
// into a shrug (#385 decision 17).
const ownershipDoc = "core/OWNERSHIP.md"

// symbolOwnershipHeading is the deepest heading of the table's section, so the header prose above
// it is free to change without touching the parser. Same arrangement as the four in ARCHITECTURE.md.
const symbolOwnershipHeading = "### Core symbol ownership"

// The three justifications this table adds to the four constants_ownership.go already declares.
// justificationKernel, justificationBothApps, justificationContract and justificationMoving are
// shared with that table deliberately: the two answer the same question at two grains, and a
// reader should not have to learn two vocabularies to read them.
const (
	// justificationOwnPackage: the declaring package's own production code names it, from a
	// declaration that is itself justified. The table asks why core declares a symbol, which is
	// two questions -- does the package belong in core, and does the symbol belong to the package
	// -- and they come apart for a package with behaviour. sessionstore.SessionIdBytes is the
	// width the store mints an identifier at, inside a store both processes depend on.
	justificationOwnPackage = "own-package"
	// justificationReachable: a justified symbol's own declaration names it, or it is a const or
	// var of a justified type. countries.Country is only ever AllInfo's element type; a contract
	// row on it would be true and misleading.
	justificationReachable = "reachable"
	// justificationTestSupport: no package a binary links names it in production, and something
	// names it -- a test anywhere, or the declaring package's own production code. Asserted, but
	// checked in both directions, so it cannot park a symbol one application uses.
	//
	// "A binary links it" rather than "a production file names it", which is how the other six are
	// read, because this is the one word that is about being compiled into nothing rather than
	// about who the consumer is. Three packages in this tree are test support written in files
	// without the _test.go suffix -- core/testutil, core/mocks and each application's handlertest
	// -- so a plain production reading has adminconsole/internal/handlertest/json.go contradicting
	// a test-support row for testutil.Reporter, which is the harness every rule test in the
	// repository drives a guard through.
	justificationTestSupport = "test-support"
)

// assertedJustifications are the three a human writes. Each needs a non-empty note, and each is
// legal only where the tree offers no computed answer at all.
var assertedJustifications = map[string]bool{
	justificationTestSupport: true,
	justificationContract:    true,
	justificationMoving:      true,
}

// justificationStrength orders the computed words. A row states the strongest the tree backs,
// which is what keeps the weaker ones honest: reachable is reachable only where own-package does
// not hold.
var justificationStrength = map[string]int{
	justificationKernel:     4,
	justificationBothApps:   3,
	justificationOwnPackage: 2,
	justificationReachable:  1,
}

// issueInNote matches the "#385" form a moving note has to carry. issueRef is anchored because the
// constants table's issue cell holds nothing else; a note is prose with an issue somewhere in it.
var issueInNote = regexp.MustCompile(`#\d+`)

// symbolKey identifies one row: the declaring package as a directory relative to the source root,
// and the exported name. The package is the real Go package rather than the top-level core
// directory, so core/sessionstore and core/sessionstore/sessiontest are two packages and nothing
// hides in a subdirectory the table never enumerated.
type symbolKey struct {
	pkg  string
	name string
}

func (k symbolKey) String() string { return k.pkg + "." + k.name }

type symbolRow struct {
	pkg           string
	symbol        string
	justification string
	note          string
	line          int
}

func (r symbolRow) key() symbolKey { return symbolKey{pkg: r.pkg, name: r.symbol} }

// symbolCensus is what the tree says, against which the table is checked.
type symbolCensus struct {
	// declared is every exported symbol every core package declares, sorted.
	declared []symbolKey
	// corePkgs, apps and tests are the references from outside the declaring package: which other
	// core packages name it in production, which modules do, and whether any test anywhere does.
	corePkgs map[symbolKey]map[string]bool
	apps     map[symbolKey]map[string]bool
	tests    map[symbolKey]bool
	// linkedApps records, per symbol, the modules naming it in production from a package one of
	// their binaries actually links. It is the same evidence as apps, narrowed, and only a
	// test-support row reads it.
	linkedApps map[symbolKey]map[string]bool
	// linked is every package directory a shipped binary reaches through production imports.
	linked map[string]bool
	// pkgs carries each package's internal shape: what it declares, what each top-level
	// declaration names, and the type of each package-level const and var.
	pkgs map[string]*packageSymbols
}

// packageSymbols is one core package as the resolver reads it.
type packageSymbols struct {
	// name is the package clause its production files carry, which is the identifier an unaliased
	// import of it binds. Go binds the declared name and not the last segment of the import path,
	// and a package named for something other than its directory is read through that name
	// everywhere: by the applications importing it, and by its own external tests.
	name     string
	exported map[string]bool
	// nodes is one entry per top-level declaration owner: a function by its name, a method by its
	// receiver type, a type by its name, a const or var by each name it introduces. Unexported
	// owners are nodes too, because an exported symbol reached only through an unexported helper
	// is still reached.
	nodes map[string]*declNode
	// valueType maps a package-level const or var to the same-package named type it is declared
	// with, including the type a const inherits from the nearest preceding ValueSpec carrying one.
	// That inheritance is the Go spec's, and reading the syntax spec-by-spec instead is what made
	// probe/census2.out call GenderFemale, GenderMale and GenderOther test-only while Gender was
	// both-apps.
	valueType map[string]string
	// ownRefs is every package-level name the package's own production code reaches, from any
	// declaration, justified or not. Only a test-support row reads it.
	ownRefs map[string]bool
}

// declNode is one owner and the package-level names its declaration reaches, split by position.
// The split is the line between own-package and reachable: decl is the type and the signature,
// which is how countries.Country is reached from AllInfo, and body is everything else, which is
// how sessionstore.SessionIdBytes is reached from the method that mints an identifier.
type declNode struct {
	exported bool
	decl     map[string]bool
	body     map[string]bool
}

func newDeclNode(exported bool) *declNode {
	return &declNode{exported: exported, decl: map[string]bool{}, body: map[string]bool{}}
}

// AssertSymbolOwnership holds src/core/OWNERSHIP.md to the tree it describes, in both directions:
// every exported symbol a core package declares has exactly one row, every row names a symbol that
// still exists, and every row states the strongest justification the reference graph backs.
//
// All three module unit tiers call it, so it fires whichever tier runs, exactly as
// AssertArchitecture does. src/core/cmd/ownershipdump writes the computed rows from this same
// census, so the tool and the guard can never read the tree differently.
func AssertSymbolOwnership(t *testing.T) {
	t.Helper()

	assertSymbolOwnership(t, SourceRoot(t))
}

// assertSymbolOwnership is the reporting half, taking the root as a parameter and failing through
// a Reporter so a rule test can drive it against a fixture tree. See Reporter in guard.go.
func assertSymbolOwnership(r Reporter, root string) {
	r.Helper()

	doc, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ownershipDoc)))
	if err != nil {
		r.Fatalf("reading %s: %v", ownershipDoc, err)
	}

	rows, findings := parseSymbolOwnershipDoc(string(doc))

	graph, err := buildImportGraph(root)
	if err != nil {
		r.Fatalf("reading the import graph under %s: %v", root, err)
	}

	census, err := buildSymbolCensus(root, graph)
	if err != nil {
		r.Fatalf("reading the core symbol census under %s: %v", root, err)
	}
	// The three ways this guard could pass by finding nothing. A census that read no package, no
	// declaration or no reference satisfies every rule below over an empty set, which is the one
	// failure mode a clean tree cannot be told apart from a correct one.
	if len(census.pkgs) == 0 {
		r.Fatalf("found no core packages under %s", root)
	}
	if len(census.declared) == 0 {
		r.Fatalf("found no exported declarations in any core package under %s", root)
	}
	if len(census.corePkgs) == 0 && len(census.apps) == 0 {
		r.Fatalf("found no production reference to any core symbol under %s", root)
	}

	findings = append(findings, checkSymbolOwnership(rows, census)...)

	sort.Strings(findings)
	for _, f := range findings {
		r.Errorf("%s", f)
	}
}

// ---- the document --------------------------------------------------------------------------

// parseSymbolOwnershipDoc reads the table. A malformed row is a finding rather than a parse
// failure, so one bad cell reports itself instead of silently shortening the table and turning
// every symbol it covered into a missing row.
func parseSymbolOwnershipDoc(doc string) ([]symbolRow, []string) {
	var rows []symbolRow
	var findings []string

	table, ok := tableUnder(strings.Split(doc, "\n"), symbolOwnershipHeading)
	if !ok {
		return nil, []string{fmt.Sprintf("%s has no %q table", ownershipDoc, symbolOwnershipHeading)}
	}
	for _, row := range table {
		if len(row.cells) != 4 {
			findings = append(findings, fmt.Sprintf(
				"%s:%d: an ownership row needs 4 cells, found %d", ownershipDoc, row.line, len(row.cells)))
			continue
		}
		rows = append(rows, symbolRow{
			pkg:           row.cells[0],
			symbol:        row.cells[1],
			justification: row.cells[2],
			// The note comes from the raw line rather than from the parsed cell, because splitRow
			// strips backticks -- right for an identifier cell, wrong for prose that cites one,
			// and a round trip through ownershipdump would otherwise rewrite every note it read.
			note: rawCell(row.raw, 3),
			line: row.line,
		})
	}
	return rows, findings
}

// rawCell returns one cell of a markdown table row with its padding trimmed and nothing else
// touched.
func rawCell(line string, index int) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
	if index >= len(parts) {
		return ""
	}
	return strings.TrimSpace(parts[index])
}

// ---- the checks ----------------------------------------------------------------------------

// checkSymbolOwnership holds the table and the tree to each other, in both directions.
func checkSymbolOwnership(rows []symbolRow, census *symbolCensus) []string {
	var findings []string

	computed := census.computeJustifications()

	byKey := map[symbolKey]symbolRow{}
	for _, row := range rows {
		if first, duplicate := byKey[row.key()]; duplicate {
			findings = append(findings, fmt.Sprintf(
				"core symbols: %s:%d gives %s a second row; the first is at line %d",
				ownershipDoc, row.line, row.key(), first.line))
			continue
		}
		byKey[row.key()] = row
	}

	declared := map[symbolKey]bool{}
	for _, key := range census.declared {
		declared[key] = true
		if _, ok := byKey[key]; !ok {
			findings = append(findings, fmt.Sprintf(
				"core symbols: %s holds no row for %s; every exported symbol core declares says why it is there, so that leaving one in core is a decision rather than a default",
				ownershipDoc, key))
		}
	}

	for _, row := range rows {
		if !declared[row.key()] {
			findings = append(findings, fmt.Sprintf(
				"core symbols: %s:%d records %s, which the tree no longer declares; delete the row",
				ownershipDoc, row.line, row.key()))
			continue
		}
		if byKey[row.key()].line != row.line {
			// Already reported as a duplicate; checking it twice would say the same thing twice.
			continue
		}
		findings = append(findings, checkSymbolRow(row, census, computed[row.key()])...)
	}

	return findings
}

// checkSymbolRow holds one row to what the tree backs for its symbol.
func checkSymbolRow(row symbolRow, census *symbolCensus, computed string) []string {
	_, isComputedWord := justificationStrength[row.justification]
	if !isComputedWord && !assertedJustifications[row.justification] {
		return []string{fmt.Sprintf(
			"core symbols: %s:%d gives %s the justification %q, which is none of the seven",
			ownershipDoc, row.line, row.key(), row.justification)}
	}

	if computed != "" {
		if row.justification != computed {
			return []string{fmt.Sprintf(
				"core symbols: %s:%d records %s as %s, but the tree backs %s: %s; a row states the strongest claim that holds",
				ownershipDoc, row.line, row.key(), row.justification, computed, census.evidenceFor(row.key(), computed))}
		}
		return nil
	}

	if isComputedWord {
		return []string{fmt.Sprintf(
			"core symbols: %s:%d records %s as %s, but nothing in the tree backs a computed justification for it: %s; either move the symbol out of core or assert %s, %s or %s with a note",
			ownershipDoc, row.line, row.key(), row.justification, census.evidenceFor(row.key(), ""),
			justificationTestSupport, justificationContract, justificationMoving)}
	}

	var findings []string
	if noNote(row.note) {
		findings = append(findings, fmt.Sprintf(
			"core symbols: %s:%d asserts %s for %s with no note; the three asserted justifications are the ones nothing can check, so the argument is the whole of what a reviewer has to read",
			ownershipDoc, row.line, row.justification, row.key()))
	}
	switch row.justification {
	case justificationMoving:
		if !issueInNote.MatchString(row.note) {
			findings = append(findings, fmt.Sprintf(
				"core symbols: %s:%d records %s as %s but its note names no issue; a justification that expires has to say when",
				ownershipDoc, row.line, row.key(), justificationMoving))
		}
	case justificationTestSupport:
		if linked := census.linkedReferrers(row.key()); len(linked) > 0 {
			findings = append(findings, fmt.Sprintf(
				"core symbols: %s:%d records %s as %s, but %s names it in production and a binary links that package; test support is the one asserted word the tree can contradict, so it cannot park a symbol somebody ships",
				ownershipDoc, row.line, row.key(), justificationTestSupport, strings.Join(linked, ", ")))
		} else if !census.tests[row.key()] && !census.namedByOwnPackage(row.key()) {
			findings = append(findings, fmt.Sprintf(
				"core symbols: %s:%d records %s as %s, but nothing names it -- no test anywhere, and not its own package; it is supporting nothing",
				ownershipDoc, row.line, row.key(), justificationTestSupport))
		}
	}
	return findings
}

// noNote reports whether a note cell is empty in the sense the table means. The document writes an
// em dash on a computed row; a hyphen and an empty cell mean the same thing to a reader, and
// refusing them would be a finding about typography rather than about the tree.
func noNote(cell string) bool {
	switch strings.TrimSpace(cell) {
	case "—", "–", "-", "":
		return true
	}
	return false
}

// productionReferrersOutside lists what names a symbol in production from outside its own package.
func (c *symbolCensus) productionReferrersOutside(key symbolKey) []string {
	var out []string
	for pkg := range c.corePkgs[key] {
		out = append(out, pkg)
	}
	for app := range c.apps[key] {
		out = append(out, app)
	}
	sort.Strings(out)
	return out
}

// linkedReferrers lists the packages a binary links that name a symbol in production, which is the
// half of a test-support row the tree can contradict. Only the core packages are named exactly: a
// reference from an application is recorded as the module, since a symbol reached from anywhere in
// a shipped binary is shipped.
func (c *symbolCensus) linkedReferrers(key symbolKey) []string {
	var out []string
	for pkg := range c.corePkgs[key] {
		if c.linked[pkg] {
			out = append(out, pkg)
		}
	}
	for app := range c.linkedApps[key] {
		out = append(out, app)
	}
	sort.Strings(out)
	return out
}

// namedByOwnPackage reports whether the declaring package's own production code names a symbol at
// all, justified or not. It is the other way a test-support row earns its second half:
// core/mocks.TestFile is the fs.File that core/mocks.TestFS returns and no test constructs one
// directly, which makes it test support rather than something supporting nothing.
func (c *symbolCensus) namedByOwnPackage(key symbolKey) bool {
	pkg, ok := c.pkgs[key.pkg]
	return ok && pkg.ownRefs[key.name]
}

// evidenceFor renders what the census saw, so a finding carries the reason and a reader can argue
// with the answer rather than trust it.
func (c *symbolCensus) evidenceFor(key symbolKey, computed string) string {
	var parts []string
	if outside := c.productionReferrersOutside(key); len(outside) > 0 {
		parts = append(parts, strings.Join(outside, ", ")+" names it in production")
	}
	switch computed {
	case justificationOwnPackage:
		parts = append(parts, "its own package names it from a justified declaration")
	case justificationReachable:
		parts = append(parts, "a justified declaration in its own package names it")
	}
	if c.tests[key] {
		parts = append(parts, "a test names it")
	}
	if len(parts) == 0 {
		return "nothing names it"
	}
	return strings.Join(parts, "; ")
}

// ---- the resolver --------------------------------------------------------------------------

// computeJustifications resolves the four computed words for every declared symbol, or the empty
// string where the tree offers none.
//
// The seeds are external evidence and nothing else: kernel and both-apps are read straight off
// production references from outside the declaring package. own-package and reachable then require
// a source that is already justified, and iterate to a fixpoint.
//
// Circular evidence is not evidence, which is what the seeding rule buys. Two references never
// count for the symbol they name: a method's receiver, because a method rides with its receiver
// and so cannot vouch for it, and the declared type of a const or var the same package writes.
// Without both, core/enums justifies itself and the guard is blind to exactly the package #385
// deletes -- AcrLevel would be own-package because `AcrLevel1 AcrLevel = ...` and
// `func (acr AcrLevel) IsHigherThan` name it, and AcrLevel1 would be reachable as a const of a
// justified type, with nothing outside core/enums anywhere in the loop.
//
// An asserted row is not a seed either, for the same reason one step further out. If it were, two
// mutually referring symbols could each be justified by the other's assertion, and the table would
// not even be stable: ownershipdump would rewrite both asserted rows as computed on one run and
// then refuse them both on the next, neither being asserted any more.
func (c *symbolCensus) computeJustifications() map[symbolKey]string {
	best := map[symbolKey]string{}
	set := func(key symbolKey, word string) bool {
		if justificationStrength[word] <= justificationStrength[best[key]] {
			return false
		}
		best[key] = word
		return true
	}

	for _, key := range c.declared {
		switch {
		case len(c.corePkgs[key]) > 0:
			best[key] = justificationKernel
		case c.apps[key]["authserver"] && c.apps[key]["adminconsole"]:
			best[key] = justificationBothApps
		}
	}

	// live is one entry per top-level declaration the closure has reached, exported or not. An
	// unexported helper is a conduit: a symbol reached only through one is still reached, and
	// stopping at the package's exported surface would leave half of every package unjustifiable.
	live := map[symbolKey]bool{}

	for changed := true; changed; {
		changed = false

		for dir, pkg := range c.pkgs {
			for name, node := range pkg.nodes {
				key := symbolKey{pkg: dir, name: name}
				if node.exported && best[key] != "" && !live[key] {
					live[key] = true
					changed = true
				}
			}
			for name, node := range pkg.nodes {
				if !live[symbolKey{pkg: dir, name: name}] {
					continue
				}
				if c.spread(dir, pkg, node.body, justificationOwnPackage, live, set) {
					changed = true
				}
				if c.spread(dir, pkg, node.decl, justificationReachable, live, set) {
					changed = true
				}
			}
			for name, typeName := range pkg.valueType {
				if !pkg.exported[name] || best[symbolKey{pkg: dir, name: typeName}] == "" {
					continue
				}
				if set(symbolKey{pkg: dir, name: name}, justificationReachable) {
					changed = true
				}
			}
		}
	}

	return best
}

// spread marks every name one live declaration reaches as live, and gives the exported ones the
// word that position earns.
func (c *symbolCensus) spread(dir string, pkg *packageSymbols, names map[string]bool, word string, live map[symbolKey]bool, set func(symbolKey, string) bool) bool {
	changed := false
	for name := range names {
		key := symbolKey{pkg: dir, name: name}
		if _, isNode := pkg.nodes[name]; isNode && !live[key] {
			live[key] = true
			changed = true
		}
		if pkg.exported[name] && set(key, word) {
			changed = true
		}
	}
	return changed
}

// ---- the census ----------------------------------------------------------------------------

// buildSymbolCensus reads every core package's exported declarations and internal reference graph,
// then every production and test reference to them from anywhere in the tree.
//
// ceiling: a reference from outside the declaring package is a selector on the identifier the
// import binds, resolved by name within the file, exactly as buildConstantsCensus reads one. A
// package-level declaration shadowing that name is caught, because the parser resolves it; a local
// variable inside a function shadowing it would be read as the package. Nothing in this tree does
// that, and closing it means type-checking every package in four modules rather than parsing them.
// Revisit if a row ever rests on a reference that turns out to be a false one (#385).
//
// References from inside the declaring package are not read that way, because there they carry no
// selector and an unqualified identifier matched by spelling is the over-count that matters: a
// local, a parameter, a struct field, a struct-literal key or a label sharing an exported symbol's
// name would justify it, and this tree already has that shape -- core/testutil declares a type
// Address and a field named Address. Those are resolved with go/types over each package's own
// syntax instead, production files and internal test files alike, so an identifier counts only
// when it resolves to the declared object.
//
// ceiling: the go/types pass runs with a stub importer, so nothing an import contributes is
// resolved and every selector on an imported package is an error the checker is told to continue
// past. In-package name resolution does not depend on imports, so Uses and Defs are sound for
// exactly the identifiers this arm reads. A dot import would break that, and this tree has none
// (#385).
func buildSymbolCensus(root string, graph *importGraph) (*symbolCensus, error) {
	census := &symbolCensus{
		corePkgs:   map[symbolKey]map[string]bool{},
		apps:       map[symbolKey]map[string]bool{},
		tests:      map[symbolKey]bool{},
		linkedApps: map[symbolKey]map[string]bool{},
		pkgs:       map[string]*packageSymbols{},
	}

	linked, err := linkedPackages(root, graph)
	if err != nil {
		return nil, err
	}
	census.linked = linked

	dirs, err := corePackageDirs(root)
	if err != nil {
		return nil, err
	}

	// byImportPath lets the reference walk below turn an import into the package directory whose
	// row the reference backs.
	byImportPath := map[string]string{}
	for _, dir := range dirs {
		pkg, err := readPackageSymbols(root, dir)
		if err != nil {
			return nil, err
		}
		census.pkgs[dir] = pkg
		if len(pkg.exported) == 0 {
			// A package declaring nothing exported owns no row and nothing can select off it.
			// core/countries/generate and core/timezones/generate are both package main whose
			// only exported spellings sit inside a raw string template.
			continue
		}
		importPath, hasPath := graph.importPath(dir)
		if hasPath {
			byImportPath[importPath] = dir
		}
		if err := census.readOwnPackageTests(root, dir, importPath); err != nil {
			return nil, err
		}
		for name := range pkg.exported {
			census.declared = append(census.declared, symbolKey{pkg: dir, name: name})
		}
	}
	sort.Slice(census.declared, func(i, j int) bool {
		if census.declared[i].pkg != census.declared[j].pkg {
			return census.declared[i].pkg < census.declared[j].pkg
		}
		return census.declared[i].name < census.declared[j].name
	})

	if err := census.readReferences(root, graph, byImportPath); err != nil {
		return nil, err
	}
	return census, nil
}

// corePackageDirs lists every directory under core holding at least one production Go file that
// some build includes, as a directory relative to the source root. Recursive, because decision 15
// grants no package-level exemption and a symbol in a subdirectory is still a symbol core declares.
// The generated mock subpackages drop out here rather than by name: every file in them carries
// //go:build !production, which is the rule that already excludes them everywhere else.
func corePackageDirs(root string) ([]string, error) {
	seen := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, "core"), func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, path, nil, parser.PackageClauseOnly|parser.ParseComments)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns, and reporting it
			// here would send the reader to the wrong place.
			return nil
		}
		if exemptByBuildConstraint(file, fset) {
			return nil
		}
		rel, relErr := filepath.Rel(root, filepath.Dir(path))
		if relErr != nil {
			return errs.Wrapf(relErr, "relating %s to %s", path, root)
		}
		seen[filepath.ToSlash(rel)] = true
		return nil
	})
	if err != nil {
		return nil, errs.Wrapf(err, "walking the core module under %s", root)
	}

	dirs := make([]string, 0, len(seen))
	for dir := range seen {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	return dirs, nil
}

// readPackageSymbols type-checks one core package's production files and reads its exported
// declarations, its internal reference graph and the declared type of each package-level value.
func readPackageSymbols(root, dir string) (*packageSymbols, error) {
	abs := filepath.Join(root, filepath.FromSlash(dir))
	entries, err := os.ReadDir(abs)
	if err != nil {
		return nil, errs.Wrapf(err, "reading %s", dir)
	}

	fset := token.NewFileSet()
	var files []*ast.File
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, pErr := parser.ParseFile(fset, filepath.Join(abs, entry.Name()), nil, parser.ParseComments)
		if pErr != nil {
			return nil, errs.Wrapf(pErr, "parsing %s/%s", dir, entry.Name())
		}
		if exemptByBuildConstraint(file, fset) {
			continue
		}
		files = append(files, file)
	}

	pkg := &packageSymbols{
		exported:  map[string]bool{},
		nodes:     map[string]*declNode{},
		valueType: map[string]string{},
		ownRefs:   map[string]bool{},
	}
	if len(files) == 0 {
		return pkg, nil
	}
	pkg.name = files[0].Name.Name

	scope, info := checkPackage(fset, dir, files)
	for _, file := range files {
		for _, decl := range file.Decls {
			readDecl(pkg, decl, scope, info)
		}
	}
	for _, node := range pkg.nodes {
		for name := range node.decl {
			pkg.ownRefs[name] = true
		}
		for name := range node.body {
			pkg.ownRefs[name] = true
		}
	}
	return pkg, nil
}

// stubImporter answers every import with an empty package of the right name. Nothing this census
// reads comes from an import, so resolving them would buy nothing and cost the whole dependency
// graph of four modules on every unit tier.
type stubImporter struct{}

func (stubImporter) Import(path string) (*types.Package, error) {
	name := path[strings.LastIndex(path, "/")+1:]
	pkg := types.NewPackage(path, name)
	pkg.MarkComplete()
	return pkg, nil
}

// checkPackage runs go/types over one package's own syntax and returns its package scope and the
// identifier resolution. Errors are collected and ignored: with a stub importer every selector on
// an imported package is one, and a non-nil Error is what makes the checker continue past them
// rather than stop at the first.
func checkPackage(fset *token.FileSet, dir string, files []*ast.File) (*types.Scope, *types.Info) {
	conf := types.Config{
		Importer:                 stubImporter{},
		Error:                    func(error) {},
		DisableUnusedImportCheck: true,
		IgnoreFuncBodies:         false,
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}}
	pkg, _ := conf.Check(dir, fset, files, info)
	if pkg == nil {
		return types.NewScope(nil, 0, 0, dir), info
	}
	return pkg.Scope(), info
}

// readDecl records one top-level declaration: the names it introduces, and the package-level names
// its declaration and its body reach.
func readDecl(pkg *packageSymbols, decl ast.Decl, scope *types.Scope, info *types.Info) {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		// A declaration with no body -- assembly, or a //go:linkname -- carries a typed nil that
		// ast.Inspect dereferences, so the nil check inside collect cannot see it and the whole
		// guard dies on a nil pointer rather than reporting. There are none in core today.
		body := ast.Node(d.Body)
		if d.Body == nil {
			body = nil
		}
		if d.Recv == nil {
			owner := pkg.node(d.Name.Name)
			collect(pkg, owner.decl, d.Type, d.Name.Name, scope, info)
			collect(pkg, owner.body, body, d.Name.Name, scope, info)
			return
		}
		// A method rides with its receiver, so it adds no row of its own and cannot vouch for the
		// type it hangs off: what it reaches, its receiver reaches. The receiver field itself is
		// never read, which is the first of the two shapes that would otherwise let a package
		// justify itself.
		name := receiverTypeName(d.Recv)
		if name == "" {
			return
		}
		owner := pkg.node(name)
		collect(pkg, owner.decl, d.Type, name, scope, info)
		collect(pkg, owner.body, body, name, scope, info)
	case *ast.GenDecl:
		if d.Tok == token.IMPORT {
			return
		}
		// inherited is the const repetition rule: inside a parenthesized const declaration an
		// omitted expression list is, in Go's words, the textual substitution of the nearest
		// preceding non-empty one *and its type if any*, so an omitted spec's names reach
		// everything that expression and that type slot reach. Reading only the spec's own Values
		// left those edges out, and a symbol the tree justifies would then have been offered an
		// asserted escape hatch -- the one thing this table exists to refuse. It is read for a
		// const alone, because a var omitting its values is taking the zero value rather than
		// repeating anything. Final review round 2, finding 1; the type slot, round 3, finding 2.
		//
		// inheritedType is reset by every non-empty list, to nil as readily as to a type, because
		// what Go substitutes is the *nearest* preceding list: a const below an untyped list
		// inherits no type at all.
		var inherited []ast.Expr
		var inheritedType ast.Expr
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				owner := pkg.node(s.Name.Name)
				// A constraint is named in the type parameter list rather than in the type, and
				// it is as much a part of the declaration as a struct field's type is.
				if s.TypeParams != nil {
					collect(pkg, owner.decl, s.TypeParams, s.Name.Name, scope, info)
				}
				collect(pkg, owner.decl, s.Type, s.Name.Name, scope, info)
			case *ast.ValueSpec:
				values, declaredType := s.Values, s.Type
				switch {
				case len(values) > 0:
					inherited, inheritedType = values, s.Type
				case d.Tok == token.CONST:
					values, declaredType = inherited, inheritedType
				}
				for i, name := range s.Names {
					owner := pkg.node(name.Name)
					// Its own named type is the one reference that never counts as evidence for
					// that type: it is the second of the two shapes that let an enum justify the
					// type it enumerates. It is recorded instead, because the arrow runs the
					// other way -- a const of a justified type is reachable.
					//
					// Only the occurrence that spells the type is excluded, the type slot or a
					// conversion standing in for it, which is what `LevelLow = Level("low")` and
					// `LevelLow Level = "low"` have in common. Every other occurrence in the
					// initializer is an ordinary reference, and deleting the name from the whole
					// declaration afterwards threw those away: an initializer building a slice of
					// the type really is the package using it. Final review round 3, finding 3.
					named := namedValueType(name.Name, scope)
					var value ast.Expr
					if len(values) == len(s.Names) {
						value = values[i]
					}
					if named != "" {
						pkg.valueType[name.Name] = named
					}
					// head is the expression whose head spells this name's own type. For the
					// positional form that is the name's own value; for the tuple form it is the
					// single expression, which is how `var ToneCool, ok = source.(Tone)` reaches
					// the assertion at all. Which of the two names it excludes for is decided by
					// named rather than by position: ok was declared with bool, so named is empty
					// for it and nothing is excluded. Final review round 4, finding 2.
					head := value
					if head == nil && len(values) == 1 {
						head = values[0]
					}
					skip := declaredTypeOccurrences(declaredType, head, named)
					// One expression per name is positional, which is what Go means by
					// `var a, b = f(), g()`: a is initialised by f and b by g, and nothing a
					// names is evidence for anything b names. An inherited list is paired the
					// same way, since Go requires it to have one expression per name. Any other
					// count is the tuple-valued form, `var a, b = pair()`, where the single
					// expression really does initialise both names.
					if value != nil {
						collectExcept(pkg, owner.body, value, name.Name, scope, info, skip)
					} else {
						for _, expr := range values {
							collectExcept(pkg, owner.body, expr, name.Name, scope, info, skip)
						}
					}
					// The type slot is part of the declaration, so what it names is reachable
					// from a justified value: `var Registry map[string]Cog` is the only thing in
					// the package that names Cog, and reading the values alone left it looking
					// unjustified.
					collectExcept(pkg, owner.decl, declaredType, name.Name, scope, info, skip)
				}
			}
		}
	}
}

func (p *packageSymbols) node(name string) *declNode {
	if existing, ok := p.nodes[name]; ok {
		return existing
	}
	node := newDeclNode(ast.IsExported(name))
	p.nodes[name] = node
	if node.exported {
		p.exported[name] = true
	}
	return node
}

// receiverTypeName returns the base type name a method hangs off, with any pointer and any type
// parameters stripped.
func receiverTypeName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	expr := recv.List[0].Type
	for {
		switch t := expr.(type) {
		case *ast.StarExpr:
			expr = t.X
		case *ast.IndexExpr:
			expr = t.X
		case *ast.IndexListExpr:
			expr = t.X
		case *ast.Ident:
			return t.Name
		default:
			return ""
		}
	}
}

// namedValueType returns the same-package named type a package-level const or var has, or "" when
// it has none. It reads the type go/types gave the value rather than the type slot of its spec,
// because the three spellings below declare the same constant and a reader choosing one of the
// last two should not be handed an asserted escape hatch for a symbol the tree justifies:
//
//	const ColourRed Colour = "red"      // the type slot
//	const ColourRed = Colour("red")     // a conversion in the expression
//	const ( ColourRed Colour = "red"; ColourBlue )  // repeating the spec above it
//
// Reading the syntax spec by spec instead is what made probe/census2.out call GenderFemale,
// GenderMale and GenderOther test-only while Gender itself was both-apps.
//
// Only a named type this package declares counts. A slice, a map or a pointer is a composite, and
// the arrow this feeds -- a const of a justified type is reachable -- is about an enum member,
// not about a variable holding a collection; a type from an import is not a row in this table.
func namedValueType(name string, scope *types.Scope) string {
	obj := scope.Lookup(name)
	switch obj.(type) {
	case *types.Const, *types.Var:
	default:
		return ""
	}
	named, isNamed := types.Unalias(obj.Type()).(*types.Named)
	if !isNamed {
		return ""
	}
	if named.Obj() == nil || named.Obj().Parent() != scope {
		return ""
	}
	return named.Obj().Name()
}

// declaredTypeOccurrences returns the identifiers in one value's declaration that spell the value's
// own named type rather than use it: the type slot, and the conversion, composite literal or type
// assertion at the head of its initializer, which is where a value that omits the slot spells the
// same thing. Those three are the whole of it, because they are the only expression forms whose
// head names the type of the value the expression produces. Nothing deeper counts, so
// `var ToneWarm Tone = firstOf([]Tone{"warm"})` still names Tone once.
//
// An empty named means the value has no same-package named type, and then nothing is excluded --
// which is what leaves the bool of `var ToneCool, ok = source.(Tone)` naming Tone ordinarily. The
// exclusion is per value rather than per declaration, and only the first result of a comma-ok
// assertion takes the asserted type.
func declaredTypeOccurrences(declaredType, value ast.Expr, named string) map[*ast.Ident]bool {
	if named == "" {
		return nil
	}
	skip := map[*ast.Ident]bool{}
	// A generic named type is spelled instantiated, `Box[int]` or `Pair[K, V]`, which go/ast wraps
	// in an IndexExpr or an IndexListExpr around the base identifier. Only that base is the value's
	// own type: the type arguments are ordinary references, and so is anything deeper. Without the
	// unwrapping the slot read as a plain reference and a justified `var Default Box[int]` made Box
	// reachable from itself, which is the circularity this whole exclusion exists to refuse.
	// Final review round 4, finding 1.
	mark := func(expr ast.Expr) {
		for {
			switch e := unparen(expr).(type) {
			case *ast.IndexExpr:
				expr = e.X
			case *ast.IndexListExpr:
				expr = e.X
			case *ast.Ident:
				if e.Name == named {
					skip[e] = true
				}
				return
			default:
				return
			}
		}
	}
	mark(declaredType)
	switch head := unparen(value).(type) {
	case *ast.CallExpr:
		mark(head.Fun)
	case *ast.CompositeLit:
		mark(head.Type)
	case *ast.TypeAssertExpr:
		// `var ToneWarm = source.(Tone)` spells Tone exactly as `Tone("warm")` does. Reading it as
		// a use instead let a member promote its own type to own-package. Final review round 4,
		// finding 2.
		mark(head.Type)
	}
	return skip
}

// collect records every package-level name of this package that a syntax subtree reaches, skipping
// the owner's own name. Resolution is by object identity rather than by spelling, so a local, a
// parameter, a struct field, a struct-literal key, a label or a selector member sharing an
// exported symbol's name is not a reference to it.
func collect(pkg *packageSymbols, into map[string]bool, node ast.Node, owner string, scope *types.Scope, info *types.Info) {
	collectExcept(pkg, into, node, owner, scope, info, nil)
}

// collectExcept is collect with a set of identifier occurrences left out, which is how a value's
// declaration of its own type is told apart from a use of it.
func collectExcept(pkg *packageSymbols, into map[string]bool, node ast.Node, owner string, scope *types.Scope, info *types.Info, skip map[*ast.Ident]bool) {
	if node == nil {
		return
	}
	ast.Inspect(node, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		obj := info.Uses[ident]
		if obj == nil || obj.Parent() != scope || ident.Name == owner || skip[ident] {
			return true
		}
		into[ident.Name] = true
		return true
	})
	// Every name the subtree reaches has to be a node before the fixpoint can walk through it, so
	// an unexported helper declared later in the file is still a conduit.
	for name := range into {
		pkg.node(name)
	}
}

// readReferences walks the whole tree for references to core symbols from outside their declaring
// package, and for the test references that are the other half of a test-support row.
func (c *symbolCensus) readReferences(root string, graph *importGraph, byImportPath map[string]string) error {
	corePath := graph.modules["core"]
	if corePath == "" {
		return errs.Errorf("the import graph knows no core module")
	}

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return errs.Wrapf(relErr, "relating %s to %s", path, root)
		}
		dir := filepath.ToSlash(filepath.Dir(rel))
		isTest := strings.HasSuffix(path, "_test.go")

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return errs.Wrapf(readErr, "reading %s", path)
		}
		// A file not containing the core module path cannot import a core package, so it cannot
		// name a symbol from one. A declaring package's own tests name their symbols with no
		// import at all, and readOwnPackageTests has already read those.
		if !bytes.Contains(content, []byte(corePath)) {
			return nil
		}

		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, path, content, parser.ParseComments)
		if pErr != nil {
			return nil
		}
		if !isTest && exemptByBuildConstraint(file, fset) {
			return nil
		}

		c.recordSelectors(dir, isTest, byImportPath, file)
		return nil
	})
}

// readOwnPackageTests records the symbols a core package's own tests name, which is the half of a
// test-support row that the tree can supply rather than contradict.
//
// It is a per-package pass rather than a branch of the reference walk because the two kinds of
// test file in a directory resolve a name two different ways. An internal test, whose clause is
// the production package's own name, names a symbol unqualified, so it is type-checked together
// with the production files and read by object identity, exactly as collect reads a production
// declaration. An external test, whose clause is that name with `_test` on the end, is a different
// package that reaches the symbol through the import, so it is read as a selector like any other
// importing file.
//
// Reading the internal arm by spelling instead is what the final review caught: a local variable,
// a parameter or a field spelled like an exported orphan made the orphan look named, so
// test-support -- the one asserted word the tree can argue with -- would have parked dead code in
// core behind a word the guard believed it had checked (#385).
func (c *symbolCensus) readOwnPackageTests(root, dir, importPath string) error {
	abs := filepath.Join(root, filepath.FromSlash(dir))
	entries, err := os.ReadDir(abs)
	if err != nil {
		return errs.Wrapf(err, "reading %s", dir)
	}

	fset := token.NewFileSet()
	var production, tests []*ast.File
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		file, pErr := parser.ParseFile(fset, filepath.Join(abs, entry.Name()), nil, parser.ParseComments)
		if pErr != nil {
			// A file that does not parse is a compile error the build tier owns, exactly as in
			// corePackageDirs.
			continue
		}
		if strings.HasSuffix(entry.Name(), "_test.go") {
			tests = append(tests, file)
			continue
		}
		if !exemptByBuildConstraint(file, fset) {
			production = append(production, file)
		}
	}

	// Which of the two shapes a test file is, is decided by the declaring package's own name
	// rather than by whether the test's package clause ends in `_test`. A production package may
	// legally be named that way, and then its internal tests carry the same clause: the spelling
	// sent them down the external arm, which looks for a self-import no internal test has, and the
	// guard refused genuine evidence for test-support. The suffix is the fallback for a directory
	// whose production files did not parse, where there is no name to compare against. Final
	// review round 2, finding 2.
	declared := ""
	if len(production) > 0 {
		declared = production[0].Name.Name
	}
	var internal, external []*ast.File
	for _, file := range tests {
		isExternal := strings.HasSuffix(file.Name.Name, "_test")
		if declared != "" {
			isExternal = file.Name.Name != declared
		}
		if isExternal {
			external = append(external, file)
			continue
		}
		internal = append(internal, file)
	}

	pkg := c.pkgs[dir]
	for _, file := range external {
		// The self-import binds the declaring package's own name when it carries no alias, so an
		// external test of a package named `odd_test` in core/odd writes `odd_test.Unused` and
		// looking for `odd.Unused` finds nothing. Final review round 3, finding 4.
		local, imports := localImportName(file, importPath, declared)
		if !imports {
			continue
		}
		for _, name := range selectedNames(file, local) {
			if pkg.exported[name] {
				c.tests[symbolKey{pkg: dir, name: name}] = true
			}
		}
	}

	if len(internal) == 0 {
		return nil
	}
	scope, info := checkPackage(fset, dir, append(production, internal...))
	for _, file := range internal {
		ast.Inspect(file, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok || !pkg.exported[ident.Name] {
				return true
			}
			if obj := info.Uses[ident]; obj != nil && obj.Parent() == scope {
				c.tests[symbolKey{pkg: dir, name: ident.Name}] = true
			}
			return true
		})
	}
	return nil
}

// recordSelectors reads the symbols one file selects off the core packages it imports, and files
// each reference under the module or the core package that made it.
func (c *symbolCensus) recordSelectors(dir string, isTest bool, byImportPath map[string]string, file *ast.File) {
	for importPath, declaring := range byImportPath {
		if declaring == dir {
			continue
		}
		local, imports := localImportName(file, importPath, c.pkgs[declaring].name)
		if !imports {
			continue
		}
		for _, name := range selectedNames(file, local) {
			key := symbolKey{pkg: declaring, name: name}
			if !c.pkgs[declaring].exported[name] {
				continue
			}
			if isTest {
				c.tests[key] = true
				continue
			}
			if dir == "core" || strings.HasPrefix(dir, "core/") {
				if c.corePkgs[key] == nil {
					c.corePkgs[key] = map[string]bool{}
				}
				c.corePkgs[key][dir] = true
				continue
			}
			module := moduleOfDir(dir)
			if module == "" {
				continue
			}
			if c.apps[key] == nil {
				c.apps[key] = map[string]bool{}
			}
			c.apps[key][module] = true
			if c.linked[dir] {
				if c.linkedApps[key] == nil {
					c.linkedApps[key] = map[string]bool{}
				}
				c.linkedApps[key][module] = true
			}
		}
	}
}

// linkedPackages returns every package directory a shipped binary reaches, as directories relative
// to the source root: each main package under the four modules, and everything its production
// imports reach transitively.
//
// Only a test-support row reads this, and it is what lets the word mean what ARCHITECTURE.md's
// package table already says about core/testutil and core/mocks -- "test support compiled into no
// binary". Three packages in this tree are test support written in files with no _test.go suffix,
// so "a production file names it" and "a binary ships it" are genuinely different questions, and
// only the second one is the one test-support asks.
func linkedPackages(root string, graph *importGraph) (map[string]bool, error) {
	var queue []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, path, nil, parser.PackageClauseOnly|parser.ParseComments)
		if pErr != nil || file.Name == nil || file.Name.Name != "main" || exemptByBuildConstraint(file, fset) {
			return nil
		}
		rel, relErr := filepath.Rel(root, filepath.Dir(path))
		if relErr != nil {
			return errs.Wrapf(relErr, "relating %s to %s", path, root)
		}
		if importPath, ok := graph.importPath(filepath.ToSlash(rel)); ok {
			queue = append(queue, importPath)
		}
		return nil
	})
	if err != nil {
		return nil, errs.Wrapf(err, "finding the main packages under %s", root)
	}

	seen := map[string]bool{}
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		if seen[path] {
			continue
		}
		seen[path] = true
		queue = append(queue, graph.prod[path]...)
	}

	linked := make(map[string]bool, len(seen))
	for path := range seen {
		linked[graph.relPath(path)] = true
	}
	return linked, nil
}

// moduleOfDir names the module a directory belongs to the way the justifications do: the two
// applications by name, and cmd/goiabada-setup as a third binary that is neither of them, so a
// symbol only the setup command names can never read as both-apps.
func moduleOfDir(dir string) string {
	switch {
	case strings.HasPrefix(dir, "authserver/") || dir == "authserver":
		return "authserver"
	case strings.HasPrefix(dir, "adminconsole/") || dir == "adminconsole":
		return "adminconsole"
	case strings.HasPrefix(dir, "cmd/goiabada-setup"):
		return "cmd/goiabada-setup"
	}
	return ""
}

// ---- the generator -------------------------------------------------------------------------

// ownershipTableHeader is the two lines every markdown table starts with, which tableUnder skips
// and the generator has to write back.
var ownershipTableHeader = []string{
	"| package | symbol | justification | note |",
	"|---|---|---|---|",
}

// unjustifiedPlaceholder is what a row gets when the tree backs no computed justification and
// nobody has asserted one. It is none of the seven, so the guard refuses it: a symbol cannot reach
// the table without somebody either moving it or writing a word and a reason.
const unjustifiedPlaceholder = "unjustified"

// RenderSymbolOwnership reads the tree at root and the OWNERSHIP.md currently on disk, and returns
// the document rewritten so its table describes the tree, together with the symbols it refuses to
// justify. Only the table is rewritten; the header prose above it and anything below it are the
// document's own.
//
// The computed rows are written from the reference graph, and the asserted rows and every note are
// preserved from the file. A symbol the tree does not justify and nobody has asserted is rendered
// with a placeholder and named in the second return value, because inventing a word for it is the
// one thing this tool must not do: that is the whole reason the table exists.
func RenderSymbolOwnership(root string) (string, []string, error) {
	path := filepath.Join(root, filepath.FromSlash(ownershipDoc))
	content, err := os.ReadFile(path)
	if err != nil {
		return "", nil, errs.Wrapf(err, "reading %s", ownershipDoc)
	}

	graph, err := buildImportGraph(root)
	if err != nil {
		return "", nil, err
	}
	census, err := buildSymbolCensus(root, graph)
	if err != nil {
		return "", nil, err
	}
	if len(census.declared) == 0 {
		return "", nil, errs.Errorf("found no exported declarations in any core package under %s", root)
	}

	existing, _ := parseSymbolOwnershipDoc(string(content))
	previous := map[symbolKey]symbolRow{}
	for _, row := range existing {
		previous[row.key()] = row
	}

	computed := census.computeJustifications()
	rows := make([]string, 0, len(census.declared))
	var unjustified []string
	for _, key := range census.declared {
		justification := computed[key]
		note := previous[key].note
		if justification == "" {
			justification = unjustifiedPlaceholder
			if assertedJustifications[previous[key].justification] {
				justification = previous[key].justification
			} else {
				unjustified = append(unjustified, key.String())
			}
		}
		if noNote(note) {
			note = "—"
		}
		rows = append(rows, fmt.Sprintf("| `%s` | `%s` | %s | %s |", key.pkg, key.name, justification, note))
	}

	doc, err := replaceOwnershipTable(string(content), rows)
	if err != nil {
		return "", nil, err
	}
	return doc, unjustified, nil
}

// replaceOwnershipTable swaps the document's table for the generated one, leaving the header prose
// above it and anything below it exactly as they were. Writing the whole file instead would put
// the header's prose in the tool, where nobody edits it.
func replaceOwnershipTable(doc string, rows []string) (string, error) {
	lines := strings.Split(doc, "\n")

	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == symbolOwnershipHeading {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return "", errs.Errorf("%s has no %q heading to write the table under", ownershipDoc, symbolOwnershipHeading)
	}

	// The table begins at the first row line after the heading and ends at the first line that is
	// not one, exactly where tableUnder stops reading.
	for start < len(lines) && strings.TrimSpace(lines[start]) == "" {
		start++
	}
	end := start
	for end < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[end]), "|") {
		end++
	}

	out := make([]string, 0, len(lines)+len(rows))
	out = append(out, lines[:start]...)
	out = append(out, ownershipTableHeader...)
	out = append(out, rows...)
	out = append(out, lines[end:]...)
	return strings.Join(out, "\n"), nil
}

// FindSourceRoot returns the directory holding the four go.mod files, ascending from dir. It is
// SourceRoot's answer without a *testing.T, for src/core/cmd/ownershipdump, which is a command
// rather than a test and still has to root its walk in the same place the guard does.
func FindSourceRoot(dir string) (string, error) {
	return sourceRootFrom(dir)
}
