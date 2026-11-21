package refgraph

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/pkgload"
	"github.com/leodip/goiabada/core/sourceroot"
	"golang.org/x/tools/go/packages"
)

// Four of the seven justifications, the ones that answer whether a symbol belongs in core at all,
// strongest first. A row states the strongest claim the tree backs, which is what keeps contract
// honest: it is reachable only when none of the other three holds, so writing it is a claim a
// reviewer can argue with rather than a shrug.
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

// The other three, which answer whether a symbol belongs to the package declaring it.
const (
	// justificationOwnPackage: the declaring package's own production code names it, from a
	// declaration that is itself justified. The table asks why core declares a symbol, which is
	// two questions -- does the package belong in core, and does the symbol belong to the package
	// -- and they come apart for a package with behaviour. sessionstore.SessionIDBytes is the
	// width the store mints an identifier at, inside a store both processes depend on.
	justificationOwnPackage = "own-package"
	// justificationReachable: a justified symbol's own declaration names it, or it is a const or
	// var of a justified type. api.RedirectURIResponse is ClientResponse.RedirectURIs' element
	// type, and only the auth server names it outside its package; a contract row on it would be
	// true and misleading.
	justificationReachable = "reachable"
	// justificationTestSupport: no package a binary links names it in production, and something
	// names it -- a test anywhere, or the declaring package's own production code. Asserted, but
	// checked in both directions, so it cannot park a symbol one application uses.
	//
	// "A binary links it" rather than "a production file names it", which is how the other six are
	// read, because this is the one word that is about being compiled into nothing rather than
	// about who the consumer is. Test support in this tree is written in files without the
	// _test.go suffix -- core/guard itself, and the admin console's handlertest -- so a plain
	// production reading has adminconsole/internal/handlertest/json.go contradicting
	// a test-support row for guard.Reporter, which is the harness every rule test in the
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

// issueInNote matches the "#385" form a moving note has to carry. It is not anchored, because a
// note is prose with an issue somewhere in it.
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
	// linkedCore and linkedApps record, per symbol, the core packages and the modules naming it
	// in production from a package a binary of the same release build links. They are the same
	// evidence as corePkgs and apps, narrowed, and only a test-support row reads them. Linkage and
	// reference are paired build by build: a package one platform links and a reference only
	// another platform compiles ship together in no binary.
	linkedCore map[symbolKey]map[string]bool
	linkedApps map[symbolKey]map[string]bool
	// pkgs carries each package's internal shape: what it declares, what each top-level
	// declaration names, and the type of each package-level const and var.
	pkgs map[string]*packageSymbols
	// dirs maps a core package's import path to its directory, which is how an object's package
	// becomes the row it backs.
	dirs map[string]string
}

// packageSymbols is one core package as the resolver reads it.
type packageSymbols struct {
	exported map[string]bool
	// nodes is one entry per top-level declaration owner: a function by its name, a method by its
	// receiver type, a type by its name, a const or var by each name it introduces. Unexported
	// owners are nodes too, because an exported symbol reached only through an unexported helper
	// is still reached.
	nodes map[string]*declNode
	// valueType maps a package-level const or var to the same-package named types it is declared
	// with, including the type a const inherits from the nearest preceding ValueSpec carrying one.
	// That inheritance is the Go spec's, and reading the syntax spec-by-spec instead once
	// misclassified gender.Female, Male and Other as test-only while Gender was both-apps, caught
	// during #385. It is a set because each release build's declaration is read into the one record,
	// and two platforms' files can declare the value with different types.
	valueType map[string]map[string]bool
	// ownRefs is every package-level name the package's own production code reaches, from any
	// declaration, justified or not. Only a test-support row reads it.
	ownRefs map[string]bool
}

// declNode is one owner and the package-level names its declaration reaches, split by position.
// The split is the line between own-package and reachable: decl is the type and the signature,
// which is how api.RedirectURIResponse is reached from ClientResponse, and body is everything
// else, which is how sessionstore.SessionIDBytes is reached from the method that mints an
// identifier.
type declNode struct {
	exported bool
	decl     map[string]bool
	body     map[string]bool
}

func newDeclNode(exported bool) *declNode {
	return &declNode{exported: exported, decl: map[string]bool{}, body: map[string]bool{}}
}

// OwnershipCheck is what CheckOwnership read and what it found wrong. The three counts are how
// much of the tree the census reached, and they are for the reporting half: a census that read no
// package, no declaration or no reference satisfies every rule over an empty set, which is the one
// failure mode a clean tree cannot be told apart from a correct one, so a zero is fatal there.
type OwnershipCheck struct {
	// Packages is the number of core package directories the census read.
	Packages int
	// Declared is the number of exported symbols those packages declare.
	Declared int
	// Referenced is the number of those symbols a production file outside their package names.
	Referenced int
	// Findings is every way the table and the tree disagree, sorted.
	Findings []string
}

// CheckOwnership holds src/core/OWNERSHIP.md to the tree at root, in both directions: every
// exported symbol a core package declares has exactly one row, every row names a symbol that still
// exists, and every row states the strongest justification the reference graph backs. It is the
// finder behind core/guard.AssertSymbolOwnership, and it reads the tree with the same census
// RenderSymbolOwnership writes from.
func CheckOwnership(root string) (OwnershipCheck, error) {
	doc, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ownershipDoc)))
	if err != nil {
		return OwnershipCheck{}, errs.Wrapf(err, "reading %s", ownershipDoc)
	}

	rows, findings := parseSymbolOwnershipDoc(string(doc))

	census, err := buildSymbolCensus(root)
	if err != nil {
		return OwnershipCheck{}, errs.Wrapf(err, "reading the core symbol census under %s", root)
	}

	referenced := map[symbolKey]bool{}
	for key := range census.corePkgs {
		referenced[key] = true
	}
	for key := range census.apps {
		referenced[key] = true
	}

	findings = append(findings, checkSymbolOwnership(rows, census)...)
	sort.Strings(findings)

	return OwnershipCheck{
		Packages:   len(census.pkgs),
		Declared:   len(census.declared),
		Referenced: len(referenced),
		Findings:   findings,
	}, nil
}

// ---- the document --------------------------------------------------------------------------

// parseSymbolOwnershipDoc reads the table. A malformed row is a finding rather than a parse
// failure, so one bad cell reports itself instead of silently shortening the table and turning
// every symbol it covered into a missing row.
func parseSymbolOwnershipDoc(doc string) ([]symbolRow, []string) {
	var rows []symbolRow
	var findings []string

	table, ok := TableUnder(strings.Split(doc, "\n"), symbolOwnershipHeading)
	if !ok {
		return nil, []string{fmt.Sprintf("%s has no %q table", ownershipDoc, symbolOwnershipHeading)}
	}
	for _, row := range table {
		if len(row.Cells) != 4 {
			findings = append(findings, fmt.Sprintf(
				"%s:%d: an ownership row needs 4 cells, found %d", ownershipDoc, row.Line, len(row.Cells)))
			continue
		}
		rows = append(rows, symbolRow{
			pkg:           row.Cells[0],
			symbol:        row.Cells[1],
			justification: row.Cells[2],
			// The note comes from the raw line rather than from the parsed cell, because splitRow
			// strips backticks -- right for an identifier cell, wrong for prose that cites one,
			// and a round trip through ownershipdump would otherwise rewrite every note it read.
			note: rawCell(row.Raw, 3),
			line: row.Line,
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
	for pkg := range c.linkedCore[key] {
		out = append(out, pkg)
	}
	for app := range c.linkedApps[key] {
		out = append(out, app)
	}
	sort.Strings(out)
	return out
}

// namedByOwnPackage reports whether the declaring package's own production code names a symbol at
// all, justified or not. It is the other way a test-support row earns its second half: a type a
// fake returns, which no test names because every test takes it from the fake, is test support
// rather than something supporting nothing. The rules test pinning it is
// TestSymbolOwnership_ItsOwnPackageNamingATestSupportSymbolIsEvidence.
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
			for name, typeNames := range pkg.valueType {
				if !pkg.exported[name] {
					continue
				}
				for typeName := range typeNames {
					if best[symbolKey{pkg: dir, name: typeName}] == "" {
						continue
					}
					if set(symbolKey{pkg: dir, name: name}, justificationReachable) {
						changed = true
					}
					break
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

// buildSymbolCensus loads the four modules type-checked through core/pkgload, and reads from those
// packages every core package's exported declarations and internal reference graph, then every
// production and test reference to them from anywhere in the tree.
//
// A reference is an identifier the type checker resolved to a core symbol, which is an object
// declared at the package level of a core package: the declaring package and the name are the row
// it backs. Reading the object rather than the spelling is what makes a dot import a reference like
// any other, and a local, a parameter or a field spelled like a package or a symbol no reference at
// all. It is also what lets a test variant, the package type-checked a second time with its own
// tests, back the same rows as the package itself (#420).
//
// Production code is read as every release build selects it, pkgload.ReleaseBuilds: the
// declarations, the references from outside the declaring package, and the packages a binary
// links. A production reference in a file only another platform compiles is still shipped, and it
// can be the one that contradicts a test-support row. Test references are read from the test build
// of the machine the census runs on, since a test for another platform does not run there (#420
// decision 11). A file only a race build or a custom tag selects is read by neither.
//
// A package that does not load or type-check stops the census with pkgload's error naming it: a
// reading of a half-checked tree misses references, and a table written from it would be wrong
// (#420 decision 3). A module the build selects no package of holds none.
func buildSymbolCensus(root string) (*symbolCensus, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, errs.Wrapf(err, "resolving %s", root)
	}
	census := &symbolCensus{
		corePkgs:   map[symbolKey]map[string]bool{},
		apps:       map[symbolKey]map[string]bool{},
		tests:      map[symbolKey]bool{},
		linkedCore: map[symbolKey]map[string]bool{},
		linkedApps: map[symbolKey]map[string]bool{},
		pkgs:       map[string]*packageSymbols{},
		dirs:       map[string]string{},
	}

	builds := append(pkgload.ReleaseBuilds(), pkgload.Build{Tests: true})
	loaded, err := loadTree(abs, builds)
	if err != nil {
		return nil, err
	}
	release, tests := loaded[:len(builds)-1], loaded[len(builds)-1]

	// A platform's build adds what only its own files declare, so every build of a package is read
	// into the one record its directory has.
	for _, pkgs := range release {
		for _, lp := range pkgs {
			if !isCoreDir(lp.dir) {
				continue
			}
			pkg := census.pkgs[lp.dir]
			if pkg == nil {
				pkg = newPackageSymbols()
				census.pkgs[lp.dir] = pkg
			}
			census.dirs[lp.pkg.PkgPath] = lp.dir
			for _, file := range lp.pkg.Syntax {
				for _, decl := range file.Decls {
					readDecl(pkg, decl, lp.pkg.Types.Scope(), lp.pkg.TypesInfo)
				}
			}
		}
	}
	for dir, pkg := range census.pkgs {
		for _, node := range pkg.nodes {
			for name := range node.decl {
				pkg.ownRefs[name] = true
			}
			for name := range node.body {
				pkg.ownRefs[name] = true
			}
		}
		// A package declaring nothing exported owns no row. core/countries/generate and
		// core/timezones/generate are both package main whose only exported spellings sit inside
		// a raw string template.
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

	for _, pkgs := range release {
		linked := linkedPackages(pkgs)
		for _, lp := range pkgs {
			census.readProductionReferences(lp, linked[lp.dir])
		}
	}
	testOnly := testOnlyDeclarations(tests)
	for _, lp := range tests {
		census.readTestReferences(lp, testOnly)
	}
	return census, nil
}

// loadedPackage is one package a build of the tree holds, with its directory relative to the
// source root, which is how the table names a package.
type loadedPackage struct {
	dir string
	pkg *packages.Package
}

// loadTree loads every package of the four modules for each build, one slice per build in the
// order given. The first load error in build and then module order is the one returned. A package
// whose files are not under the root is the go command's own, a test binary's generated main, and
// names nothing.
func loadTree(root string, builds []pkgload.Build) ([][]loadedPackage, error) {
	var dirs []string
	for _, module := range sourceroot.ModuleDirs() {
		dirs = append(dirs, filepath.Join(root, filepath.FromSlash(module)))
	}
	loaded, err := pkgload.LoadBuilds(builds, dirs...)
	if err != nil {
		return nil, err
	}

	out := make([][]loadedPackage, len(builds))
	for b, pkgs := range loaded {
		for _, p := range pkgs {
			if len(p.GoFiles) == 0 {
				continue
			}
			rel, err := filepath.Rel(root, filepath.Dir(p.GoFiles[0]))
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				continue
			}
			out[b] = append(out[b], loadedPackage{dir: filepath.ToSlash(rel), pkg: p})
		}
	}
	return out, nil
}

func newPackageSymbols() *packageSymbols {
	return &packageSymbols{
		exported:  map[string]bool{},
		nodes:     map[string]*declNode{},
		valueType: map[string]map[string]bool{},
		ownRefs:   map[string]bool{},
	}
}

func isCoreDir(dir string) bool {
	return dir == "core" || strings.HasPrefix(dir, "core/")
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
		name := receiverTypeName(d, info)
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
						if pkg.valueType[name.Name] == nil {
							pkg.valueType[name.Name] = map[string]bool{}
						}
						pkg.valueType[name.Name][named] = true
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

// receiverTypeName returns the name of the type a method hangs off, read from the method's own
// object, so a pointer, parentheses and type parameters around the receiver's spelling change
// nothing. A method go/types gave no named receiver is discarded.
func receiverTypeName(d *ast.FuncDecl, info *types.Info) string {
	fn, ok := info.Defs[d.Name].(*types.Func)
	if !ok {
		return ""
	}
	recv := fn.Type().(*types.Signature).Recv()
	if recv == nil {
		return ""
	}
	t := types.Unalias(recv.Type())
	if ptr, isPtr := t.(*types.Pointer); isPtr {
		t = types.Unalias(ptr.Elem())
	}
	named, isNamed := t.(*types.Named)
	if !isNamed {
		return ""
	}
	return named.Obj().Name()
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
// Reading the syntax spec by spec instead once misclassified gender.Female, Male and Other as
// test-only while Gender itself was both-apps, caught during #385.
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
			switch e := Unparen(expr).(type) {
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
	switch head := Unparen(value).(type) {
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

// symbolOf returns the row an object backs: a symbol a core package declares at its package level
// and exports. A method, a field, a local and anything another module declares back none. An
// instantiated generic function or variable backs the row of the declaration it instantiates.
func (c *symbolCensus) symbolOf(obj types.Object) (symbolKey, bool) {
	switch o := obj.(type) {
	case *types.Func:
		obj = o.Origin()
	case *types.Var:
		obj = o.Origin()
	}
	if obj == nil || obj.Pkg() == nil || !obj.Exported() || obj.Pkg().Scope().Lookup(obj.Name()) != obj {
		return symbolKey{}, false
	}
	dir, ok := c.dirs[obj.Pkg().Path()]
	if !ok || !c.pkgs[dir].exported[obj.Name()] {
		return symbolKey{}, false
	}
	return symbolKey{pkg: dir, name: obj.Name()}, true
}

// readProductionReferences files every core symbol one production package names from outside the
// symbol's own package under the core package or the module that named it, and also as linked
// evidence when a binary of the build that loaded the package links it. A reference from inside
// the declaring package is the internal graph's, which readDecl has read.
func (c *symbolCensus) readProductionReferences(lp loadedPackage, linked bool) {
	for _, obj := range lp.pkg.TypesInfo.Uses {
		key, ok := c.symbolOf(obj)
		if !ok || key.pkg == lp.dir {
			continue
		}
		if isCoreDir(lp.dir) {
			addTo(c.corePkgs, key, lp.dir)
			if linked {
				addTo(c.linkedCore, key, lp.dir)
			}
			continue
		}
		module := moduleOfDir(lp.dir)
		if module == "" {
			continue
		}
		addTo(c.apps, key, module)
		if linked {
			addTo(c.linkedApps, key, module)
		}
	}
}

// readTestReferences records the core symbols one package of the test build names from its test
// files, which is the half of a test-support row the tree can supply rather than contradict. The
// declaring package's own tests count, internal and external alike: an internal test names a symbol
// unqualified, an external one through the import, and both resolve to the symbol's object. An
// internal test's own declaration of an exported name is no production symbol, even where a
// release build's file declares the same name, so a reference to it, one of testOnly, is evidence
// for nothing.
func (c *symbolCensus) readTestReferences(lp loadedPackage, testOnly map[types.Object]bool) {
	for ident, obj := range lp.pkg.TypesInfo.Uses {
		if !inTestFile(lp.pkg.Fset, ident.Pos()) {
			continue
		}
		if key, ok := c.symbolOf(obj); ok && !testOnly[obj] {
			c.tests[key] = true
		}
	}
}

// testOnlyDeclarations returns the package-level objects the test build's test files declare, read
// from each package's parsed source. An object's own position cannot say this: one another module
// imports comes from export data, whose positions carry the file a //line directive names, so a
// production declaration mapped to a _test.go name would read as a test's. A test-only declaration
// is only ever visible to its own package and that package's external test, both in the same load,
// so the object is the one their references resolve to.
func testOnlyDeclarations(pkgs []loadedPackage) map[types.Object]bool {
	testOnly := map[types.Object]bool{}
	for _, lp := range pkgs {
		scope := lp.pkg.Types.Scope()
		for ident, obj := range lp.pkg.TypesInfo.Defs {
			if obj != nil && obj.Parent() == scope && inTestFile(lp.pkg.Fset, ident.Pos()) {
				testOnly[obj] = true
			}
		}
	}
	return testOnly
}

// inTestFile reports whether pos is in a _test.go file: the file itself, not one a //line directive
// maps it to, since the directive moves where a diagnostic points and not which build compiles it.
func inTestFile(fset *token.FileSet, pos token.Pos) bool {
	return strings.HasSuffix(fset.PositionFor(pos, false).Filename, "_test.go")
}

// addTo records value in the set evidence holds for key.
func addTo(evidence map[symbolKey]map[string]bool, key symbolKey, value string) {
	if evidence[key] == nil {
		evidence[key] = map[string]bool{}
	}
	evidence[key][value] = true
}

// linkedPackages returns every package directory a binary of one release build reaches, as
// directories relative to the source root: each main package of the four modules as that build
// selects it, developer commands included, and every first-party package its imports reach
// transitively in the same build.
//
// Only a test-support row reads this, and it is what lets the word mean what ARCHITECTURE.md's
// package table already says about core/guard -- "test support compiled into no binary". Test
// support in this tree is written in files with no _test.go suffix, so "a production file names
// it" and "a binary ships it" are genuinely different questions, and only the second one is the one
// test-support asks.
func linkedPackages(pkgs []loadedPackage) map[string]bool {
	linked := map[string]bool{}
	byID := make(map[string]loadedPackage, len(pkgs))
	var queue []string
	for _, lp := range pkgs {
		byID[lp.pkg.ID] = lp
		if lp.pkg.Name == "main" {
			queue = append(queue, lp.pkg.ID)
		}
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		lp, firstParty := byID[id]
		if !firstParty || seen[id] {
			continue
		}
		seen[id] = true
		linked[lp.dir] = true
		for _, imported := range lp.pkg.Imports {
			queue = append(queue, imported.ID)
		}
	}
	return linked
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

// ownershipTableHeader is the two lines every markdown table starts with, which TableUnder skips
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

	census, err := buildSymbolCensus(root)
	if err != nil {
		return "", nil, errs.Wrapf(err, "reading the core symbol census under %s", root)
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
	// not one, exactly where TableUnder stops reading.
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
