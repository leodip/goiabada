package testutil

// Seam 7: the fourth ARCHITECTURE.md table, over fixture trees written into a temp directory and
// read through the same graph builder and reference walk the real caller uses.
//
// The synthetic half exists for the reason architecture_rules_test.go sets out, and rule 7 needs it
// more than the other three do. The table was written from the tree, so the real tree satisfies it
// by construction and the only thing a passing run proves is that nothing crashed. Every direction
// the rule refuses therefore gets a fixture that must be caught, and the deliberate leniencies —
// test files, a symbol named in a comment, a package naming its own siblings — get one that must
// survive.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- fixture helpers -----------------------------------------------------------------------

// constantsPkg writes a core/constants declaring the given exported symbols.
func constantsPkg(symbols ...string) string {
	var b strings.Builder
	b.WriteString("package constants\n\nconst (\n")
	for _, s := range symbols {
		b.WriteString("\t" + s + " = \"" + strings.ToLower(s) + "\"\n")
	}
	b.WriteString(")\n")
	return b.String()
}

// pkgNaming writes a package that imports core/constants under the given local name, empty for the
// plain import, and names each symbol off it. The reference is a package-level var so the fixture
// stays a legal file rather than merely a parseable one.
func pkgNaming(name, local string, symbols ...string) string {
	var b strings.Builder
	b.WriteString("package " + name + "\n\nimport ")
	if local != "" {
		b.WriteString(local + " ")
	} else {
		local = "constants"
	}
	b.WriteString("\"example.test/core/constants\"\n\n")
	for i, s := range symbols {
		b.WriteString("var _ = " + local + "." + s + "\n")
		_ = i
	}
	return b.String()
}

// constantsRows builds the table from "<symbol> <justification> <issue>" triples.
func constantsRows(rows ...string) []constantsRow {
	out := make([]constantsRow, 0, len(rows))
	for i, r := range rows {
		f := strings.Fields(r)
		out = append(out, constantsRow{symbol: f[0], justification: f[1], issue: f[2], line: i + 1})
	}
	return out
}

// constantsBaselineFiles is the smallest tree rule 7 passes over: one declared symbol, named by one
// kernel package. Fixtures driving the reporting half carry it because the guard is fatal on a tree
// that declares no core constant or references none.
func constantsBaselineFiles() map[string]string {
	return map[string]string{
		"core/constants/constants.go": constantsPkg("Shared"),
		"core/errs/errs.go":           pkgNaming("errs", "", "Shared"),
	}
}

func withConstantsBaseline(files map[string]string) map[string]string {
	out := constantsBaselineFiles()
	for rel, src := range files {
		out[rel] = src
	}
	return out
}

// checkConstants runs the census and the checks over a fixture tree, sorted the way
// AssertArchitecture sorts findings.
func checkConstants(t *testing.T, files map[string]string, tables architectureTables) []string {
	t.Helper()

	root := writeTree(t, files)
	graph, err := buildImportGraph(root)
	require.NoError(t, err)
	census, err := buildConstantsCensus(root, graph)
	require.NoError(t, err)

	findings := checkConstantsOwnership(tables, graph, census)
	sort.Strings(findings)
	return findings
}

// kernelOwners is the ownership table most fixtures below need: core/constants and the packages
// naming it, each with an owner rule 7 reads.
func kernelOwners(rows ...string) architectureTables {
	all := append([]string{"core/constants kernel -"}, rows...)
	return architectureTables{owners: ownerRows(all...)}
}

// ---- both directions: the symbol and the row -----------------------------------------------

// TestConstantsOwnership_ASymbolWithNoRow is the direction that makes adding a constant to core a
// decision. Without it the table only ever describes what somebody remembered to write down.
func TestConstantsOwnership_ASymbolWithNoRow(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.constants = constantsRows("Shared kernel -")

	findings := checkConstants(t, map[string]string{
		"core/constants/constants.go": constantsPkg("Shared", "Forgotten"),
		"core/errs/errs.go":           pkgNaming("errs", "", "Shared", "Forgotten"),
	}, tables)

	assertFindings(t, findings, "holds no row for Forgotten")
}

// TestConstantsOwnership_ARowForASymbolThatIsGone is the other direction, and it is what stops the
// table outliving what it describes: the issue that moves a symbol has to delete its row.
func TestConstantsOwnership_ARowForASymbolThatIsGone(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.constants = constantsRows("Shared kernel -", "Departed kernel -")

	findings := checkConstants(t, constantsBaselineFiles(), tables)

	assertFindings(t, findings, "records Departed, which core/constants no longer declares")
}

// TestConstantsOwnership_ADuplicateRow keeps two rows for one symbol from disagreeing quietly, with
// whichever the parser read last deciding.
func TestConstantsOwnership_ADuplicateRow(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.constants = constantsRows("Shared kernel -", "Shared contract -")

	findings := checkConstants(t, constantsBaselineFiles(), tables)

	assertFindings(t, findings, "gives Shared a second row")
}

// ---- the justifications --------------------------------------------------------------------

// TestConstantsOwnership_AKernelRowNoKernelPackageBacks is the rule that expires a kernel claim.
// Once the kernel package naming a symbol stops naming it, rule 2 no longer holds the symbol in
// core and the row has to say what does.
func TestConstantsOwnership_AKernelRowNoKernelPackageBacks(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.constants = constantsRows("Shared kernel -")

	findings := checkConstants(t, map[string]string{
		"core/constants/constants.go":  constantsPkg("Shared"),
		"core/errs/errs.go":            pkg("errs"),
		"authserver/internal/a/a.go":   pkgNaming("a", "", "Shared"),
		"adminconsole/internal/b/b.go": pkgNaming("b", "", "Shared"),
	}, tables)

	assertFindings(t, findings, "records Shared as kernel, but the tree backs both-apps")
}

// TestConstantsOwnership_ABothAppsRowOnlyOneApplicationBacks catches the row that was true when it
// was written and stopped being true when one process let the symbol go. Left standing, it reads as
// a shared value while one process owns it outright.
func TestConstantsOwnership_ABothAppsRowOnlyOneApplicationBacks(t *testing.T) {
	tables := kernelOwners()
	tables.constants = constantsRows("Shared both-apps -")

	findings := checkConstants(t, map[string]string{
		"core/constants/constants.go": constantsPkg("Shared"),
		"authserver/internal/a/a.go":  pkgNaming("a", "", "Shared"),
	}, tables)

	assertFindings(t, findings, "records Shared as both-apps, but the tree backs contract: only authserver references it")
}

// TestConstantsOwnership_AMovingRowNoMovingPackageBacks is the burn-down half of the moving
// justification: the row exists because a package on its way out of core names the symbol, so when
// that package has gone the row must go with it.
func TestConstantsOwnership_AMovingRowNoMovingPackageBacks(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.constants = constantsRows("Shared moving #359")

	findings := checkConstants(t, constantsBaselineFiles(), tables)

	assertFindings(t, findings, "records Shared as moving, but the tree backs kernel: core/errs references it")
}

// TestConstantsOwnership_AMovingRowNamingTheWrongIssue holds the expiry date to the packages that
// set it. A row naming an issue that moves nothing pinning the symbol would survive that issue
// landing, which is the whole property the justification is for.
func TestConstantsOwnership_AMovingRowNamingTheWrongIssue(t *testing.T) {
	tables := kernelOwners("core/data authserver #359")
	tables.constants = constantsRows("Shared moving #360")

	findings := checkConstants(t, map[string]string{
		"core/constants/constants.go": constantsPkg("Shared"),
		"core/data/data.go":           pkgNaming("data", "", "Shared"),
	}, tables)

	assertFindings(t, findings, "says Shared stops being core's in #360, but the packages pinning it (core/data) move in #359")
}

// TestConstantsOwnership_AMovingRowWithNoIssue refuses the justification that expires without
// saying when, which is a waiver wearing a burn-down's clothes.
func TestConstantsOwnership_AMovingRowWithNoIssue(t *testing.T) {
	tables := kernelOwners("core/data authserver #359")
	tables.constants = constantsRows("Shared moving -")

	findings := checkConstants(t, map[string]string{
		"core/constants/constants.go": constantsPkg("Shared"),
		"core/data/data.go":           pkgNaming("data", "", "Shared"),
	}, tables)

	assertFindings(t, findings, "names \"-\" where an issue like #359 belongs")
}

// TestConstantsOwnership_AContractRowACheckableJustificationCovers is what keeps the escape hatch
// last. contract cannot be checked, so a row reaching for it while a checkable claim holds would be
// the way every row eventually becomes contract.
func TestConstantsOwnership_AContractRowACheckableJustificationCovers(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.constants = constantsRows("Shared contract -")

	findings := checkConstants(t, constantsBaselineFiles(), tables)

	assertFindings(t, findings, "records Shared as contract, but the tree backs kernel")
}

// TestConstantsOwnership_AContractRowNothingElseBacks is the leniency the rule above needs: when no
// checkable justification holds, contract is the answer and the guard accepts it without argument.
func TestConstantsOwnership_AContractRowNothingElseBacks(t *testing.T) {
	tables := kernelOwners()
	tables.constants = constantsRows("Shared contract -")

	findings := checkConstants(t, map[string]string{
		"core/constants/constants.go": constantsPkg("Shared"),
		"authserver/internal/a/a.go":  pkgNaming("a", "", "Shared"),
	}, tables)

	assert.Empty(t, findings)
}

// TestConstantsOwnership_AnUnknownJustification refuses a fifth value rather than reading it as one
// of the four, since an unrecognised cell that passed would be a row nothing checks.
func TestConstantsOwnership_AnUnknownJustification(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.constants = constantsRows("Shared probably -")

	findings := checkConstants(t, constantsBaselineFiles(), tables)

	assertFindings(t, findings, "gives Shared the justification \"probably\", which is none of kernel, both-apps, moving, contract")
}

// TestConstantsOwnership_AnIssueOnANonExpiringRow keeps the issue cell meaning one thing. A kernel
// row naming an issue reads as a burn-down entry that nothing will ever burn down.
func TestConstantsOwnership_AnIssueOnANonExpiringRow(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.constants = constantsRows("Shared kernel #359")

	findings := checkConstants(t, constantsBaselineFiles(), tables)

	assertFindings(t, findings, "gives Shared the issue #359; only a moving row names one")
}

// TestConstantsOwnership_ATreeTheTableDescribesPasses is the clean direction, and it is what keeps
// every case above from passing for the wrong reason: a guard matching nothing at all would satisfy
// all of them by producing no findings either.
func TestConstantsOwnership_ATreeTheTableDescribesPasses(t *testing.T) {
	tables := kernelOwners("core/errs kernel -", "core/data authserver #359")
	tables.constants = constantsRows(
		"Kerneled kernel -",
		"Shared both-apps -",
		"Pinned moving #359",
		"Promised contract -",
	)

	findings := checkConstants(t, map[string]string{
		"core/constants/constants.go":  constantsPkg("Kerneled", "Shared", "Pinned", "Promised"),
		"core/errs/errs.go":            pkgNaming("errs", "", "Kerneled"),
		"core/data/data.go":            pkgNaming("data", "", "Pinned"),
		"authserver/internal/a/a.go":   pkgNaming("a", "", "Shared", "Promised"),
		"adminconsole/internal/b/b.go": pkgNaming("b", "", "Shared"),
	}, tables)

	assert.Empty(t, findings)
}

// ---- how a reference is read ----------------------------------------------------------------

// TestConstantsOwnership_ReferencesAreReadFromTheAst pins what counts as naming a symbol. The
// alias case is load-bearing rather than decorative: every file naming both a core constant and its
// own process's imports core's as coreconstants, so a walk matching the text "constants." would
// miss exactly the files this change created.
func TestConstantsOwnership_ReferencesAreReadFromTheAst(t *testing.T) {
	root := writeTree(t, map[string]string{
		"core/constants/constants.go": constantsPkg("Aliased", "Mentioned", "Quoted"),
		"core/errs/errs.go":           pkgNaming("errs", "coreconstants", "Aliased"),
		"authserver/internal/a/a.go": "package a\n\n" +
			"import \"example.test/core/constants\"\n\n" +
			"// constants.Mentioned is named in a comment and is not a reference.\n" +
			"var mentioned = \"constants.Quoted\"\n" +
			"var _ = constants.Aliased\n" +
			"var _ = mentioned\n",
	})

	graph, err := buildImportGraph(root)
	require.NoError(t, err)
	census, err := buildConstantsCensus(root, graph)
	require.NoError(t, err)

	assert.Equal(t, []string{"Aliased", "Mentioned", "Quoted"}, census.declared)
	assert.ElementsMatch(t,
		[]string{"example.test/core/errs", "example.test/authserver/internal/a"},
		census.refs["Aliased"], "an aliased import is a reference and a plain one is too")
	assert.Empty(t, census.refs["Mentioned"], "a symbol named in a comment is not a reference")
	assert.Empty(t, census.refs["Quoted"], "a symbol named in a string literal is not a reference")
}

// TestConstantsOwnership_ALocalShadowingTheImportIsNotThePackage is the one way a selector can
// carry the import's spelling and mean something else. Nothing in this tree does it, and the case
// exists so that the check which excludes it is itself checked rather than assumed.
func TestConstantsOwnership_ALocalShadowingTheImportIsNotThePackage(t *testing.T) {
	root := writeTree(t, map[string]string{
		"core/constants/constants.go": constantsPkg("Real", "Shadowed"),
		"core/errs/errs.go":           pkgNaming("errs", "", "Real"),
		"authserver/internal/a/a.go": "package a\n\n" +
			"import \"example.test/core/constants\"\n\n" +
			"var _ = constants.Real\n\n" +
			"func f() string {\n" +
			"\tconstants := struct{ Shadowed string }{}\n" +
			"\treturn constants.Shadowed\n" +
			"}\n",
	})

	graph, err := buildImportGraph(root)
	require.NoError(t, err)
	census, err := buildConstantsCensus(root, graph)
	require.NoError(t, err)

	assert.NotEmpty(t, census.refs["Real"], "the import itself must still be read as a reference")
	assert.Empty(t, census.refs["Shadowed"], "a local shadowing the import is not the package")
}

// TestConstantsOwnership_TestFilesAreNotReferences is the leniency the justifications are written
// around. A test may name anything from anywhere, exactly as rules 2 and 3 allow, so a symbol kept
// alive only by a test is one no production code consumes.
func TestConstantsOwnership_TestFilesAreNotReferences(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.constants = constantsRows("Shared kernel -", "TestOnly contract -")

	findings := checkConstants(t, map[string]string{
		"core/constants/constants.go":       constantsPkg("Shared", "TestOnly"),
		"core/errs/errs.go":                 pkgNaming("errs", "", "Shared"),
		"adminconsole/internal/b/b.go":      pkg("b"),
		"adminconsole/internal/b/b_test.go": pkgNaming("b", "", "TestOnly"),
		"authserver/internal/a/a_test.go":   pkgNaming("a", "", "TestOnly"),
	}, tables)

	assert.Empty(t, findings, "two test files naming it must not add up to both-apps")
}

// TestConstantsOwnership_ThePackageDoesNotJustifyItself keeps core/constants out of its own census.
// It is a kernel package, so counting a sibling file's reference would make every symbol kernel and
// the table would pass whatever it said.
func TestConstantsOwnership_ThePackageDoesNotJustifyItself(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.constants = constantsRows("Shared kernel -", "Internal contract -")

	findings := checkConstants(t, map[string]string{
		"core/constants/constants.go": constantsPkg("Shared", "Internal"),
		"core/constants/uses.go":      "package constants\n\nvar _ = Internal\n",
		"core/errs/errs.go":           pkgNaming("errs", "", "Shared"),
	}, tables)

	assert.Empty(t, findings, "a symbol named only by its own package is backed by nothing")
}

// ---- the reporting half ----------------------------------------------------------------------

// TestConstantsOwnership_TheGuardFailsOnASymbolWithNoRow drives rule 7 through assertArchitecture,
// which is the path the three module tiers take.
func TestConstantsOwnership_TheGuardFailsOnASymbolWithNoRow(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), withConstantsBaseline(map[string]string{
		"core/api/api.go":             pkg("api"),
		"core/constants/constants.go": constantsPkg("Shared", "Forgotten"),
	}))

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Failed(), "a symbol with no row passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "holds no row for Forgotten")
}

// TestConstantsOwnership_TheGuardIsFatalWithNoDeclarations is the walk that reached nothing. A
// census reading no declaration satisfies "every symbol has a row" for no symbols at all, which is
// how this half of the guard would die still green.
func TestConstantsOwnership_TheGuardIsFatalWithNoDeclarations(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), map[string]string{
		"core/api/api.go":             pkg("api"),
		"core/constants/constants.go": "package constants\n\nconst unexported = \"x\"\n",
		"core/errs/errs.go":           pkg("errs"),
	})

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Stopped, "a core/constants declaring nothing exported must be fatal")
	assert.Contains(t, report.Fatal, "found no exported declarations in core/constants")
}

// TestConstantsOwnership_TheGuardIsFatalWithNoReferences is the same failure from the other side: a
// reference walk that matched nothing would rest every justification on an empty set, so every
// kernel and both-apps row would fail at once rather than quietly pass. Fatal is still the right
// answer, because the walk being broken is not a fact about the tree.
func TestConstantsOwnership_TheGuardIsFatalWithNoReferences(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), map[string]string{
		"core/api/api.go":             pkg("api"),
		"core/constants/constants.go": constantsPkg("Shared"),
		"core/errs/errs.go":           pkg("errs"),
	})

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Stopped, "a tree referencing no core constant must be fatal")
	assert.Contains(t, report.Fatal, "found no production reference to any core/constants symbol")
}

// TestConstantsOwnership_TheGuardIsFatalWithNoConstantsPackage pins the third way the walk stops
// meaning anything: core/constants itself being renamed or removed without the table going with it.
func TestConstantsOwnership_TheGuardIsFatalWithNoConstantsPackage(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), map[string]string{
		"core/api/api.go": pkg("api"),
	})

	report := RunGuard(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Stopped, "a tree with no core/constants must be fatal")
	assert.Contains(t, report.Fatal, "census")
}

// ---- the real table --------------------------------------------------------------------------

// TestConstantsOwnership_TheRealTableIsHeldByItsRows takes ARCHITECTURE.md apart one row at a time,
// as the exception and foreign tables already are. The tree satisfies the table by construction, so
// the only way to learn whether the rows are load-bearing is to break each one and watch.
func TestConstantsOwnership_TheRealTableIsHeldByItsRows(t *testing.T) {
	root := SourceRoot(t)

	doc, err := os.ReadFile(filepath.Join(filepath.Dir(root), architectureDoc))
	require.NoError(t, err)
	tables, findings := parseArchitectureDoc(string(doc))
	require.Empty(t, findings)
	require.NotEmpty(t, tables.constants)

	graph, err := buildImportGraph(root)
	require.NoError(t, err)
	census, err := buildConstantsCensus(root, graph)
	require.NoError(t, err)
	require.Empty(t, checkConstantsOwnership(tables, graph, census))

	// Every justification the table uses must be reachable from every row, so that flipping a row
	// is a real change of claim rather than a spelling the checks ignore.
	others := map[string][]string{
		justificationKernel:   {justificationBothApps, justificationMoving, justificationContract},
		justificationBothApps: {justificationKernel, justificationMoving, justificationContract},
		justificationMoving:   {justificationKernel, justificationBothApps, justificationContract},
	}

	for i, row := range tables.constants {
		t.Run(row.symbol+" dropped", func(t *testing.T) {
			kept := architectureTables{owners: tables.owners}
			for _, r := range tables.constants {
				if r != row {
					kept.constants = append(kept.constants, r)
				}
			}
			findings := checkConstantsOwnership(kept, graph, census)
			require.Len(t, findings, 1)
			assert.Contains(t, findings[0], "holds no row for "+row.symbol)
		})

		for _, flipped := range others[row.justification] {
			t.Run(row.symbol+" as "+flipped, func(t *testing.T) {
				changed := architectureTables{owners: tables.owners}
				changed.constants = append(changed.constants, tables.constants...)
				changed.constants[i].justification = flipped
				if flipped == justificationMoving {
					changed.constants[i].issue = "#359"
				} else {
					changed.constants[i].issue = "—"
				}

				findings := checkConstantsOwnership(changed, graph, census)
				require.Len(t, findings, 1)
				assert.Contains(t, findings[0], row.symbol)
				assert.Contains(t, findings[0], "the tree backs "+row.justification)
			})
		}
	}
}

// TestConstantsOwnership_TheRealTableCountsWhatTheTreeDeclares is the cheap whole-table assertion
// the row-by-row cases above cannot make: that the walk found the package at all, and that the
// table covers it exactly rather than approximately.
func TestConstantsOwnership_TheRealTableCountsWhatTheTreeDeclares(t *testing.T) {
	root := SourceRoot(t)

	doc, err := os.ReadFile(filepath.Join(filepath.Dir(root), architectureDoc))
	require.NoError(t, err)
	tables, _ := parseArchitectureDoc(string(doc))

	graph, err := buildImportGraph(root)
	require.NoError(t, err)
	census, err := buildConstantsCensus(root, graph)
	require.NoError(t, err)

	symbols := make([]string, 0, len(tables.constants))
	for _, row := range tables.constants {
		symbols = append(symbols, row.symbol)
	}
	sort.Strings(symbols)

	assert.Equal(t, census.declared, symbols)
}
