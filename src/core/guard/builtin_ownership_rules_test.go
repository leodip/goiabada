package guard

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

	"github.com/leodip/goiabada/core/internal/refgraph"
)

// ---- fixture helpers -----------------------------------------------------------------------

// builtinSource writes a core/builtin declaring the given exported symbols.
func builtinSource(symbols ...string) string {
	var b strings.Builder
	b.WriteString("package builtin\n\nconst (\n")
	for _, s := range symbols {
		b.WriteString("\t" + s + " = \"" + strings.ToLower(s) + "\"\n")
	}
	b.WriteString(")\n")
	return b.String()
}

// pkgNaming writes a package that imports core/builtin under the given local name, empty for the
// plain import, and names each symbol off it. The reference is a package-level var so the fixture
// stays a legal file rather than merely a parseable one.
func pkgNaming(name, local string, symbols ...string) string {
	var b strings.Builder
	b.WriteString("package " + name + "\n\nimport ")
	if local != "" {
		b.WriteString(local + " ")
	} else {
		local = "builtin"
	}
	b.WriteString("\"example.test/core/builtin\"\n\n")
	for i, s := range symbols {
		b.WriteString("var _ = " + local + "." + s + "\n")
		_ = i
	}
	return b.String()
}

// builtinRows builds the table from "<symbol> <justification> <issue>" triples.
func builtinRows(rows ...string) []builtinRow {
	out := make([]builtinRow, 0, len(rows))
	for i, r := range rows {
		f := strings.Fields(r)
		out = append(out, builtinRow{symbol: f[0], justification: f[1], issue: f[2], line: i + 1})
	}
	return out
}

// builtinBaselineFiles is the smallest tree rule 7 passes over: one declared symbol, named by one
// kernel package. Fixtures driving the reporting half carry it because the guard is fatal on a tree
// that declares no built-in identifier or references none.
func builtinBaselineFiles() map[string]string {
	return map[string]string{
		"core/builtin/builtin.go": builtinSource("Shared"),
		"core/errs/errs.go":       pkgNaming("errs", "", "Shared"),
	}
}

func withBuiltinBaseline(files map[string]string) map[string]string {
	out := builtinBaselineFiles()
	for rel, src := range files {
		out[rel] = src
	}
	return out
}

// checkConstants runs the census and the checks over a fixture tree, sorted the way
// AssertArchitecture sorts findings.
func checkBuiltin(t *testing.T, files map[string]string, tables architectureTables) []string {
	t.Helper()

	root := writeTree(t, files)
	graph, err := refgraph.BuildImportGraph(root)
	require.NoError(t, err)
	census, err := buildBuiltinCensus(root, graph)
	require.NoError(t, err)

	findings := checkBuiltinOwnership(tables, graph, census)
	sort.Strings(findings)
	return findings
}

// kernelOwners is the ownership table most fixtures below need: core/builtin and the packages
// naming it, each with an owner rule 7 reads.
func kernelOwners(rows ...string) architectureTables {
	all := append([]string{"core/builtin kernel -"}, rows...)
	return architectureTables{owners: ownerRows(all...)}
}

// ---- both directions: the symbol and the row -----------------------------------------------

// TestBuiltinOwnership_ASymbolWithNoRow is the direction that makes adding a constant to core a
// decision. Without it the table only ever describes what somebody remembered to write down.
func TestBuiltinOwnership_ASymbolWithNoRow(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.builtin = builtinRows("Shared kernel -")

	findings := checkBuiltin(t, map[string]string{
		"core/builtin/builtin.go": builtinSource("Shared", "Forgotten"),
		"core/errs/errs.go":       pkgNaming("errs", "", "Shared", "Forgotten"),
	}, tables)

	assertFindings(t, findings, "holds no row for Forgotten")
}

// TestBuiltinOwnership_ARowForASymbolThatIsGone is the other direction, and it is what stops the
// table outliving what it describes: the issue that moves a symbol has to delete its row.
func TestBuiltinOwnership_ARowForASymbolThatIsGone(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.builtin = builtinRows("Shared kernel -", "Departed kernel -")

	findings := checkBuiltin(t, builtinBaselineFiles(), tables)

	assertFindings(t, findings, "records Departed, which core/builtin no longer declares")
}

// TestBuiltinOwnership_ADuplicateRow keeps two rows for one symbol from disagreeing quietly, with
// whichever the parser read last deciding.
func TestBuiltinOwnership_ADuplicateRow(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.builtin = builtinRows("Shared kernel -", "Shared contract -")

	findings := checkBuiltin(t, builtinBaselineFiles(), tables)

	assertFindings(t, findings, "gives Shared a second row")
}

// ---- the justifications --------------------------------------------------------------------

// TestBuiltinOwnership_AKernelRowNoKernelPackageBacks is the rule that expires a kernel claim.
// Once the kernel package naming a symbol stops naming it, rule 2 no longer holds the symbol in
// core and the row has to say what does.
func TestBuiltinOwnership_AKernelRowNoKernelPackageBacks(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.builtin = builtinRows("Shared kernel -")

	findings := checkBuiltin(t, map[string]string{
		"core/builtin/builtin.go":      builtinSource("Shared"),
		"core/errs/errs.go":            pkg("errs"),
		"authserver/internal/a/a.go":   pkgNaming("a", "", "Shared"),
		"adminconsole/internal/b/b.go": pkgNaming("b", "", "Shared"),
	}, tables)

	assertFindings(t, findings, "records Shared as kernel, but the tree backs both-apps")
}

// TestBuiltinOwnership_ABothAppsRowOnlyOneApplicationBacks catches the row that was true when it
// was written and stopped being true when one process let the symbol go. Left standing, it reads as
// a shared value while one process owns it outright.
func TestBuiltinOwnership_ABothAppsRowOnlyOneApplicationBacks(t *testing.T) {
	tables := kernelOwners()
	tables.builtin = builtinRows("Shared both-apps -")

	findings := checkBuiltin(t, map[string]string{
		"core/builtin/builtin.go":    builtinSource("Shared"),
		"authserver/internal/a/a.go": pkgNaming("a", "", "Shared"),
	}, tables)

	assertFindings(t, findings, "records Shared as both-apps, but the tree backs contract: only authserver references it")
}

// TestBuiltinOwnership_AMovingRowNoMovingPackageBacks is the burn-down half of the moving
// justification: the row exists because a package on its way out of core names the symbol, so when
// that package has gone the row must go with it.
func TestBuiltinOwnership_AMovingRowNoMovingPackageBacks(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.builtin = builtinRows("Shared moving #359")

	findings := checkBuiltin(t, builtinBaselineFiles(), tables)

	assertFindings(t, findings, "records Shared as moving, but the tree backs kernel: core/errs references it")
}

// TestBuiltinOwnership_AMovingRowNamingTheWrongIssue holds the expiry date to the packages that
// set it. A row naming an issue that moves nothing pinning the symbol would survive that issue
// landing, which is the whole property the justification is for.
func TestBuiltinOwnership_AMovingRowNamingTheWrongIssue(t *testing.T) {
	tables := kernelOwners("core/data authserver #359")
	tables.builtin = builtinRows("Shared moving #360")

	findings := checkBuiltin(t, map[string]string{
		"core/builtin/builtin.go": builtinSource("Shared"),
		"core/data/data.go":       pkgNaming("data", "", "Shared"),
	}, tables)

	assertFindings(t, findings, "says Shared stops being core's in #360, but the packages pinning it (core/data) move in #359")
}

// TestBuiltinOwnership_AMovingRowWithNoIssue refuses the justification that expires without
// saying when, which is a waiver wearing a burn-down's clothes.
func TestBuiltinOwnership_AMovingRowWithNoIssue(t *testing.T) {
	tables := kernelOwners("core/data authserver #359")
	tables.builtin = builtinRows("Shared moving -")

	findings := checkBuiltin(t, map[string]string{
		"core/builtin/builtin.go": builtinSource("Shared"),
		"core/data/data.go":       pkgNaming("data", "", "Shared"),
	}, tables)

	assertFindings(t, findings, "names \"-\" where an issue like #359 belongs")
}

// TestBuiltinOwnership_AContractRowACheckableJustificationCovers is what keeps the escape hatch
// last. contract cannot be checked, so a row reaching for it while a checkable claim holds would be
// the way every row eventually becomes contract.
func TestBuiltinOwnership_AContractRowACheckableJustificationCovers(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.builtin = builtinRows("Shared contract -")

	findings := checkBuiltin(t, builtinBaselineFiles(), tables)

	assertFindings(t, findings, "records Shared as contract, but the tree backs kernel")
}

// TestBuiltinOwnership_AContractRowNothingElseBacks is the leniency the rule above needs: when no
// checkable justification holds, contract is the answer and the guard accepts it without argument.
func TestBuiltinOwnership_AContractRowNothingElseBacks(t *testing.T) {
	tables := kernelOwners()
	tables.builtin = builtinRows("Shared contract -")

	findings := checkBuiltin(t, map[string]string{
		"core/builtin/builtin.go":    builtinSource("Shared"),
		"authserver/internal/a/a.go": pkgNaming("a", "", "Shared"),
	}, tables)

	assert.Empty(t, findings)
}

// TestBuiltinOwnership_AnUnknownJustification refuses a fifth value rather than reading it as one
// of the four, since an unrecognised cell that passed would be a row nothing checks.
func TestBuiltinOwnership_AnUnknownJustification(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.builtin = builtinRows("Shared probably -")

	findings := checkBuiltin(t, builtinBaselineFiles(), tables)

	assertFindings(t, findings, "gives Shared the justification \"probably\", which is none of kernel, both-apps, moving, contract")
}

// TestBuiltinOwnership_AnIssueOnANonExpiringRow keeps the issue cell meaning one thing. A kernel
// row naming an issue reads as a burn-down entry that nothing will ever burn down.
func TestBuiltinOwnership_AnIssueOnANonExpiringRow(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.builtin = builtinRows("Shared kernel #359")

	findings := checkBuiltin(t, builtinBaselineFiles(), tables)

	assertFindings(t, findings, "gives Shared the issue #359; only a moving row names one")
}

// TestBuiltinOwnership_ATreeTheTableDescribesPasses is the clean direction, and it is what keeps
// every case above from passing for the wrong reason: a guard matching nothing at all would satisfy
// all of them by producing no findings either.
func TestBuiltinOwnership_ATreeTheTableDescribesPasses(t *testing.T) {
	tables := kernelOwners("core/errs kernel -", "core/data authserver #359")
	tables.builtin = builtinRows(
		"Kerneled kernel -",
		"Shared both-apps -",
		"Pinned moving #359",
		"Promised contract -",
	)

	findings := checkBuiltin(t, map[string]string{
		"core/builtin/builtin.go":      builtinSource("Kerneled", "Shared", "Pinned", "Promised"),
		"core/errs/errs.go":            pkgNaming("errs", "", "Kerneled"),
		"core/data/data.go":            pkgNaming("data", "", "Pinned"),
		"authserver/internal/a/a.go":   pkgNaming("a", "", "Shared", "Promised"),
		"adminconsole/internal/b/b.go": pkgNaming("b", "", "Shared"),
	}, tables)

	assert.Empty(t, findings)
}

// ---- how a reference is read ----------------------------------------------------------------

// TestBuiltinOwnership_ReferencesAreReadFromTheAst pins what counts as naming a symbol. The
// alias case stays covered although no file in the tree aliases core/builtin: 64 files once imported
// core/constants as coreconstants, and a walk matching the text "builtin." would miss the next file
// that aliases it for a reason of its own (#351, #442).
func TestBuiltinOwnership_ReferencesAreReadFromTheAst(t *testing.T) {
	root := writeTree(t, map[string]string{
		"core/builtin/builtin.go": builtinSource("Aliased", "Mentioned", "Quoted"),
		"core/errs/errs.go":       pkgNaming("errs", "corebuiltin", "Aliased"),
		"authserver/internal/a/a.go": "package a\n\n" +
			"import \"example.test/core/builtin\"\n\n" +
			"// builtin.Mentioned is named in a comment and is not a reference.\n" +
			"var mentioned = \"builtin.Quoted\"\n" +
			"var _ = builtin.Aliased\n" +
			"var _ = mentioned\n",
	})

	graph, err := refgraph.BuildImportGraph(root)
	require.NoError(t, err)
	census, err := buildBuiltinCensus(root, graph)
	require.NoError(t, err)

	assert.Equal(t, []string{"Aliased", "Mentioned", "Quoted"}, census.declared)
	assert.ElementsMatch(t,
		[]string{"example.test/core/errs", "example.test/authserver/internal/a"},
		census.refs["Aliased"], "an aliased import is a reference and a plain one is too")
	assert.Empty(t, census.refs["Mentioned"], "a symbol named in a comment is not a reference")
	assert.Empty(t, census.refs["Quoted"], "a symbol named in a string literal is not a reference")
}

// TestBuiltinOwnership_ALocalShadowingTheImportIsNotThePackage is the one way a selector can
// carry the import's spelling and mean something else. Nothing in this tree does it, and the case
// exists so that the check which excludes it is itself checked rather than assumed.
func TestBuiltinOwnership_ALocalShadowingTheImportIsNotThePackage(t *testing.T) {
	root := writeTree(t, map[string]string{
		"core/builtin/builtin.go": builtinSource("Real", "Shadowed"),
		"core/errs/errs.go":       pkgNaming("errs", "", "Real"),
		"authserver/internal/a/a.go": "package a\n\n" +
			"import \"example.test/core/builtin\"\n\n" +
			"var _ = builtin.Real\n\n" +
			"func f() string {\n" +
			"\tbuiltin := struct{ Shadowed string }{}\n" +
			"\treturn builtin.Shadowed\n" +
			"}\n",
	})

	graph, err := refgraph.BuildImportGraph(root)
	require.NoError(t, err)
	census, err := buildBuiltinCensus(root, graph)
	require.NoError(t, err)

	assert.NotEmpty(t, census.refs["Real"], "the import itself must still be read as a reference")
	assert.Empty(t, census.refs["Shadowed"], "a local shadowing the import is not the package")
}

// TestBuiltinOwnership_TestFilesAreNotReferences is the leniency the justifications are written
// around. A test may name anything from anywhere, exactly as rules 2 and 3 allow, so a symbol kept
// alive only by a test is one no production code consumes.
func TestBuiltinOwnership_TestFilesAreNotReferences(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.builtin = builtinRows("Shared kernel -", "TestOnly contract -")

	findings := checkBuiltin(t, map[string]string{
		"core/builtin/builtin.go":           builtinSource("Shared", "TestOnly"),
		"core/errs/errs.go":                 pkgNaming("errs", "", "Shared"),
		"adminconsole/internal/b/b.go":      pkg("b"),
		"adminconsole/internal/b/b_test.go": pkgNaming("b", "", "TestOnly"),
		"authserver/internal/a/a_test.go":   pkgNaming("a", "", "TestOnly"),
	}, tables)

	assert.Empty(t, findings, "two test files naming it must not add up to both-apps")
}

// TestBuiltinOwnership_ThePackageDoesNotJustifyItself keeps core/builtin out of its own census.
// It is a kernel package, so counting a sibling file's reference would make every symbol kernel and
// the table would pass whatever it said.
func TestBuiltinOwnership_ThePackageDoesNotJustifyItself(t *testing.T) {
	tables := kernelOwners("core/errs kernel -")
	tables.builtin = builtinRows("Shared kernel -", "Internal contract -")

	findings := checkBuiltin(t, map[string]string{
		"core/builtin/builtin.go": builtinSource("Shared", "Internal"),
		"core/builtin/uses.go":    "package builtin\n\nvar _ = Internal\n",
		"core/errs/errs.go":       pkgNaming("errs", "", "Shared"),
	}, tables)

	assert.Empty(t, findings, "a symbol named only by its own package is backed by nothing")
}

// ---- the reporting half ----------------------------------------------------------------------

// TestBuiltinOwnership_TheGuardFailsOnASymbolWithNoRow drives rule 7 through assertArchitecture,
// which is the path the three module tiers take.
func TestBuiltinOwnership_TheGuardFailsOnASymbolWithNoRow(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), withShippedMains(withBuiltinBaseline(map[string]string{
		"core/api/api.go":         pkg("api"),
		"core/builtin/builtin.go": builtinSource("Shared", "Forgotten"),
	})))

	report := Run(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Failed(), "a symbol with no row passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "holds no row for Forgotten")
}

// TestBuiltinOwnership_TheGuardIsFatalWithNoDeclarations is the walk that reached nothing. A
// census reading no declaration satisfies "every symbol has a row" for no symbols at all, which is
// how this half of the guard would die still green.
func TestBuiltinOwnership_TheGuardIsFatalWithNoDeclarations(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), map[string]string{
		"core/api/api.go":         pkg("api"),
		"core/builtin/builtin.go": "package builtin\n\nconst unexported = \"x\"\n",
		"core/errs/errs.go":       pkg("errs"),
	})

	report := Run(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Stopped, "a core/builtin declaring nothing exported must be fatal")
	assert.Contains(t, report.Fatal, "found no exported declarations in core/builtin")
}

// TestBuiltinOwnership_TheGuardIsFatalWithNoReferences is the same failure from the other side: a
// reference walk that matched nothing would rest every justification on an empty set, so every
// kernel and both-apps row would fail at once rather than quietly pass. Fatal is still the right
// answer, because the walk being broken is not a fact about the tree.
func TestBuiltinOwnership_TheGuardIsFatalWithNoReferences(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), map[string]string{
		"core/api/api.go":         pkg("api"),
		"core/builtin/builtin.go": builtinSource("Shared"),
		"core/errs/errs.go":       pkg("errs"),
	})

	report := Run(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Stopped, "a tree referencing no built-in identifier must be fatal")
	assert.Contains(t, report.Fatal, "found no production reference to any core/builtin symbol")
}

// TestBuiltinOwnership_TheGuardIsFatalWithNoConstantsPackage pins the third way the walk stops
// meaning anything: core/builtin itself being renamed or removed without the table going with it.
func TestBuiltinOwnership_TheGuardIsFatalWithNoConstantsPackage(t *testing.T) {
	root := architectureFixture(t, architectureDocWith("| `core/api` | kernel | — |"), map[string]string{
		"core/api/api.go": pkg("api"),
	})

	report := Run(func(r Reporter) { assertArchitecture(r, root) })

	require.True(t, report.Stopped, "a tree with no core/builtin must be fatal")
	assert.Contains(t, report.Fatal, "census")
}

// ---- the real table --------------------------------------------------------------------------

// TestBuiltinOwnership_TheRealTableIsHeldByItsRows takes ARCHITECTURE.md apart one row at a time,
// as the exception and foreign tables already are. The tree satisfies the table by construction, so
// the only way to learn whether the rows are load-bearing is to break each one and watch.
func TestBuiltinOwnership_TheRealTableIsHeldByItsRows(t *testing.T) {
	root := SourceRoot(t)

	doc, err := os.ReadFile(filepath.Join(filepath.Dir(root), architectureDoc))
	require.NoError(t, err)
	tables, findings := parseArchitectureDoc(string(doc))
	require.Empty(t, findings)
	require.NotEmpty(t, tables.builtin)

	graph, err := refgraph.BuildImportGraph(root)
	require.NoError(t, err)
	census, err := buildBuiltinCensus(root, graph)
	require.NoError(t, err)
	require.Empty(t, checkBuiltinOwnership(tables, graph, census))

	// Every justification the table uses must be reachable from every row, so that flipping a row
	// is a real change of claim rather than a spelling the checks ignore.
	others := map[string][]string{
		refgraph.JustificationKernel:   {refgraph.JustificationBothApps, refgraph.JustificationMoving, refgraph.JustificationContract},
		refgraph.JustificationBothApps: {refgraph.JustificationKernel, refgraph.JustificationMoving, refgraph.JustificationContract},
		refgraph.JustificationMoving:   {refgraph.JustificationKernel, refgraph.JustificationBothApps, refgraph.JustificationContract},
	}

	for i, row := range tables.builtin {
		t.Run(row.symbol+" dropped", func(t *testing.T) {
			kept := architectureTables{owners: tables.owners}
			for _, r := range tables.builtin {
				if r != row {
					kept.builtin = append(kept.builtin, r)
				}
			}
			findings := checkBuiltinOwnership(kept, graph, census)
			require.Len(t, findings, 1)
			assert.Contains(t, findings[0], "holds no row for "+row.symbol)
		})

		for _, flipped := range others[row.justification] {
			t.Run(row.symbol+" as "+flipped, func(t *testing.T) {
				changed := architectureTables{owners: tables.owners}
				changed.builtin = append(changed.builtin, tables.builtin...)
				changed.builtin[i].justification = flipped
				if flipped == refgraph.JustificationMoving {
					changed.builtin[i].issue = "#359"
				} else {
					changed.builtin[i].issue = "—"
				}

				findings := checkBuiltinOwnership(changed, graph, census)
				require.Len(t, findings, 1)
				assert.Contains(t, findings[0], row.symbol)
				assert.Contains(t, findings[0], "the tree backs "+row.justification)
			})
		}
	}
}

// TestBuiltinOwnership_TheRealTableCountsWhatTheTreeDeclares is the cheap whole-table assertion
// the row-by-row cases above cannot make: that the walk found the package at all, and that the
// table covers it exactly rather than approximately.
func TestBuiltinOwnership_TheRealTableCountsWhatTheTreeDeclares(t *testing.T) {
	root := SourceRoot(t)

	doc, err := os.ReadFile(filepath.Join(filepath.Dir(root), architectureDoc))
	require.NoError(t, err)
	tables, _ := parseArchitectureDoc(string(doc))

	graph, err := refgraph.BuildImportGraph(root)
	require.NoError(t, err)
	census, err := buildBuiltinCensus(root, graph)
	require.NoError(t, err)

	symbols := make([]string, 0, len(tables.builtin))
	for _, row := range tables.builtin {
		symbols = append(symbols, row.symbol)
	}
	sort.Strings(symbols)

	assert.Equal(t, census.declared, symbols)
}
