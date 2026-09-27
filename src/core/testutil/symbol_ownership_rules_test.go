package testutil

// The reporting half of AssertSymbolOwnership, over fixture trees written into a temp directory.
//
// The census, the seven justifications and the generator are refgraph's, and so are their rules
// tests, in core/internal/refgraph/symbol_ownership_test.go. What is left here is the five lines
// that turn refgraph.CheckOwnership's answer into Errorf and Fatalf, which is the half whose
// defect disables the guard across every module with nothing going red (#333, #431).

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// symbolReportingFiles is the smallest tree the census justifies whole: one exported type another
// core package names in production, which makes it kernel.
func symbolReportingFiles(rows ...string) map[string]string {
	return map[string]string{
		"core/shared/shared.go": "package shared\n\ntype Kernelled struct{}\n",
		"core/other/other.go": `package other

import "example.test/core/shared"

var _ = shared.Kernelled{}
`,
		"core/OWNERSHIP.md": symbolOwnershipDoc(rows...),
	}
}

// symbolOwnershipDoc renders a whole OWNERSHIP.md around a table from "<package> <symbol>
// <justification> <note...>" lines, which is what the reporting half reads off disk.
func symbolOwnershipDoc(rows ...string) string {
	var b strings.Builder
	b.WriteString("# Core symbol ownership\n\nPreamble prose the parser never reads.\n\n")
	b.WriteString("### Core symbol ownership\n\n")
	b.WriteString("| package | symbol | justification | note |\n|---|---|---|---|\n")
	for _, r := range rows {
		f := strings.SplitN(r, " ", 4)
		note := "—"
		if len(f) == 4 {
			note = f[3]
		}
		b.WriteString("| `" + f[0] + "` | `" + f[1] + "` | " + f[2] + " | " + note + " |\n")
	}
	return b.String()
}

// TestSymbolOwnership_ReportingHalfPasses drives assertSymbolOwnership itself over a tree its table
// describes.
func TestSymbolOwnership_ReportingHalfPasses(t *testing.T) {
	root := writeTree(t, symbolReportingFiles("core/shared Kernelled kernel —"))

	report := RunGuard(func(r Reporter) { assertSymbolOwnership(r, root) })

	assert.False(t, report.Failed(), "findings:\n%s", report.Text())
}

// TestSymbolOwnership_ReportingHalfReports is the other half: a finding reaches Errorf rather than
// being computed and dropped. Blinding the five lines that report is what disabled
// AssertNoDeadInterfaces across every module with nothing going red.
func TestSymbolOwnership_ReportingHalfReports(t *testing.T) {
	root := writeTree(t, symbolReportingFiles("core/shared Kernelled reachable —"))

	report := RunGuard(func(r Reporter) { assertSymbolOwnership(r, root) })

	assert.True(t, report.Failed())
	assert.False(t, report.Stopped)
	assert.Contains(t, report.Text(), "but the tree backs kernel")
}

// TestSymbolOwnership_ACensusThatCannotBeReadIsFatal is the error arm: a tree with no OWNERSHIP.md
// stops the guard rather than reading as a table with no rows.
func TestSymbolOwnership_ACensusThatCannotBeReadIsFatal(t *testing.T) {
	files := symbolReportingFiles()
	delete(files, "core/OWNERSHIP.md")
	root := writeTree(t, files)

	report := RunGuard(func(r Reporter) { assertSymbolOwnership(r, root) })

	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "reading core/OWNERSHIP.md")
}

// TestSymbolOwnership_TheWalkThatReachedNothing is the failure a clean tree cannot be told apart
// from a correct one. A census that read no declaration satisfies "every symbol has a row" over an
// empty set.
func TestSymbolOwnership_TheWalkThatReachedNothing(t *testing.T) {
	root := writeTree(t, map[string]string{
		"core/OWNERSHIP.md": symbolOwnershipDoc(),
		"core/quiet/quiet.go": `package quiet

func helper() int { return 1 }
`,
	})

	report := RunGuard(func(r Reporter) { assertSymbolOwnership(r, root) })

	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "found no exported declarations in any core package")
}

// TestSymbolOwnership_TheWalkThatFoundNoPackage is the same failure one step earlier, and it is
// the one a mistyped root produces: a guard rooted at the wrong directory passes everything.
func TestSymbolOwnership_TheWalkThatFoundNoPackage(t *testing.T) {
	root := writeTree(t, map[string]string{"core/OWNERSHIP.md": symbolOwnershipDoc()})

	report := RunGuard(func(r Reporter) { assertSymbolOwnership(r, root) })

	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "found no core packages under")
}

// TestSymbolOwnership_TheWalkThatFoundNoReference is the same failure one step along: declarations
// read, but nothing naming them, which would rest every justification on an empty set.
func TestSymbolOwnership_TheWalkThatFoundNoReference(t *testing.T) {
	root := writeTree(t, map[string]string{
		"core/OWNERSHIP.md":     symbolOwnershipDoc("core/lonely Thing contract Nothing names it."),
		"core/lonely/lonely.go": "package lonely\n\ntype Thing struct{}\n",
	})

	report := RunGuard(func(r Reporter) { assertSymbolOwnership(r, root) })

	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "found no production reference to any core symbol")
}
