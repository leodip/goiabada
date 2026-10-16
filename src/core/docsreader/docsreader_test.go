package docsreader

// The reader's own rules. Every docs test reads the site through this package, so what a heading
// inside a fence, a deeper heading, a missing section and an escaped pipe in a cell read is held
// here, where a change shows before it shows anywhere else (#536).

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// sectionPage holds a section of its own with prose, a fenced block whose heading repeats the
// section's, a subsection, and a section after it.
const sectionPage = "## Before\n" +
	"\n" +
	"`OUTSIDE` above.\n" +
	"\n" +
	"## Time zone\n" +
	"\n" +
	"Both servers read `TZ`.\n" +
	"\n" +
	"```\n" +
	"## Time zone\n" +
	"`IN_FENCE`\n" +
	"```\n" +
	"\n" +
	"### Detail\n" +
	"\n" +
	"`NESTED`\n" +
	"\n" +
	"## Next\n" +
	"\n" +
	"`AFTER`\n"

// TestSectionText_ADeeperHeadingIsPartOfTheSection: a deeper heading's line and the prose under it
// are part of the section, and fenced lines are too, while the sections around it are not.
func TestSectionText_ADeeperHeadingIsPartOfTheSection(t *testing.T) {
	section, found := SectionText(sectionPage, "## Time zone")
	if !found {
		t.Fatal("the page has a ## Time zone section")
	}
	for _, want := range []string{"`TZ`", "IN_FENCE", "### Detail", "`NESTED`"} {
		if !strings.Contains(section, want) {
			t.Errorf("the section leaves out %s:\n%s", want, section)
		}
	}
	for _, outside := range []string{"OUTSIDE", "AFTER"} {
		if strings.Contains(section, outside) {
			t.Errorf("the section reads %s, which is outside it:\n%s", outside, section)
		}
	}
}

// TestSectionText_AHeadingInsideAFenceOpensNothing: the fenced copy of the heading is not the
// section's heading, and a page whose only such heading is fenced has no such section.
func TestSectionText_AHeadingInsideAFenceOpensNothing(t *testing.T) {
	fenced := "```\n## Time zone\n`TZ`\n```\n"
	if _, found := SectionText(fenced, "## Time zone"); found {
		t.Error("a heading inside a fence opened a section")
	}
}

// TestSectionText_AHeadingInsideAFenceEndsNothing: a heading inside a fence is not the next
// heading of the section's level, so the prose under it is still part of the section.
func TestSectionText_AHeadingInsideAFenceEndsNothing(t *testing.T) {
	page := "## Time zone\n\n`TZ`\n\n```\n## Next\n`IN_FENCE`\n```\n\n`STILL_IN`\n\n## Next\n\n`AFTER`\n"
	section, found := SectionText(page, "## Time zone")
	if !found {
		t.Fatal("the page has a ## Time zone section")
	}
	if !strings.Contains(section, "STILL_IN") {
		t.Errorf("a heading inside a fence ended the section:\n%s", section)
	}
	if strings.Contains(section, "AFTER") {
		t.Errorf("the section read past its end:\n%s", section)
	}
}

// TestSectionText_AMissingSectionReadsNothing: found is false and the text is empty, so a check
// that read nothing cannot pass as one that did.
func TestSectionText_AMissingSectionReadsNothing(t *testing.T) {
	section, found := SectionText("## Run tests\n\n| `x` |\n", "## Run the tests")
	if found || section != "" {
		t.Errorf("a page with no such section read %q", section)
	}
}

// TestSectionText_AnEmptyHeadingReadsTheWholePage: the readers that scan a whole page ask for it
// with an empty heading.
func TestSectionText_AnEmptyHeadingReadsTheWholePage(t *testing.T) {
	page := "# Title\n\n| a |\n|---|\n| b |\n"
	whole, found := SectionText(page, "")
	if !found || whole != page {
		t.Errorf("an empty heading read %q", whole)
	}
}

// TestTables_HeadersDelimitersAndDataRows: the header is the row a delimiter row follows, the
// delimiter row is neither, fenced rows are no rows, and a page reads its tables in order.
func TestTables_HeadersDelimitersAndDataRows(t *testing.T) {
	text := "intro\n" +
		"| Tier | What |\n" +
		"|---|:-:|\n" +
		"| `x` | one |\n" +
		"| `y` and `z` | two |\n" +
		"\n" +
		"```\n" +
		"| `fenced` | no |\n" +
		"```\n" +
		"\n" +
		"| Second |\n" +
		"|---|\n" +
		"| `b` |\n"
	tables := Tables(text)
	if len(tables) != 2 {
		t.Fatalf("%d tables, want 2: %+v", len(tables), tables)
	}
	if got, want := strings.Join(tables[0].Header, "|"), "Tier|What"; got != want {
		t.Errorf("first header %q, want %q", got, want)
	}
	if len(tables[0].Rows) != 2 || tables[0].Rows[0][0] != "`x`" || tables[0].Rows[1][0] != "`y` and `z`" {
		t.Errorf("first table rows %+v", tables[0].Rows)
	}
	if len(tables[1].Rows) != 1 || tables[1].Rows[0][0] != "`b`" {
		t.Errorf("second table rows %+v", tables[1].Rows)
	}
}

// TestTables_AnEscapedPipeStaysInItsCell: a pipe escaped inside a cell does not split it, and a
// code span keeps its backticks.
func TestTables_AnEscapedPipeStaysInItsCell(t *testing.T) {
	text := "| Setting | Example |\n" +
		"|---|---|\n" +
		"| `a\\|b` | `x` |\n" +
		"| plain | y |\n"
	tables := Tables(text)
	if len(tables) != 1 || len(tables[0].Rows) != 2 {
		t.Fatalf("tables %+v", tables)
	}
	if got, want := tables[0].Rows[0][0], "`a|b`"; got != want {
		t.Errorf("the escaped pipe left its cell: %q, want %q", got, want)
	}
	if got, want := tables[0].Rows[0][1], "`x`"; got != want {
		t.Errorf("a code span lost its backticks: %q, want %q", got, want)
	}
}

// TestRow_EveryBackslashReadsTheCharacterAfterIt: a pipe escaped inside a cell stays in it, a
// doubled backslash is kept as written — under CommonMark the pipe after it is then a column
// separator — and any other backslash keeps the character after it, inside a code span or out of
// one, since a cell is the text it is written as. The empty cell after a closing pipe is not a
// cell.
func TestRow_EveryBackslashReadsTheCharacterAfterIt(t *testing.T) {
	for _, row := range []struct {
		line string
		want []string
	}{
		{`| C:\\| ready |`, []string{`C:\\`, "ready"}},
		{`| a\|b | x |`, []string{"a|b", "x"}},
		{`| a \|`, []string{"a |"}},
		{`| a | |`, []string{"a", ""}},
		{"| `C:\\\\dir` | `a\\*b` |", []string{"`C:\\\\dir`", "`a\\*b`"}},
	} {
		if got := Row(row.line); !slices.Equal(got, row.want) {
			t.Errorf("Row(%q) = %q, want %q", row.line, got, row.want)
		}
	}
}

// TestTables_ARowOfEmptyCellsIsData: a delimiter row is dashes in every cell, so a row whose cells
// are all empty is a header or a data row, never the row under a header.
func TestTables_ARowOfEmptyCellsIsData(t *testing.T) {
	tables := Tables("| | |\n|:--|--:|\n| `a` | b |\n| | |\n")
	if len(tables) != 1 {
		t.Fatalf("tables %+v", tables)
	}
	if got, want := tables[0].Header, []string{"", ""}; !slices.Equal(got, want) {
		t.Errorf("header %q, want %q", got, want)
	}
	if len(tables[0].Rows) != 2 || !slices.Equal(tables[0].Rows[1], []string{"", ""}) {
		t.Errorf("rows %q, want the code row and the empty one", tables[0].Rows)
	}
}

// TestTables_ARowOfDashesBelowTheDelimiterIsData: only the delimiter row under the header is
// skipped, so a placeholder row of dashes in the body is a data row, as the page renders it.
func TestTables_ARowOfDashesBelowTheDelimiterIsData(t *testing.T) {
	tables := Tables("| Record | Level |\n|---|---|\n| `a` | `INFO` |\n| - | - |\n|---|---|\n")
	if len(tables) != 1 {
		t.Fatalf("tables %+v", tables)
	}
	want := [][]string{{"`a`", "`INFO`"}, {"-", "-"}, {"---", "---"}}
	if got := tables[0].Rows; !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Errorf("rows %q, want %q", got, want)
	}
}

// TestTables_AFenceLineEndsATable: a fence line ends the table before it, so an empty fenced
// block between two tables leaves them two tables.
func TestTables_AFenceLineEndsATable(t *testing.T) {
	tables := Tables("| A |\n|---|\n| a |\n```\n```\n| B |\n|---|\n| b |\n")
	if len(tables) != 2 {
		t.Fatalf("%d tables, want 2: %+v", len(tables), tables)
	}
	if got := tables[1].Header; !slices.Equal(got, []string{"B"}) {
		t.Errorf("second header %q, want [B]", got)
	}
}

// TestTables_ARowNoDelimiterFollowsIsData: a row a delimiter row does not follow is not a header,
// so a table written without one reads as rows only.
func TestTables_ARowNoDelimiterFollowsIsData(t *testing.T) {
	tables := Tables("### Narrow it\n\n| `nested` | no header row |\n")
	if len(tables) != 1 || tables[0].Header != nil {
		t.Fatalf("tables %+v", tables)
	}
	if len(tables[0].Rows) != 1 || tables[0].Rows[0][0] != "`nested`" {
		t.Errorf("rows %+v", tables[0].Rows)
	}
}

// TestRows_FlattensEveryTablesDataRows: the pages that list one row per variable read every table
// in a section as one list of rows.
func TestRows_FlattensEveryTablesDataRows(t *testing.T) {
	rows := Rows("| A |\n|---|\n| a |\n\n| B |\n|---|\n| b |\n")
	if len(rows) != 2 || rows[0][0] != "a" || rows[1][0] != "b" {
		t.Errorf("rows %+v", rows)
	}
}

// TestSection_ReadsThePageAndNamesWhatItCannotRead: a page that cannot be read, and one with no
// such section, are errors that name the page.
func TestSection_ReadsThePageAndNamesWhatItCannotRead(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "page.mdx"), []byte("## Time zone\n\n`TZ`\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Section(root, "docs/page.mdx", "## Time zone"); err != nil {
		t.Errorf("reading a section that exists: %v", err)
	}
	if _, err := Section(root, "docs/absent.mdx", "## Time zone"); err == nil ||
		!strings.Contains(err.Error(), "reading docs/absent.mdx") {
		t.Errorf("a page that cannot be read: %v", err)
	}
	if _, err := Section(root, "docs/page.mdx", "## Absent"); err == nil ||
		!strings.Contains(err.Error(), `docs/page.mdx has no "## Absent" section`) {
		t.Errorf("a section that is missing: %v", err)
	}
}
