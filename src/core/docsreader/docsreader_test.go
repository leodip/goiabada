package docsreader

// The reader's own rules. Every docs test reads the site through this package, so what a code
// fence is, and what a heading inside one, a deeper heading, a missing section and an escaped pipe
// in a cell read, is held here, where a change shows before it shows anywhere else (#536).

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

// TestSectionText_AHeadingInsideAnyFenceOpensNothing: the section walk reads fences by the rule
// the table walk does, so a heading inside a tilde fence, or after a shorter run inside a longer
// backtick fence, is code and opens no section.
func TestSectionText_AHeadingInsideAnyFenceOpensNothing(t *testing.T) {
	for name, page := range map[string]string{
		"a tilde fence":               "~~~\n## Time zone\n`TZ`\n~~~\n",
		"a four-backtick fence":       "````markdown\n```\n## Time zone\n`TZ`\n````\n",
		"a fence a language reopened": "```\n```bash\n## Time zone\n`TZ`\n```\n",
	} {
		t.Run(name, func(t *testing.T) {
			if section, found := SectionText(page, "## Time zone"); found {
				t.Errorf("a heading inside the fence opened a section:\n%s", section)
			}
		})
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

// TestTables_EachDataRowSaysItsLine: each data row has the 1-based line of the text it is on,
// counted past the header and delimiter rows, so a guard reporting page lines does not count them.
func TestTables_EachDataRowSaysItsLine(t *testing.T) {
	text := "# Catalog\n" +
		"\n" +
		"| metric | type |\n" +
		"|---|---|\n" +
		"| `a` | counter |\n" +
		"| `b` | gauge |\n"
	tables := Tables(text)
	if len(tables) != 1 {
		t.Fatalf("tables %+v", tables)
	}
	if got, want := tables[0].Lines, []int{5, 6}; !slices.Equal(got, want) {
		t.Errorf("lines %v, want %v", got, want)
	}
}

// TestTables_ARowOfATableWithNoHeaderSaysItsLine: with no delimiter row every row is a data row,
// the first included, and each says its own line.
func TestTables_ARowOfATableWithNoHeaderSaysItsLine(t *testing.T) {
	tables := Tables("intro\n| `a` | one |\n| `b` | two |\n")
	if len(tables) != 1 || tables[0].Header != nil {
		t.Fatalf("tables %+v", tables)
	}
	if got, want := tables[0].Lines, []int{2, 3}; !slices.Equal(got, want) {
		t.Errorf("lines %v, want %v", got, want)
	}
}

// TestTables_ARowAfterAFencedBlockSaysItsPageLine: the fenced lines are not rows but are still
// lines of the text, so a row after a fenced block says the line it is on, not a count of rows.
func TestTables_ARowAfterAFencedBlockSaysItsPageLine(t *testing.T) {
	text := "| A |\n" +
		"|---|\n" +
		"| a |\n" +
		"```\n" +
		"| fenced |\n" +
		"```\n" +
		"\n" +
		"| B |\n" +
		"|---|\n" +
		"| b1 |\n" +
		"| b2 |\n"
	tables := Tables(text)
	if len(tables) != 2 {
		t.Fatalf("%d tables, want 2: %+v", len(tables), tables)
	}
	if got, want := tables[0].Lines, []int{3}; !slices.Equal(got, want) {
		t.Errorf("first table lines %v, want %v", got, want)
	}
	if got, want := tables[1].Lines, []int{10, 11}; !slices.Equal(got, want) {
		t.Errorf("second table lines %v, want %v", got, want)
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

// TestCells_EveryBackslashReadsTheCharacterAfterIt: a pipe escaped inside a cell stays in it, a
// doubled backslash is kept as written — under CommonMark the pipe after it is then a column
// separator — and any other backslash keeps the character after it, inside a code span or out of
// one, since a cell is the text it is written as. The empty cell after a closing pipe is not a
// cell.
func TestCells_EveryBackslashReadsTheCharacterAfterIt(t *testing.T) {
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
		if got := cells(row.line); !slices.Equal(got, row.want) {
			t.Errorf("cells(%q) = %q, want %q", row.line, got, row.want)
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

// TestTables_AFenceClosesOnlyOnABareRunOfItsCharacterAtLeastAsLong: a fence opens on three or
// more backticks or tildes and closes only on a line that is a run of the same character at least
// as long, so a table in each fence below is code and the table after its closing line is the one
// table read. BlankColumn empties that table's column and keeps every fenced line as written.
func TestTables_AFenceClosesOnlyOnABareRunOfItsCharacterAtLeastAsLong(t *testing.T) {
	const fenced = "| Event | Details |\n|---|---|\n| `fenced` | `in_fence` |\n"
	const after = "\n| Event | Details |\n|---|---|\n| `real` | `payload_key` |\n"
	for _, tc := range []struct{ name, block string }{
		{"a tilde fence", "~~~\n" + fenced + "~~~\n"},
		{"a tilde fence with a language", "~~~yaml\n" + fenced + "~~~\n"},
		{"a three-backtick line inside a four-backtick fence", "````markdown\n```\n" + fenced + "```\n````\n"},
		{"a backtick line with a language inside an open fence", "```\n```go\n" + fenced + "```\n"},
		{"a tilde line inside a backtick fence", "```\n~~~\n" + fenced + "```\n"},
		{"a backtick line inside a tilde fence", "~~~\n```\n" + fenced + "~~~\n"},
		{"a tilde line with text after it inside a tilde fence", "~~~\n~~~ not a close\n" + fenced + "~~~\n"},
		{"a longer closing run", "```\n" + fenced + "`````\n"},
		{"whitespace after the closing run", "~~~~\n" + fenced + "~~~~ \t\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := "Prose.\n\n" + tc.block + after
			assertTables(t, Tables(text), []Table{
				{Header: []string{"Event", "Details"}, Rows: [][]string{{"`real`", "`payload_key`"}}},
			})
			blanked := BlankColumn(text, "Details")
			assertLinesKept(t, text, blanked, len(strings.Split(text, "\n"))-2)
			assertTables(t, Tables(blanked), []Table{
				{Header: []string{"Event", "Details"}, Rows: [][]string{{"`real`", ""}}},
			})
		})
	}
}

// TestTables_ARunOfTwoOpensNoFence: a fence opens on three backticks or tildes, so a prose line
// that starts with a double-backtick code span or a strikethrough is prose. The heading after it
// opens its section, and the table after it is read and blanked.
func TestTables_ARunOfTwoOpensNoFence(t *testing.T) {
	const after = "\n## Time zone\n\n| Event | Details |\n|---|---|\n| `real` | `payload_key` |\n"
	for name, prose := range map[string]string{
		"two backticks": "`` `TZ` `` names the zone.\n",
		"two tildes":    "~~Retired~~ names nothing.\n",
	} {
		t.Run(name, func(t *testing.T) {
			text := prose + after
			if _, found := SectionText(text, "## Time zone"); !found {
				t.Errorf("the heading after the prose opened no section:\n%s", text)
			}
			assertTables(t, Tables(text), []Table{
				{Header: []string{"Event", "Details"}, Rows: [][]string{{"`real`", "`payload_key`"}}},
			})
			blanked := BlankColumn(text, "Details")
			assertLinesKept(t, text, blanked, len(strings.Split(text, "\n"))-2)
			assertTables(t, Tables(blanked), []Table{
				{Header: []string{"Event", "Details"}, Rows: [][]string{{"`real`", ""}}},
			})
		})
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

// TestTableColumns_PicksTheNamedColumnsInTheAskedOrder: each row's cells come back in the order the
// headers are asked for, not the order the table writes them, as Tables read them.
func TestTableColumns_PicksTheNamedColumnsInTheAskedOrder(t *testing.T) {
	table := Tables("| A | `B` | C |\n|---|---|---|\n| a1 | `b1` | c1 |\n| a2 | `b2` | c2 |\n")[0]
	columns, err := table.Columns("C", "A", "`B`")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"c1", "a1", "`b1`"}, {"c2", "a2", "`b2`"}}
	if !slices.EqualFunc(columns, want, slices.Equal[[]string]) {
		t.Errorf("columns %q, want %q", columns, want)
	}
}

// TestTableColumns_AShortRowHasEmptyCells: a row that stops before a named column has an empty
// cell there rather than being dropped or shifting the cells after it.
func TestTableColumns_AShortRowHasEmptyCells(t *testing.T) {
	table := Tables("| A | B | C |\n|---|---|---|\n| a1 |\n| a2 | b2 | c2 |\n")[0]
	columns, err := table.Columns("A", "C")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"a1", ""}, {"a2", "c2"}}
	if !slices.EqualFunc(columns, want, slices.Equal[[]string]) {
		t.Errorf("columns %q, want %q", columns, want)
	}
}

// TestTableColumns_AMissingHeaderIsAnErrorNamingIt: a header the table does not carry is an error
// naming the first one missing, and no columns come back.
func TestTableColumns_AMissingHeaderIsAnErrorNamingIt(t *testing.T) {
	table := Tables("| A | B |\n|---|---|\n| a | b |\n")[0]
	columns, err := table.Columns("A", "Missing", "Absent")
	if err == nil || err.Error() != "the table has no column headed Missing" {
		t.Errorf("a missing header: %v", err)
	}
	if columns != nil {
		t.Errorf("a missing header still read %q", columns)
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

// assertTables fails t unless got is want, table by table: the same headers, and the same data
// rows with the same cells.
func assertTables(t *testing.T, got, want []Table) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d tables %+v, want %d %+v", len(got), got, len(want), want)
	}
	for i := range want {
		if !slices.Equal(got[i].Header, want[i].Header) {
			t.Errorf("table %d header %q, want %q", i, got[i].Header, want[i].Header)
		}
		if !slices.EqualFunc(got[i].Rows, want[i].Rows, slices.Equal[[]string]) {
			t.Errorf("table %d rows %q, want %q", i, got[i].Rows, want[i].Rows)
		}
	}
}

// assertLinesKept fails t unless every line of blanked is the line of text at the same place, but
// for the rewritten lines, given by their 0-based index: those lines are the rewritten data rows,
// whose spelling Tables reading the result back holds.
func assertLinesKept(t *testing.T, text, blanked string, rewritten ...int) {
	t.Helper()
	before, after := strings.Split(text, "\n"), strings.Split(blanked, "\n")
	if len(after) != len(before) {
		t.Fatalf("%d lines came back, want %d:\n%s", len(after), len(before), blanked)
	}
	for i := range before {
		if !slices.Contains(rewritten, i) && after[i] != before[i] {
			t.Errorf("line %d came back as %q, want it as written: %q", i+1, after[i], before[i])
		}
	}
}

// TestBlankColumn_EmptiesEachDataCellOfTheColumn: every data cell of the named column is emptied
// and the column stays, while the header row, the delimiter row, the prose and a table without
// the column come back as written.
func TestBlankColumn_EmptiesEachDataCellOfTheColumn(t *testing.T) {
	text := "Prose names `granted_ids`.\n" +
		"|  Event | Details  |    Why |\n" +
		"| :--- | --- | ---: |\n" +
		"| `a` | `key_a` | one |\n" +
		"| `b` | `key_b` and `key_c` | two |\n" +
		"\n" +
		"| Event | Why it matters |\n" +
		"|---|---|\n" +
		"| `c` | keyed by `user_id` |\n"
	blanked := BlankColumn(text, "Details")
	assertLinesKept(t, text, blanked, 3, 4)
	assertTables(t, Tables(blanked), []Table{
		{Header: []string{"Event", "Details", "Why"}, Rows: [][]string{{"`a`", "", "one"}, {"`b`", "", "two"}}},
		{Header: []string{"Event", "Why it matters"}, Rows: [][]string{{"`c`", "keyed by `user_id`"}}},
	})
}

// TestBlankColumn_EmptiesTheColumnInEveryTableThatHasIt: each table that has the column has its
// cells emptied, the column found in each table's own header, wherever that header puts it.
func TestBlankColumn_EmptiesTheColumnInEveryTableThatHasIt(t *testing.T) {
	text := "| Details | Event |\n" +
		"|---|---|\n" +
		"| `first` | `a` |\n" +
		"\n" +
		"| Event | Details | Why |\n" +
		"|---|---|---|\n" +
		"| `b` | `second` | two |\n" +
		"| `c` | `third` | three |\n"
	blanked := BlankColumn(text, "Details")
	assertLinesKept(t, text, blanked, 2, 6, 7)
	assertTables(t, Tables(blanked), []Table{
		{Header: []string{"Details", "Event"}, Rows: [][]string{{"", "`a`"}}},
		{Header: []string{"Event", "Details", "Why"}, Rows: [][]string{{"`b`", "", "two"}, {"`c`", "", "three"}}},
	})
}

// TestBlankColumn_TheColumnIsTheFirstHeaderCellEqualToTheHeader: a header cell that only starts
// with the header is not it, and of two equal header cells the first is the column.
func TestBlankColumn_TheColumnIsTheFirstHeaderCellEqualToTheHeader(t *testing.T) {
	text := "| Details here | Details | Details |\n|---|---|---|\n| one | two | three |\n"
	assertTables(t, Tables(BlankColumn(text, "Details")), []Table{
		{Header: []string{"Details here", "Details", "Details"}, Rows: [][]string{{"one", "", "three"}}},
	})
}

// TestBlankColumn_AnEscapedPipeStaysInItsCell: a pipe escaped in a cell before the column does not
// move the column, and a pipe escaped in a kept cell is still in it once the row is rewritten.
func TestBlankColumn_AnEscapedPipeStaysInItsCell(t *testing.T) {
	text := "| Event | Details | Note |\n" +
		"|---|---|---|\n" +
		"| `a\\|b` | `payload_key` | `c\\|d` |\n" +
		"| `e` | `f\\|g` | h\\\\|\n"
	blanked := BlankColumn(text, "Details")
	assertLinesKept(t, text, blanked, 2, 3)
	assertTables(t, Tables(blanked), []Table{
		{Header: []string{"Event", "Details", "Note"}, Rows: [][]string{{"`a|b`", "", "`c|d`"}, {"`e`", "", `h\\`}}},
	})
	if strings.Contains(blanked, "payload_key") {
		t.Errorf("a cell of the column is still read:\n%s", blanked)
	}
}

// TestBlankColumn_AFencedPipeLineIsKeptAndIsNoRow: a fenced line is text, not a row, so a table
// inside a fence is kept as written and a fence ends the table before it.
func TestBlankColumn_AFencedPipeLineIsKeptAndIsNoRow(t *testing.T) {
	text := "| Event | Details |\n" +
		"|---|---|\n" +
		"| `a` | `k` |\n" +
		"```\n" +
		"| `fenced` | `in_fence` |\n" +
		"| Event | Details |\n" +
		"|---|---|\n" +
		"| `b` | `also_fenced` |\n" +
		"```\n"
	blanked := BlankColumn(text, "Details")
	assertLinesKept(t, text, blanked, 2)
	assertTables(t, Tables(blanked), []Table{
		{Header: []string{"Event", "Details"}, Rows: [][]string{{"`a`", ""}}},
	})
}

// TestBlankColumn_ATableWithNoDelimiterRowIsKeptAsWritten: the header is the row a delimiter row
// follows, so a table without one has no column to blank.
func TestBlankColumn_ATableWithNoDelimiterRowIsKeptAsWritten(t *testing.T) {
	text := "| Event | Details |\n| `a` | `k` |\n"
	if blanked := BlankColumn(text, "Details"); blanked != text {
		t.Errorf("a table with no delimiter row came back as\n%q\nwant\n%q", blanked, text)
	}
}

// TestBlankColumn_ATextNoTableHasTheColumnInComesBackByteForByte: prose, a fenced block, indented
// table lines, a table without the column and a missing final newline all come back as written.
func TestBlankColumn_ATextNoTableHasTheColumnInComesBackByteForByte(t *testing.T) {
	text := "## Events\r\n" +
		"\n" +
		"   |  Event |  Why |\n" +
		"   |:--|--:|\n" +
		"   | `a`   | `b\\|c`|\n" +
		"\n" +
		"```\n" +
		"| Details |\n" +
		"```\n" +
		"Details is no table here."
	if blanked := BlankColumn(text, "Details"); blanked != text {
		t.Errorf("a text no table has the column in came back as\n%q\nwant\n%q", blanked, text)
	}
}

// TestBlankColumn_AShortRowIsKeptAsWritten: a data row that stops before the column has nothing to
// empty, so it comes back as written.
func TestBlankColumn_AShortRowIsKeptAsWritten(t *testing.T) {
	text := "| A | B | Details |\n|---|---|---|\n|  a1 |\n| a2 | b2 | d2 |\n"
	blanked := BlankColumn(text, "Details")
	assertLinesKept(t, text, blanked, 3)
	assertTables(t, Tables(blanked), []Table{
		{Header: []string{"A", "B", "Details"}, Rows: [][]string{{"a1"}, {"a2", "b2", ""}}},
	})
}

// TestBlankColumn_ReadsBackAsTheSameTablesWithTheColumnEmpty: no cell is removed and an emptied
// cell does not turn a row into a delimiter row, so the result reads as the same tables even where
// removing the column could not: a table whose only column is the named one, a data row whose only
// cell is in it, and a row of dashes above the header.
func TestBlankColumn_ReadsBackAsTheSameTablesWithTheColumnEmpty(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       []Table
	}{
		{
			"the only column", "| Details |\n|---|\n| `k` |\n",
			[]Table{{Header: []string{"Details"}, Rows: [][]string{{""}}}},
		},
		{
			"a row's only cell", "| Details | Why |\n|---|---|\n| `k` |\n",
			[]Table{{Header: []string{"Details", "Why"}, Rows: [][]string{{""}}}},
		},
		{
			"a row of dashes above the header", "| a | b |\n| --- | `k` |\n| Why | Details |\n|---|---|\n| w | `d` |\n",
			[]Table{{Header: []string{"Why", "Details"}, Rows: [][]string{{"a", ""}, {"---", ""}, {"w", ""}}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertTables(t, Tables(BlankColumn(tc.text, "Details")), tc.want)
		})
	}
}
