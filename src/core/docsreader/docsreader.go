// Package docsreader reads the docs site's Markdown the way the docs tests read it: the section a
// heading opens and the tables inside it. Every docs test reads sections and tables through this
// package, so a fix to how a heading inside a fence, an escaped pipe or a code span in a cell is
// read is made once (#536).
//
// It is a leaf of its own rather than a file in core/guard because the setup wizard's docs tests
// read through it too, and a test the wizard reaches may not import core/guard, whose dependencies
// would land in the wizard's go.sum (#500). It imports nothing but `core/errs` and the standard
// library, and its own tests do the same, so the wizard's go.sum stays as it is.
package docsreader

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// SectionText is the text of the section heading opens in an already-read page: the lines after
// the heading up to the next heading of the same or higher level outside a code fence, the fenced
// lines among them, and a deeper heading's line too. A heading inside a fence opens and ends
// nothing. An empty heading reads the whole page. found is false when the page has no such section,
// and the text is empty with it.
func SectionText(page, heading string) (text string, found bool) {
	if heading == "" {
		return page, true
	}
	level := headingLevel(heading)
	var section strings.Builder
	inSection, inFence := false, false
	for _, line := range strings.Split(page, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inFence = !inFence
		}
		if !inFence {
			if lineLevel := headingLevel(line); lineLevel > 0 {
				if inSection && lineLevel <= level {
					break
				}
				if trimmed == heading {
					inSection, found = true, true
					continue
				}
			}
		}
		if inSection {
			section.WriteString(line)
			section.WriteByte('\n')
		}
	}
	return section.String(), found
}

// Section reads the page at root/page and returns the text of the section heading opens, the way
// SectionText reads it. An empty heading reads the whole page. A page that cannot be read, or one
// with no such section, is an error, so a check that read nothing cannot pass as one that did.
func Section(root, page, heading string) (string, error) {
	//nolint:gosec // G304: root is the repo's own docs tree and page a test-given path, never request input
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(page)))
	if err != nil {
		return "", errs.Errorf("reading %s: %w", page, err)
	}
	text, found := SectionText(string(content), heading)
	if !found {
		return "", errs.Errorf("%s has no %q section, so this check read nothing", page, heading)
	}
	return text, nil
}

// Table is one Markdown table: its header row and the data rows under it, every cell trimmed, its
// code spans keeping their backticks. A table whose header row no delimiter row follows has no
// header, and every row of it is a data row.
type Table struct {
	Header []string
	Rows   [][]string
}

// Columns returns the cells of every data row in the named columns, in the order headers names
// them, each cell as Tables read it. A row shorter than the header has an empty cell for each column
// it does not reach. A header the table does not carry is an error naming the first one, so a check
// reading a renamed column cannot pass as one that read it.
func (t Table) Columns(headers ...string) ([][]string, error) {
	indexes := make([]int, 0, len(headers))
	for _, header := range headers {
		index := slices.Index(t.Header, header)
		if index < 0 {
			return nil, errs.Errorf("the table has no column headed %s", header)
		}
		indexes = append(indexes, index)
	}
	columns := make([][]string, 0, len(t.Rows))
	for _, row := range t.Rows {
		cells := make([]string, 0, len(indexes))
		for _, index := range indexes {
			cell := ""
			if index < len(row) {
				cell = row[index]
			}
			cells = append(cells, cell)
		}
		columns = append(columns, cells)
	}
	return columns, nil
}

// Tables returns every table in text, in the order the page reads them. Fenced code holds no
// table: a line inside a code fence is never a row, and a fence line ends the table before it. The
// delimiter row under a header is neither a header nor a data row, and the header is the row the
// first delimiter row follows.
func Tables(text string) []Table {
	var (
		tables  []Table
		rows    [][]string
		inFence bool
	)
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		fence := strings.HasPrefix(trimmed, "```")
		if fence {
			inFence = !inFence
		}
		if fence || inFence || !strings.HasPrefix(trimmed, "|") {
			if len(rows) > 0 {
				tables = append(tables, classify(rows))
				rows = nil
			}
			continue
		}
		rows = append(rows, cells(trimmed))
	}
	if len(rows) > 0 {
		tables = append(tables, classify(rows))
	}
	return tables
}

// Rows returns the data rows of every table in text, in the order the page reads them. A header
// row and the delimiter row under it are not data rows.
func Rows(text string) [][]string {
	var rows [][]string
	for _, table := range Tables(text) {
		rows = append(rows, table.Rows...)
	}
	return rows
}

// Row splits one table row into its cells, the way Tables reads every row of a table: a pipe
// escaped inside a cell stays in it, any other backslash keeps the character after it, and every
// cell is trimmed. A guard that walks a page line by line for its own structure, such as one
// holding a page to a line-numbered catalog, reads each line's cells through it, so the one
// splitter lives here too (#536).
func Row(line string) []string {
	return cells(line)
}

// classify splits one table's rows into its header and its data rows: the row the first delimiter
// row follows is the header, and with no delimiter row every row is a data row. Only that one
// delimiter row is skipped: a row of dashes further down is a data row, as the page renders it.
func classify(rows [][]string) Table {
	delimiter := -1
	for i := 1; i < len(rows); i++ {
		if isDelimiterRow(rows[i]) {
			delimiter = i
			break
		}
	}
	var table Table
	for i, row := range rows {
		switch i {
		case delimiter:
		case delimiter - 1:
			table.Header = row
		default:
			table.Rows = append(table.Rows, row)
		}
	}
	return table
}

// isDelimiterRow says whether a row is shaped as the one under a table's header: every cell
// dashes, with a colon at either end or both. A row of empty cells is not.
func isDelimiterRow(cells []string) bool {
	for _, cell := range cells {
		dashes := strings.TrimSuffix(strings.TrimPrefix(cell, ":"), ":")
		if dashes == "" || strings.Trim(dashes, "-") != "" {
			return false
		}
	}
	return true
}

// cells splits one table row into its cells: on the pipes the row is written with, every
// backslash read together with the character after it. An escaped pipe stays in its cell as a
// pipe, the one escape the table rather than the text reads; any other backslash is kept with the
// character after it, so `\\|` is an escaped backslash and then the pipe that ends the cell, and a
// cell reads as it is written, the way a code span keeps its backticks. Every cell is trimmed.
func cells(line string) []string {
	s := strings.TrimPrefix(line, "|")
	var out []string
	var cell strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s) && s[i+1] == '|':
			cell.WriteByte('|')
			i++
		case s[i] == '\\' && i+1 < len(s):
			cell.WriteString(s[i : i+2])
			i++
		case s[i] == '|':
			out = append(out, strings.TrimSpace(cell.String()))
			cell.Reset()
		default:
			cell.WriteByte(s[i])
		}
	}
	// The empty cell after a closing pipe is not a cell.
	if last := strings.TrimSpace(cell.String()); last != "" || len(out) == 0 {
		out = append(out, last)
	}
	return out
}

// headingLevel is the number of #s opening a Markdown heading, and 0 for any other line.
func headingLevel(line string) int {
	hashes := len(line) - len(strings.TrimLeft(line, "#"))
	if hashes == 0 || hashes > 6 || !strings.HasPrefix(line[hashes:], " ") {
		return 0
	}
	return hashes
}
