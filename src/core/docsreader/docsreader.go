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

// Tables returns every table in text, in the order the page reads them. Fenced code holds no
// table: a line inside a code fence is never a row. A delimiter row, the one under a header, is
// neither a header nor a data row, and the header is the row a delimiter row follows.
func Tables(text string) []Table {
	var (
		tables  []Table
		rows    [][]string
		inFence bool
	)
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inFence = !inFence
			continue
		}
		if inFence || !strings.HasPrefix(trimmed, "|") {
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
// row and a delimiter row are not data rows.
func Rows(text string) [][]string {
	var rows [][]string
	for _, table := range Tables(text) {
		rows = append(rows, table.Rows...)
	}
	return rows
}

// classify splits one table's rows into its header and its data rows: the row the first delimiter
// row follows is the header, and with no delimiter row every row is a data row.
func classify(rows [][]string) Table {
	header := -1
	for i, row := range rows {
		if i > 0 && isDelimiterRow(row) {
			header = i - 1
			break
		}
	}
	var table Table
	for i, row := range rows {
		switch {
		case isDelimiterRow(row):
		case i == header:
			table.Header = row
		default:
			table.Rows = append(table.Rows, row)
		}
	}
	return table
}

// isDelimiterRow says whether every cell of a row is dashes, colons and spaces: the row under a
// table's header, which is neither a header nor a data row.
func isDelimiterRow(cells []string) bool {
	return strings.Trim(strings.Join(cells, ""), "-: ") == ""
}

// cells splits one table row into its cells: on the pipes the row is written with, a pipe escaped
// inside a cell staying in it. Every cell is trimmed.
func cells(line string) []string {
	s := strings.TrimPrefix(line, "|")
	if strings.HasSuffix(s, "|") && !strings.HasSuffix(s, `\|`) {
		s = s[:len(s)-1]
	}
	var out []string
	var cell strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s) && s[i+1] == '|':
			cell.WriteByte('|')
			i++
		case s[i] == '|':
			out = append(out, strings.TrimSpace(cell.String()))
			cell.Reset()
		default:
			cell.WriteByte(s[i])
		}
	}
	return append(out, strings.TrimSpace(cell.String()))
}

// headingLevel is the number of #s opening a Markdown heading, and 0 for any other line.
func headingLevel(line string) int {
	hashes := len(line) - len(strings.TrimLeft(line, "#"))
	if hashes == 0 || hashes > 6 || !strings.HasPrefix(line[hashes:], " ") {
		return 0
	}
	return hashes
}
