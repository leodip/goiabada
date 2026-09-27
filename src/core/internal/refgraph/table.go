package refgraph

import (
	"strings"
)

// DocRow is one body row of a markdown table: its cells, and the 1-based line it sits on.
type DocRow struct {
	Cells []string
	Line  int
	// Raw is the row exactly as the document writes it. splitRow strips backticks, which is right
	// for the identifier cells every table here carries and wrong for the note column
	// OWNERSHIP.md adds, where the cell is prose that cites them.
	Raw string
}

// TableUnder returns the body rows of the first markdown table following the heading, with the
// header and its separator dropped. The table ends at the first line that is not a table row, so
// the prose after it is never read as data.
func TableUnder(lines []string, heading string) ([]DocRow, bool) {
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == heading {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil, false
	}

	var rows []DocRow
	seen := 0
	for i := start; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" {
			if seen > 0 {
				break
			}
			continue
		}
		if !strings.HasPrefix(trimmed, "|") {
			break
		}
		seen++
		// The header row and the |---|---| separator under it carry no data.
		if seen <= 2 {
			continue
		}
		rows = append(rows, DocRow{Cells: splitRow(trimmed), Line: i + 1, Raw: trimmed})
	}
	return rows, true
}

// splitRow turns "| `core/api` | kernel | — |" into its three cells, with the pipes, the padding
// and the backticks removed. Backticks are stripped because every identifier in the document is
// written as code and none of them contain one.
func splitRow(line string) []string {
	trimmed := strings.Trim(strings.TrimSpace(line), "|")
	parts := strings.Split(trimmed, "|")
	cells := make([]string, 0, len(parts))
	for _, p := range parts {
		cells = append(cells, strings.TrimSpace(strings.ReplaceAll(p, "`", "")))
	}
	return cells
}
