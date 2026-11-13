package stylingcontract

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/docsreader"
)

// The Styling contract reference page held to the contract's lists: it is where an administrator
// reads what their custom CSS can rely on, so a variable, a page or a hook class the page lists
// that the contract does not, or one it leaves out, fails here (#816).

const stylingContractPage = "../../../site/src/content/docs/reference/styling-contract.mdx"

// serverCell is how the page's On column names the servers whose pages draw a hook class.
var serverCell = map[string]string{
	"auth server":                "Auth server",
	"admin console":              "Admin console",
	"auth server, admin console": "Both",
}

func readStylingContractPage(t *testing.T) string {
	t.Helper()
	page, err := os.ReadFile(stylingContractPage)
	require.NoError(t, err, "unable to read the Styling contract page")
	return string(page)
}

// sectionColumn reads the cells of column in the one table of the section heading opens, each
// with its code span's backticks taken off.
func sectionColumn(t *testing.T, page, heading string, columns ...string) [][]string {
	t.Helper()
	section, found := docsreader.SectionText(page, heading)
	require.Truef(t, found, "the Styling contract page has no %q section", heading)
	tables := docsreader.Tables(section)
	require.Lenf(t, tables, 1, "the %q section holds one table", heading)
	rows, err := tables[0].Columns(columns...)
	require.NoErrorf(t, err, "the %q section's table", heading)
	for _, row := range rows {
		for i := range row {
			row[i] = strings.Trim(row[i], "`")
		}
	}
	return rows
}

func TestStylingContractPage_ListsTheVariables(t *testing.T) {
	page := readStylingContractPage(t)

	var listed []string
	for _, row := range sectionColumn(t, page, "## CSS variables", "Variable") {
		listed = append(listed, row[0])
	}

	assert.Equal(t, Variables(), listed)
}

func TestStylingContractPage_ListsEveryGroupsPages(t *testing.T) {
	page := readStylingContractPage(t)

	for _, group := range pageGroups {
		var listed []string
		for _, row := range sectionColumn(t, page, "### "+group.Name, "`data-page`") {
			listed = append(listed, row[0])
		}

		assert.Equalf(t, group.Pages, listed, "the %s section", group.Name)
	}
}

func TestStylingContractPage_ListsEveryGroupsHookClassesAndWhereTheyAreDrawn(t *testing.T) {
	page := readStylingContractPage(t)

	for _, group := range classGroups {
		var want, listed [][]string
		for _, c := range group.Classes {
			servers := make([]string, 0, len(c.Servers))
			for _, s := range c.Servers {
				servers = append(servers, string(s))
			}
			want = append(want, []string{c.Name, serverCell[strings.Join(servers, ", ")]})
		}
		listed = sectionColumn(t, page, "### "+group.Name, "Class", "On")

		assert.Equalf(t, want, listed, "the %s section", group.Name)
	}
}
