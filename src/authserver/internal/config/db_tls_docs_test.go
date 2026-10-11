package config

// The pages that tell an operator what protects the database connection, held to the settings this
// configuration reads and the refusals it answers (#502). Until #502 they sent PostgreSQL operators
// to libpq's PGSSLMODE, which now stops the start, so a page keeping that advice or quoting a refusal
// the load no longer writes sends its reader nowhere.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	databaseConnectTroubleshootingPage = "site/src/content/docs/troubleshooting/crashloopbackoff-or-unable-to-create-the-database-connection.mdx"
	productionChecklistPage            = "site/src/content/docs/deploy/production-checklist.mdx"
	securityReferencePage              = "site/src/content/docs/reference/security.mdx"
)

// libpqVariableSections are the sections an operator who set one of libpq's TLS variables is sent
// to: the troubleshooting page a refused start leads to, and the upgrade page, where an operator
// who followed the old advice learns before upgrading that the start will stop.
var libpqVariableSections = []docSection{
	{databaseConnectTroubleshootingPage, ""},
	{upgradePage, "## If you set PGSSLMODE"},
}

// TestDocs_NameEveryRefusedLibpqVariable: each section names the seven variables a PostgreSQL start
// refuses, and quotes, as the load writes it, the refusal of the two the old advice set.
func TestDocs_NameEveryRefusedLibpqVariable(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	refusals := map[string]string{}
	for _, v := range libpqTLSVariables {
		_, _, err := loadMatrixRefusing(t, map[string]string{"GOIABADA_DB_TYPE": "postgres", v.name: "verify-full"}, nil)
		require.Error(t, err, "%s stops a PostgreSQL start", v.name)
		refusals[v.name] = err.Error()
	}
	require.Len(t, refusals, 7, "libpq's seven TLS variables")

	for _, section := range libpqVariableSections {
		text, err := docSectionText(root, section)
		require.NoError(t, err)
		require.NotEmpty(t, text, "%s exists", section)
		for name, refusal := range refusals {
			assert.Contains(t, text, "`"+name+"`", "%s names %s", section, name)
			if name == "PGSSLMODE" || name == "PGSSLROOTCERT" {
				assert.Contains(t, text, "`"+refusal+"`", "%s quotes the refusal of %s", section, name)
			}
		}
	}
}

// TestDocs_TheDatabaseTransportNamesTheSettings: the production checklist's database caution and the
// Security page's line on the network name the two settings and the mode that checks whose database
// the auth server reached, and neither sends the reader to PGSSLMODE.
func TestDocs_TheDatabaseTransportNamesTheSettings(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	for _, section := range []docSection{
		{productionChecklistPage, "## Database"},
		{securityReferencePage, "## The network"},
	} {
		text, err := docSectionText(root, section)
		require.NoError(t, err)
		require.NotEmpty(t, text, "%s exists", section)
		for _, name := range []string{"GOIABADA_DB_TLS_MODE", "GOIABADA_DB_TLS_CA_FILE", "verify-full"} {
			assert.Contains(t, text, "`"+name+"`", "%s names %s", section, name)
		}
		assert.NotContains(t, text, "PGSSLMODE", "%s no longer advises libpq's variable", section)
	}
}

// TestDocs_PreferSaysWhatSQLServerEncrypts: every page that says what prefer encrypts says that on
// SQL Server it is the login, and the rest of the session only when the server forces encryption,
// which is #502 decision 2's prefer and what the data tier shows a TLS-capable SQL Server doing. Said
// as PostgreSQL's and MySQL's, encrypted whenever the server offers TLS, it reads as protection a
// SQL Server deployment does not have.
func TestDocs_PreferSaysWhatSQLServerEncrypts(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	for _, tc := range []struct {
		section docSection
		marker  string // what opens or names the line describing prefer
	}{
		{docSection{environmentVariablesPage, "## Every variable"}, "| `GOIABADA_DB_TLS_MODE`"},
		{docSection{securityReferencePage, "## The network"}, "it's `prefer`"},
		{docSection{productionChecklistPage, "## Database"}, "`GOIABADA_DB_TLS_MODE` unset"},
		{docSection{"site/src/content/docs/deploy/database.mdx", "## Where the database sits"}, "| `prefer`"},
	} {
		text, err := docSectionText(root, tc.section)
		require.NoError(t, err)
		require.NotEmpty(t, text, "%s exists", tc.section)
		var prefer string
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, tc.marker) {
				prefer = line
				break
			}
		}
		require.NotEmpty(t, prefer, "%s says what prefer encrypts", tc.section)
		assert.Contains(t, prefer, "SQL Server", "%s: %s", tc.section, prefer)
		assert.Contains(t, prefer, "login", "%s: %s", tc.section, prefer)
		assert.Contains(t, prefer, "forces encryption", "%s: %s", tc.section, prefer)
	}
}
