package localzone

import (
	"os"
	"testing"
	"time"
	// The zone the test names loads on a host with no zone database, as it does in either server.
	_ "time/tzdata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/docsreader"
)

// The environment variables page documents TZ in a section of its own, because neither config
// package reads it, so the page's checks against those packages never see it.
const (
	environmentVariablesPage = "../../../site/src/content/docs/reference/environment-variables.mdx"
	timeZoneHeading          = "## Time zone"
)

// The page's Time zone section names `TZ`, and TZ is the variable Install reads: a zone set there
// is the zone Install installs. A section that stops naming it, or an Install that reads another
// variable, fails here.
func TestEnvironmentVariablesPage_TheTimeZoneSectionNamesTheVariableInstallReads(t *testing.T) {
	page, err := os.ReadFile(environmentVariablesPage)
	require.NoError(t, err, "unable to read the environment variables page")
	section, found := docsreader.SectionText(string(page), timeZoneHeading)
	require.Truef(t, found, "%s has no %q section", environmentVariablesPage, timeZoneHeading)
	require.NotEmpty(t, section, "%s has no %q section", environmentVariablesPage, timeZoneHeading)
	assert.Contains(t, section, "`TZ`", "%s, %s: the section does not name `TZ`", environmentVariablesPage, timeZoneHeading)

	withLocal(t, hostZone)
	t.Setenv("TZ", "Europe/Lisbon")

	require.NoError(t, Install())

	assert.Equal(t, "Europe/Lisbon", time.Local.String(), "Install does not read the zone from TZ")
}
