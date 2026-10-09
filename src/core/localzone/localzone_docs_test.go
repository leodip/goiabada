package localzone

import (
	"bufio"
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
	// The zone the test names loads on a host with no zone database, as it does in either server.
	_ "time/tzdata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	section := markdownSection(page, timeZoneHeading)
	require.NotEmpty(t, section, "%s has no %q section", environmentVariablesPage, timeZoneHeading)
	assert.Contains(t, section, "`TZ`", "%s, %s: the section does not name `TZ`", environmentVariablesPage, timeZoneHeading)

	withLocal(t, hostZone)
	t.Setenv("TZ", "Europe/Lisbon")

	require.NoError(t, Install())

	assert.Equal(t, "Europe/Lisbon", time.Local.String(), "Install does not read the zone from TZ")
}

// markdownSection is the text of the section heading opens, up to the next heading of its level
// or above, with fenced code left out, and empty when the page has no such section.
func markdownSection(page []byte, heading string) string {
	level := strings.Index(heading, " ")
	var section strings.Builder
	inSection, inFence := false, false
	scanner := bufio.NewScanner(bytes.NewReader(page))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if hashes := len(line) - len(strings.TrimLeft(line, "#")); hashes > 0 && strings.HasPrefix(line[hashes:], " ") {
			if inSection && hashes <= level {
				break
			}
			inSection = inSection || strings.TrimSpace(line) == heading
			continue
		}
		if inSection {
			section.WriteString(line + "\n")
		}
	}
	return section.String()
}

func TestMarkdownSection_ReadsOnlyItsSection(t *testing.T) {
	page := "## Configuration\n\n`GHOST` above.\n\n## Time zone\n\nBoth servers read `TZ`.\n\n" +
		"```\n## Time zone\n`IN_FENCE`\n```\n### Detail\n\n`NESTED`\n\n## Next\n\n`AFTER`\n"

	section := markdownSection([]byte(page), timeZoneHeading)

	assert.Contains(t, section, "`TZ`")
	assert.Contains(t, section, "`NESTED`", "a subsection is part of the section")
	for _, outside := range []string{"GHOST", "IN_FENCE", "AFTER"} {
		assert.NotContains(t, section, outside)
	}
	assert.Empty(t, markdownSection([]byte("## Timezone\n\n`TZ`\n"), timeZoneHeading), "a page with no such section reads nothing")
	assert.Empty(t, markdownSection([]byte("```\n## Time zone\n`TZ`\n```\n"), timeZoneHeading), "a heading in a fence opens nothing")
}
