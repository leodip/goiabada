package guard

// version-manager.sh's check reports when the upstream sources that ./version-manager.sh generate
// is pinned to have moved: tzdata for the timezones, datasets/country-codes for the countries, and
// SecLists for the password blocklist. It reads the pins out of the generators' own code, so these
// tests hold it to the generators as they are: a renamed constant or a reshaped source list would
// otherwise turn the check into "Check failed" with nothing saying why.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDataSourcesCheck_ReadsEachGeneratorsPin(t *testing.T) {
	cases := map[string]struct{ generator, constant, shape string }{
		"tzdata":        {"timezones/generate/main.go", "pinnedRelease", `^[0-9]{4}[a-z]$`},
		"country-codes": {"countries/generate/main.go", "pinnedCommit", `^[0-9a-f]{40}$`},
		"SecLists":      {"passwordblocklist/generate/main.go", "pinnedCommit", `^[0-9a-f]{40}$`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(SourceRoot(t), "core", c.generator)
			pin := versionManager(t, `go_const "$1" "$2"`, file, c.constant)
			assert.Regexp(t, c.shape, pin, "check read no pin from %s", c.generator)
			content, err := os.ReadFile(file)
			require.NoError(t, err)
			assert.Contains(t, string(content), `"`+pin+`"`)
		})
	}
}

// The list check asks GitHub about is the list the generator fetches.
func TestDataSourcesCheck_ReadsThePasswordListsTheGeneratorFetches(t *testing.T) {
	files := strings.Fields(versionManager(t, `password_list_files`))
	require.NotEmpty(t, files)
	content, err := os.ReadFile(filepath.Join(SourceRoot(t), "core", "passwordblocklist", "generate", "main.go"))
	require.NoError(t, err)
	sources := regexp.MustCompile(`(?m)^\s*file:\s*"([^"]+)"`).FindAllStringSubmatch(string(content), -1)
	require.Len(t, files, len(sources), "check reads another list of files than the generator's sources")
	for i, source := range sources {
		assert.Equal(t, source[1], files[i])
		assert.True(t, strings.HasSuffix(files[i], ".txt"), "%q is no list file", files[i])
	}
}

func TestDataSourcesCheck_ReadsAGitHubCommit(t *testing.T) {
	one := `{"sha": "2d84034a0cae19ea5444b78c2131304a5c7f4bb9", "commit": {"committer": {"date": "2026-10-15T20:57:25Z"}}}`
	assert.Equal(t, "2d84034a0cae19ea5444b78c2131304a5c7f4bb9 2026-10-15T20:57:25Z",
		versionManager(t, `github_commit_fields <<< "$1"`, one))
	assert.Equal(t, "2d84034a0cae19ea5444b78c2131304a5c7f4bb9 2026-10-15T20:57:25Z",
		versionManager(t, `github_commit_fields <<< "$1"`, "["+one+`, {"sha": "older", "commit": {"committer": {"date": "2026-01-01T00:00:00Z"}}}]`),
		"a list's first commit is its newest")
	assert.Empty(t, versionManager(t, `github_commit_fields <<< "[]"`), "no commit changed the path")
}
