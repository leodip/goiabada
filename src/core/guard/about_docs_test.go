package guard

// The About pages, held to the files they describe (#522).
//
// Contributing tells a contributor how the project is built and tested: the dev container's
// development values, run-tests.sh's tiers, and the commands that regenerate the files a change
// must commit. Each is read from the file that decides it, so a tier added to run-tests.sh, a
// regenerator renamed or a dev container value changed fails here rather than leaving the page
// describing a project that no longer exists. License shows the license, which is the LICENSE
// file at the repository root and nothing else.
//
// It is a test rather than a guard: it reads three files and two pages, and core's tier runs it.

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/docsreader"
)

// The pages and the files they describe, relative to the source root.
const (
	contributingPage   = "../site/src/content/docs/about/contributing.mdx"
	licensePage        = "../site/src/content/docs/about/license.mdx"
	licenseFile        = "../LICENSE"
	runTestsScript     = "authserver/run-tests.sh"
	devcontainerConfig = ".devcontainer/devcontainer.json"

	testsHeading     = "## Run the tests"
	generatedHeading = "## Commit what you generate"
	devHeading       = "## Run Goiabada from source"
)

// regenerator is one command that rewrites committed files, the module directory it is run from,
// and the file under that directory that must exist for the command to run as written.
type regenerator struct {
	command, dir, needs string
}

// regenerators are the commands AGENTS.md says a change owes before it is committed: the schema
// goldens after a migration, the core ownership table after a core symbol moves, the mocks after an
// interface changes, the Tailwind CSS after a template's classes change, in both applications, and
// the files versions.yaml pins after a pin changes.
var regenerators = []regenerator{
	{command: "go run ./cmd/schemadump", dir: "authserver", needs: "cmd/schemadump"},
	{command: "go run ./cmd/ownershipdump", dir: "core", needs: "cmd/ownershipdump"},
	{command: "./generate-mocks.sh", dir: "authserver", needs: "generate-mocks.sh"},
	{command: "./build.sh", dir: "authserver", needs: "build.sh"},
	{command: "./build.sh", dir: "adminconsole", needs: "build.sh"},
	{command: "./version-manager.sh update", dir: "authserver", needs: "version-manager.sh"},
}

// The tier table on Contributing lists exactly the --type values run-tests.sh accepts, so a tier
// added to the script, or one a page names that the script refuses, fails here.
func TestContributingPage_TheTierTableIsEveryTypeRunTestsAccepts(t *testing.T) {
	root := SourceRoot(t)
	script := readFile(t, filepath.Join(root, runTestsScript))
	accepted := acceptedTestTypes(t, script)
	require.NotEmpty(t, accepted, "%s: no --type values read", runTestsScript)

	section, found := docsreader.SectionText(readFile(t, filepath.Join(root, contributingPage)), testsHeading)
	require.Truef(t, found, "%s has no %q section", contributingPage, testsHeading)
	require.NotEmpty(t, section, "%s has no %q section", contributingPage, testsHeading)
	listed := tableFirstColumnCode(section)

	assert.ElementsMatch(t, accepted, listed,
		"%s, %s: the tier table must list exactly the --type values %s accepts", contributingPage, testsHeading, runTestsScript)
}

// Contributing's section on generated files names each regenerator with the module directory it
// runs from, on one row of its table, every one of them is a file that exists, and the three the lint tier reruns are the
// ones run-tests.sh's lint tier names.
func TestContributingPage_NamesEveryRegenerator(t *testing.T) {
	root := SourceRoot(t)
	section, found := docsreader.SectionText(readFile(t, filepath.Join(root, contributingPage)), generatedHeading)
	require.Truef(t, found, "%s has no %q section", contributingPage, generatedHeading)
	require.NotEmpty(t, section, "%s has no %q section", contributingPage, generatedHeading)

	for _, g := range regenerators {
		_, err := os.Stat(filepath.Join(root, g.dir, filepath.FromSlash(g.needs)))
		require.NoError(t, err, "src/%s/%s, which %q needs, does not exist", g.dir, g.needs, g.command)
		assert.True(t, slices.ContainsFunc(docsreader.Rows(section), func(row []string) bool {
			return len(row) == 3 && strings.Contains(row[1], "`"+g.command+"`") && strings.Contains(row[2], "`src/"+g.dir+"`")
		}), "%s, %s: no row runs %q from src/%s", contributingPage, generatedHeading, g.command, g.dir)
	}

	lint := readFile(t, filepath.Join(root, runTestsScript))
	for _, rerun := range []string{"./generate-mocks.sh", "go run ./cmd/ownershipdump", "run ./build.sh in src/"} {
		assert.Contains(t, lint, rerun, "%s's lint tier no longer reruns %q, which %s says it does", runTestsScript, rerun, contributingPage)
	}
}

// The development values Contributing gives for signing in and reaching the two servers are the
// ones devcontainer.json sets.
func TestContributingPage_TheDevelopmentValuesAreTheDevContainers(t *testing.T) {
	root := SourceRoot(t)
	config := readFile(t, filepath.Join(root, devcontainerConfig))
	section, found := docsreader.SectionText(readFile(t, filepath.Join(root, contributingPage)), devHeading)
	require.Truef(t, found, "%s has no %q section", contributingPage, devHeading)
	require.NotEmpty(t, section, "%s has no %q section", contributingPage, devHeading)

	for _, key := range []string{
		"GOIABADA_ADMIN_EMAIL",
		"GOIABADA_ADMIN_PASSWORD",
		"GOIABADA_AUTHSERVER_BASEURL",
		"GOIABADA_ADMINCONSOLE_BASEURL",
	} {
		value := containerEnvValue(config, key)
		require.NotEmpty(t, value, "%s sets no %s", devcontainerConfig, key)
		assert.Contains(t, section, value, "%s, %s: %s's value %q is not the one given", contributingPage, devHeading, key, value)
	}
}

// License shows the LICENSE file as it is, in one fenced block.
func TestLicensePage_ShowsTheLicenseFile(t *testing.T) {
	root := SourceRoot(t)
	license := strings.TrimRight(readFile(t, filepath.Join(root, licenseFile)), "\n")
	blocks := fencedBlocks(readFile(t, filepath.Join(root, licensePage)))
	require.Len(t, blocks, 1, "%s must show the license in exactly one fenced block", licensePage)
	assert.Equal(t, license, blocks[0], "%s does not show the LICENSE file as it is", licensePage)
}

func TestAboutDocs_TheReaders(t *testing.T) {
	script := "# Validate --type\ncase \"$TYPE\" in\n    a|b|c) ;;\n    *)\nesac\n"
	assert.Equal(t, []string{"a", "b", "c"}, acceptedTestTypes(t, script))

	page := "## Run the tests\n\n| Tier (`--type`) | What |\n|---|---|\n| `x` | one |\n| `y` and `z` | two |\n\n```\n| `fenced` | no |\n```\n" +
		"### Narrow it\n\n| `nested` | a subsection is part of it |\n\n## Next\n\n| `after` | outside |\n"
	section, found := docsreader.SectionText(page, testsHeading)
	require.True(t, found, "the page has a ## Run the tests section")
	assert.Equal(t, []string{"x", "y", "nested"}, tableFirstColumnCode(section))

	config := "{\n\t\"containerEnv\": {\n\t\t\"A_KEY\": \"a value\",\n\t\t// \"B_KEY\": \"commented\"\n\t}\n}\n"
	assert.Equal(t, "a value", containerEnvValue(config, "A_KEY"))
	assert.Empty(t, containerEnvValue(config, "B_KEY"), "a commented-out entry is not set")

	assert.Equal(t, []string{"one\ntwo", "three"}, fencedBlocks("text\n```text\none\ntwo\n```\nmore\n```\nthree\n```\n"))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err, "unable to read %s", path)
	return string(b)
}

// acceptedTestTypes is the pattern list of the case statement that follows run-tests.sh's
// "# Validate --type" comment: its first arm, `a|b|c) ;;`, read as a, b and c.
func acceptedTestTypes(t *testing.T, script string) []string {
	t.Helper()
	_, after, found := strings.Cut(script, "# Validate --type\n")
	require.True(t, found, "no %q comment in %s", "# Validate --type", runTestsScript)
	arm := regexp.MustCompile(`(?m)^\s*([a-z|]+)\)\s*;;`).FindStringSubmatch(after)
	require.NotNil(t, arm, "no `a|b) ;;` arm after %q in %s", "# Validate --type", runTestsScript)
	return strings.Split(arm[1], "|")
}

// tableFirstColumnCode is the first code span of each table body row's first cell, in order. A
// header row, the one a delimiter row follows, is not a body row, whatever its cell holds.
// tableFirstColumnCode is the first code span of each table body row's first cell, in order.
func tableFirstColumnCode(section string) []string {
	code := regexp.MustCompile("`([^`]+)`")
	var out []string
	for _, row := range docsreader.Rows(section) {
		if len(row) == 0 {
			continue
		}
		if m := code.FindStringSubmatch(row[0]); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// containerEnvValue is the value devcontainer.json gives key on a line of its own, and empty when no
// line that is not a comment sets it.
func containerEnvValue(config, key string) string {
	line := regexp.MustCompile(`(?m)^\s*"` + regexp.QuoteMeta(key) + `"\s*:\s*"([^"]*)"`)
	if m := line.FindStringSubmatch(config); m != nil {
		return m[1]
	}
	return ""
}

// fencedBlocks is the content of every fenced code block on a page, in order.
func fencedBlocks(page string) []string {
	var blocks []string
	var block []string
	inFence := false
	for _, line := range strings.Split(page, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			if inFence {
				blocks = append(blocks, strings.Join(block, "\n"))
				block = nil
			}
			inFence = !inFence
			continue
		}
		if inFence {
			block = append(block, line)
		}
	}
	return blocks
}
