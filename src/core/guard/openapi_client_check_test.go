package guard

// The auth server's OpenAPI document is checked by generating a Go client from it with
// oapi-codegen and building it (#261). One script does it, and CI's Lint job and run-tests.sh's
// lint tier both run that script, so a contributor's lint run and CI's cannot disagree on whether
// the document generates a client. The generator names the type wrapping each operation's answer
// with a suffix the script sets, since its default collides with the document's own schema names;
// the API authentication page tells a Go caller to set the same one, read here from the script.

import (
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/docsreader"
)

const (
	// openAPIClientScript is the check, relative to the source root.
	openAPIClientScript    = "authserver/check-openapi-client.sh"
	apiAuthenticationPage  = "../site/src/content/docs/reference/api/authentication.mdx"
	openAPIDocumentHeading = "## The OpenAPI document"
)

// lintTierBlock is the body of run-tests.sh's `if should_run_lint; then` block, up to the fi that
// closes it at the start of a line.
func lintTierBlock(t *testing.T, script string) string {
	t.Helper()
	_, body, found := strings.Cut(script, "\nif should_run_lint; then\n")
	require.True(t, found, "%s has no `if should_run_lint; then` block", runTestsScript)
	body, _, found = strings.Cut(body, "\nfi\n")
	require.True(t, found, "%s: the lint block has no closing fi", runTestsScript)
	return body
}

// runsCommand is whether a command in script, as the shell reads it, is named name.
func runsCommand(t *testing.T, where, script, name string) bool {
	t.Helper()
	read := readShell(script)
	require.Empty(t, read.problems, "%s cannot be read as the shell reads it", where)
	return slices.ContainsFunc(read.commands, func(c shellCommand) bool {
		return len(c.words) > 0 && c.words[0].value == name
	})
}

// CI's Lint job runs the script in a step of its own that always runs and fails the job when the
// script fails, and the lint tier runs the same script.
func TestOpenAPIClientCheck_CIsLintJobAndTheLintTierRunTheScript(t *testing.T) {
	root := SourceRoot(t)
	repoRoot := filepath.Dir(root)
	jobs, err := readWorkflowJobs(readFile(t, filepath.Join(repoRoot, checkWorkflow)))
	require.NoError(t, err, "%s does not read as YAML", checkWorkflow)
	at := slices.IndexFunc(jobs, func(j workflowJob) bool { return j.name == "lint" })
	require.GreaterOrEqual(t, at, 0, "%s has no lint job", checkWorkflow)

	want := path.Join("src", openAPIClientScript)
	var steps []int
	for _, step := range jobs[at].steps {
		script, ok := step.run()
		if !ok {
			continue
		}
		dir := ""
		if _, v := step.field("working-directory"); v != nil {
			dir, _ = yamlScalar(v)
		}
		read := readShell(script.text)
		if slices.ContainsFunc(read.commands, func(c shellCommand) bool {
			return len(c.words) > 0 && path.Clean(path.Join(dir, c.words[0].value)) == want
		}) {
			steps = append(steps, step.line)
			assert.Zero(t, step.conditional(), "%s:%d: the step running %s has an if:, so some runs skip it", checkWorkflow, step.line, want)
			line, v := step.field("continue-on-error")
			assert.Zero(t, toleratesFailure(line, v), "%s:%d: the step running %s lets the job pass when it fails", checkWorkflow, step.line, want)
		}
	}
	assert.Len(t, steps, 1, "%s: the lint job must run %s in one step", checkWorkflow, want)

	tier := lintTierBlock(t, readFile(t, filepath.Join(root, runTestsScript)))
	assert.True(t, runsCommand(t, runTestsScript+"'s lint block", tier, "./"+path.Base(openAPIClientScript)),
		"%s: the lint tier does not run ./%s", runTestsScript, path.Base(openAPIClientScript))
}

// The API authentication page, where it says to generate a client from the document, names
// oapi-codegen and the suffix setting the script generates with; Contributing's lint row says the
// tier checks the document generates a client.
func TestOpenAPIClientCheck_TheDocsNameTheGeneratorAndItsSuffix(t *testing.T) {
	root := SourceRoot(t)
	suffix := regexp.MustCompile(`(?m)^\s*response-type-suffix:\s*(\w+)\s*$`).FindStringSubmatch(readFile(t, filepath.Join(root, openAPIClientScript)))
	require.NotNil(t, suffix, "%s sets no response-type-suffix", openAPIClientScript)

	section, found := docsreader.SectionText(readFile(t, filepath.Join(root, apiAuthenticationPage)), openAPIDocumentHeading)
	require.Truef(t, found, "%s has no %q section", apiAuthenticationPage, openAPIDocumentHeading)
	assert.Contains(t, section, "oapi-codegen", "%s, %s: the generator the lint checks with is not named", apiAuthenticationPage, openAPIDocumentHeading)
	assert.Contains(t, section, "`response-type-suffix: "+suffix[1]+"`",
		"%s, %s: the page must give the suffix %s generates with", apiAuthenticationPage, openAPIDocumentHeading, openAPIClientScript)

	tests, found := docsreader.SectionText(readFile(t, filepath.Join(root, contributingPage)), testsHeading)
	require.Truef(t, found, "%s has no %q section", contributingPage, testsHeading)
	row := slices.IndexFunc(docsreader.Rows(tests), func(r []string) bool { return len(r) == 2 && r[0] == "`lint`" })
	require.GreaterOrEqual(t, row, 0, "%s, %s: no row for the lint tier", contributingPage, testsHeading)
	assert.Contains(t, docsreader.Rows(tests)[row][1], "OpenAPI", "%s, %s: the lint row does not mention the client check", contributingPage, testsHeading)
}
