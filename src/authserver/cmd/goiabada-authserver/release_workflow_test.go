package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// releaseWorkflow is the release pipeline, relative to the repository root: the tag push that
// builds and attests the images and writes the draft release the maintainer publishes.
const releaseWorkflow = ".github/workflows/release.yml"

// workflowStep is one step of a workflow job, as far as the digest contract reads it: the name it
// runs under, the env it runs with, and its script.
type workflowStep struct {
	Name string            `yaml:"name"`
	Env  map[string]string `yaml:"env"`
	Run  string            `yaml:"run"`
}

// workflowJob is one job of a workflow, as far as the digest contract reads it: its outputs and
// its steps.
type workflowJob struct {
	Outputs map[string]string `yaml:"outputs"`
	Steps   []workflowStep    `yaml:"steps"`
}

// readWorkflow reads a workflow's jobs out of its YAML, or reports why it cannot be read, so a
// check that read nothing cannot pass as one that did.
func readWorkflow(text string) (map[string]workflowJob, error) {
	var workflow struct {
		Jobs map[string]workflowJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(text), &workflow); err != nil {
		return nil, err
	}
	return workflow.Jobs, nil
}

// digestImages are the two images a release pushes, each named by the output the images job
// exposes its digest as and by the env the draft reads it through, uppercase.
var digestImages = []struct{ output, env string }{
	{"authserver", "AUTHSERVER"},
	{"adminconsole", "ADMINCONSOLE"},
}

// checkDraftNamesTheDigests holds the release workflow to the contract the pinning docs rest on
// (#491): the images job exposes the two digests its digests step read as job outputs, and the
// draft rewrites its notes to append them as two full references, tag and digest together, wired
// from those outputs, so the references a release's notes list cannot drift from the image content
// it pushed and attested. It returns what does not hold.
func checkDraftNamesTheDigests(jobs map[string]workflowJob) []string {
	var findings []string
	images, ok := jobs["images"]
	if !ok {
		return []string{"release workflow: there is no images job"}
	}
	for _, image := range digestImages {
		if got, want := images.Outputs[image.output], "${{ steps.digests.outputs."+image.output+" }}"; got != want {
			findings = append(findings, fmt.Sprintf(
				"release workflow: the images job exposes no %s output as its digests step read it", image.output))
		}
	}

	draft, ok := jobs["draft"]
	if !ok {
		return append(findings, "release workflow: there is no draft job")
	}
	var notes *workflowStep
	for i := range draft.Steps {
		if strings.Contains(draft.Steps[i].Run, "gh release edit") &&
			strings.Contains(draft.Steps[i].Run, "--notes-file") {
			notes = &draft.Steps[i]
			break
		}
	}
	if notes == nil {
		return append(findings,
			"release workflow: no draft step rewrites the notes with gh release edit --notes-file")
	}
	for _, image := range digestImages {
		if got, want := notes.Env[image.env+"_DIGEST"], "${{ needs.images.outputs."+image.output+" }}"; got != want {
			findings = append(findings, fmt.Sprintf(
				"release workflow: the notes step takes the %s digest from %q, not from the images job's output",
				image.output, got))
		}
		reference := "leodip/goiabada:" + image.output + "-$VERSION@$" + image.env + "_DIGEST"
		if !strings.Contains(notes.Run, reference) {
			findings = append(findings, fmt.Sprintf(
				"release workflow: the notes the draft writes name no %s reference, tag and digest together",
				image.output))
		}
	}
	return findings
}

// releaseNotesFixture is a workflow shaped like the release's digest path: an images job exposing
// the digests its digests step read, and a draft appending them to the generated notes.
const releaseNotesFixture = `name: Release
on:
  push:
    tags: ['v*']
jobs:
  verify:
    runs-on: ubuntu-latest
    outputs:
      version: ${{ steps.v.outputs.version }}
  images:
    runs-on: ubuntu-latest
    outputs:
      authserver: ${{ steps.digests.outputs.authserver }}
      adminconsole: ${{ steps.digests.outputs.adminconsole }}
    steps:
      - name: Read pushed manifest digests
        id: digests
        run: |
          echo "authserver=sha256:a" >> "$GITHUB_OUTPUT"
          echo "adminconsole=sha256:b" >> "$GITHUB_OUTPUT"
  draft:
    needs: [verify, images]
    runs-on: ubuntu-latest
    steps:
      - name: Create the draft release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          VERSION: ${{ needs.verify.outputs.version }}
        run: |
          gh release create "v$VERSION" --draft --generate-notes dist/*
      - name: Write the image digests into the draft notes
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          VERSION: ${{ needs.verify.outputs.version }}
          AUTHSERVER_DIGEST: ${{ needs.images.outputs.authserver }}
          ADMINCONSOLE_DIGEST: ${{ needs.images.outputs.adminconsole }}
        run: |
          gh release view "v$VERSION" --json body --jq .body > notes.md
          echo "- Auth server: leodip/goiabada:authserver-$VERSION@$AUTHSERVER_DIGEST" >> notes.md
          echo "- Admin console: leodip/goiabada:adminconsole-$VERSION@$ADMINCONSOLE_DIGEST" >> notes.md
          gh release edit "v$VERSION" --notes-file notes.md
`

func TestReleaseWorkflow_TheDraftNamesTheDigests(t *testing.T) {
	t.Run("a draft appending both references wired from the images job passes", func(t *testing.T) {
		jobs, err := readWorkflow(releaseNotesFixture)
		require.NoError(t, err)
		assert.Empty(t, checkDraftNamesTheDigests(jobs))
	})

	t.Run("an images job exposing no digest output fails", func(t *testing.T) {
		text := strings.Replace(releaseNotesFixture,
			"      authserver: ${{ steps.digests.outputs.authserver }}\n", "", 1)
		jobs, err := readWorkflow(text)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"release workflow: the images job exposes no authserver output as its digests step read it",
		}, checkDraftNamesTheDigests(jobs))
	})

	t.Run("a notes step taking a digest from somewhere else fails", func(t *testing.T) {
		text := strings.Replace(releaseNotesFixture,
			"          AUTHSERVER_DIGEST: ${{ needs.images.outputs.authserver }}\n",
			"          AUTHSERVER_DIGEST: ${{ steps.digests.outputs.authserver }}\n", 1)
		jobs, err := readWorkflow(text)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"release workflow: the notes step takes the authserver digest from " +
				"\"${{ steps.digests.outputs.authserver }}\", not from the images job's output",
		}, checkDraftNamesTheDigests(jobs))
	})

	t.Run("notes naming no reference fail", func(t *testing.T) {
		text := strings.Replace(releaseNotesFixture,
			"          echo \"- Auth server: leodip/goiabada:authserver-$VERSION@$AUTHSERVER_DIGEST\" >> notes.md\n", "", 1)
		jobs, err := readWorkflow(text)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"release workflow: the notes the draft writes name no authserver reference, tag and digest together",
		}, checkDraftNamesTheDigests(jobs))
	})
}

// TestReleaseWorkflow_TheRealDraftNamesTheDigestsTheImagesJobPushed holds this repository's own
// release workflow to the digest contract, so a workflow change that stops naming the pushed
// digests in the notes fails here rather than shipping a release whose notes cannot pin what it
// attests.
func TestReleaseWorkflow_TheRealDraftNamesTheDigestsTheImagesJobPushed(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(filepath.Dir(guard.SourceRoot(t)), releaseWorkflow))
	require.NoError(t, err)
	jobs, err := readWorkflow(string(body))
	require.NoErrorf(t, err, "%s cannot be read as YAML", releaseWorkflow)
	assert.Empty(t, checkDraftNamesTheDigests(jobs))
}
