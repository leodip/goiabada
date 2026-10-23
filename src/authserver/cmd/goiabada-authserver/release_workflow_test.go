package main

import (
	"fmt"
	"os"
	"os/exec"
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

// pinnedReferencesHeading is the heading the draft's notes open with, which the upgrade page and
// the draft step's closing reminder send the reader to by name.
const pinnedReferencesHeading = "Pinned image references"

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
// step that creates the draft gives it notes naming them as two full references, tag and digest
// together, wired from those outputs, so the references a release's notes list cannot drift from
// the image content it pushed and attested. It returns what does not hold.
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
	notes := draftCreateStep(draft)
	if notes == nil || !strings.Contains(notes.Run, "--notes-file") {
		return append(findings,
			"release workflow: no draft step creates the release with gh release create --notes-file")
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

// draftCreateStep is the draft job's step that creates the release, or nil when it has none.
func draftCreateStep(draft workflowJob) *workflowStep {
	for i := range draft.Steps {
		if strings.Contains(draft.Steps[i].Run, "gh release create") {
			return &draft.Steps[i]
		}
	}
	return nil
}

// releaseNotesFixture is a workflow shaped like the release's digest path: an images job exposing
// the digests its digests step read, and a draft created with notes naming them above the
// generated ones.
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
          AUTHSERVER_DIGEST: ${{ needs.images.outputs.authserver }}
          ADMINCONSOLE_DIGEST: ${{ needs.images.outputs.adminconsole }}
        run: |
          echo "- Auth server: leodip/goiabada:authserver-$VERSION@$AUTHSERVER_DIGEST" > pinned.md
          echo "- Admin console: leodip/goiabada:adminconsole-$VERSION@$ADMINCONSOLE_DIGEST" >> pinned.md
          gh release create "v$VERSION" --draft --generate-notes --notes-file pinned.md dist/*
`

func TestReleaseWorkflow_TheDraftNamesTheDigests(t *testing.T) {
	t.Run("a draft created with both references wired from the images job passes", func(t *testing.T) {
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

	t.Run("a draft created with no notes file fails", func(t *testing.T) {
		text := strings.Replace(releaseNotesFixture, " --notes-file pinned.md", "", 1)
		jobs, err := readWorkflow(text)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"release workflow: no draft step creates the release with gh release create --notes-file",
		}, checkDraftNamesTheDigests(jobs))
	})

	t.Run("notes naming no reference fail", func(t *testing.T) {
		text := strings.Replace(releaseNotesFixture,
			"          echo \"- Auth server: leodip/goiabada:authserver-$VERSION@$AUTHSERVER_DIGEST\" > pinned.md\n", "", 1)
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

// ghStub stands in for gh on the PATH of a draft step run by runDraftCreate: it records its
// arguments one per line and copies the notes file a release create names, which is the body gh
// sends above the notes --generate-notes asks GitHub for. Anything but a release create fails.
const ghStub = `#!/bin/sh
set -eu
[ "$1 $2" = "release create" ] || exit 64
printf '%s\n' "$@" > "$GH_ARGS"
while [ $# -gt 0 ]; do
  if [ "$1" = --notes-file ]; then cp "$2" "$GH_NOTES"; fi
  shift
done
`

// draftRun is what one run of the real create step did: its exit, its output, and, when it
// reached gh, the arguments gh was given and the notes file it was handed.
type draftRun struct {
	err    error
	output string
	called bool
	args   []string
	notes  string
}

// runDraftCreate runs the release workflow's own draft create step under bash, in a directory
// holding one release asset, with gh stubbed and the two digests given.
func runDraftCreate(t *testing.T, authserverDigest, adminconsoleDigest string) draftRun {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(filepath.Dir(guard.SourceRoot(t)), releaseWorkflow))
	require.NoError(t, err)
	jobs, err := readWorkflow(string(body))
	require.NoError(t, err)
	step := draftCreateStep(jobs["draft"])
	require.NotNil(t, step, "%s: the draft job has no step running gh release create", releaseWorkflow)

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "dist"), 0o755))
	require.NoError(t, os.MkdirAll(bin, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dist", "asset.zip"), []byte("asset"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(bin, "gh"), []byte(ghStub), 0o755))
	argsFile, notesFile := filepath.Join(dir, "gh-args"), filepath.Join(dir, "gh-notes")

	cmd := exec.Command("bash", "-c", step.Run)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"VERSION=1.2.3",
		"PRERELEASE=false",
		"AUTHSERVER_DIGEST=" + authserverDigest,
		"ADMINCONSOLE_DIGEST=" + adminconsoleDigest,
		"GH_ARGS=" + argsFile,
		"GH_NOTES=" + notesFile,
	}
	output, err := cmd.CombinedOutput()
	run := draftRun{err: err, output: string(output)}
	if args, readErr := os.ReadFile(argsFile); readErr == nil {
		run.called = true
		run.args = strings.Split(strings.TrimSuffix(string(args), "\n"), "\n")
	}
	if notes, readErr := os.ReadFile(notesFile); readErr == nil {
		run.notes = string(notes)
	}
	return run
}

// TestReleaseWorkflow_TheDraftIsCreatedWithTheReferencesAboveTheGeneratedNotes runs the real create
// step: the one gh release create that makes the draft is handed a notes file opening with the
// heading the docs name and naming each image with its own version and digest, and still asks for
// the generated notes, which gh puts below that file, so the draft never exists without the
// references (#491).
func TestReleaseWorkflow_TheDraftIsCreatedWithTheReferencesAboveTheGeneratedNotes(t *testing.T) {
	authserverDigest := "sha256:" + strings.Repeat("a", 64)
	adminconsoleDigest := "sha256:" + strings.Repeat("b", 64)

	run := runDraftCreate(t, authserverDigest, adminconsoleDigest)

	require.NoError(t, run.err, run.output)
	require.True(t, run.called, "the step never ran gh release create\n%s", run.output)
	require.GreaterOrEqual(t, len(run.args), 3, "gh was given %v", run.args)
	assert.Equal(t, "release", run.args[0])
	assert.Equal(t, "create", run.args[1])
	assert.Equal(t, "v1.2.3", run.args[2], "the draft is created for the version's tag")
	assert.Contains(t, run.args, "--draft")
	assert.Contains(t, run.args, "--generate-notes", "the generated changelog stays below the references")
	assert.Contains(t, run.args, "--notes-file")
	assert.Contains(t, run.args, "dist/asset.zip", "the release assets go up in the same create")
	notes := strings.Split(run.notes, "\n")
	assert.Equal(t, "## "+pinnedReferencesHeading, notes[0], "the draft opens with the section the docs name")
	assert.Contains(t, run.output, "keeping the "+pinnedReferencesHeading+" section",
		"the closing reminder names the section the draft writes")
	assert.Contains(t, notes, "- Auth server: `leodip/goiabada:authserver-1.2.3@"+authserverDigest+"`")
	assert.Contains(t, notes, "- Admin console: `leodip/goiabada:adminconsole-1.2.3@"+adminconsoleDigest+"`")
}

// TestReleaseWorkflow_TheDraftIsNotCreatedWithoutBothDigests: a digest the images job did not give,
// or one that is not a sha256 digest, would publish a reference naming nothing, so the step stops
// before gh creates any draft.
func TestReleaseWorkflow_TheDraftIsNotCreatedWithoutBothDigests(t *testing.T) {
	digest := "sha256:" + strings.Repeat("c", 64)
	for name, digests := range map[string][2]string{
		"no auth server digest":    {"", digest},
		"no admin console digest":  {digest, ""},
		"a digest of another kind": {"md5:" + strings.Repeat("d", 32), digest},
	} {
		t.Run(name, func(t *testing.T) {
			run := runDraftCreate(t, digests[0], digests[1])

			require.Error(t, run.err)
			assert.Contains(t, run.output, "::error::the images job gave no digest for one of the images")
			assert.False(t, run.called, "gh created a draft: %v", run.args)
		})
	}
}
