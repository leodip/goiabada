package guard

// Mailpit runs at one pin, tools.mailpit in versions.yaml, wherever a test meets it: CI's Mailpit
// services, the dev container and the e2e server (#867). version-manager.sh update writes the pin
// into the dev container's Compose file, on Docker Hub, and the e2e server's default, at CI's
// mirror (decision 8), which Lint's
// "versions.yaml is applied" step holds to it, and check suggests a newer Mailpit only once GitHub
// records the release public for 3 days, as it does Trivy's (#520). Check's Versions job reads the
// pin for the services, and the data tier, which sends no mail, starts no Mailpit.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mailpitReleasesFixture is https://api.github.com/repos/axllent/mailpit/releases?per_page=10 as
// GitHub served it at mailpitReleasesCaptured, each release's assets cut to the first. Its newest
// release, v1.34.0, was published 2026-11-17T06:57:50Z, two days and fourteen hours before; the one
// before it, v1.33.1, 2026-11-07T23:38:50Z.
const (
	mailpitReleasesFixture  = "testdata/mailpit-releases.json"
	mailpitReleasesCaptured = "2026-11-19T20:45:47Z"
)

// mailpitPinnedFiles are the files update writes the pin into, relative to the repository root.
var mailpitPinnedFiles = []string{"src/.devcontainer/docker-compose.yml", "e2e/infra/lib.sh"}

// mailpitImages are the image each of mailpitPinnedFiles runs Mailpit as, without its tag: the dev
// container's from Docker Hub, the e2e server's from CI's mirror.
var mailpitImages = map[string]string{
	"src/.devcontainer/docker-compose.yml": "axllent/mailpit",
	"e2e/infra/lib.sh":                     ciMirror + "/mailpit",
}

// mailpitCheckSuggests sources version-manager.sh and asks check's source for the newest settled
// Mailpit release with the clock at now, GitHub's answer being the fixture: the version check
// suggests, or "" when it suggests none. curl and date are the network and the clock, replaced so
// no test reaches either; the answer is served only for the releases of the repository check names.
func mailpitCheckSuggests(t *testing.T, now string) string {
	t.Helper()
	fixture, err := filepath.Abs(mailpitReleasesFixture)
	require.NoError(t, err)
	out := versionManager(t, `
		now="$1" answer="$2"
		curl() {
			case "$*" in
				*"https://api.github.com/repos/axllent/mailpit/releases?per_page=10"*) cat "$answer" ;;
			esac
		}
		date() { if [ "$*" = "-u +%s" ]; then echo "$now"; else command date "$@"; fi; }
		get_github_settled "$MAILPIT_REPOSITORY" || true`,
		unix(t, now), fixture)
	fields := strings.Fields(out)
	require.LessOrEqual(t, len(fields), 1, "check printed more than one version:\n%s", out)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func TestMailpitCheck_TheNewestReleaseIsSuggestedOnlyOnceThreeDaysOld(t *testing.T) {
	assert.Equal(t, "1.33.1", mailpitCheckSuggests(t, mailpitReleasesCaptured),
		"v1.34.0 had been public for two days and fourteen hours when the fixture was taken")
	assert.Equal(t, "1.33.1", mailpitCheckSuggests(t, "2026-11-20T06:57:49Z"), "a second short of three days")
	assert.Equal(t, "1.34.0", mailpitCheckSuggests(t, "2026-11-20T06:57:50Z"), "exactly three days")
}

// mailpitUpdate copies files, each a path relative to the repository root and its content, into an
// empty tree and runs update's Mailpit step there with tools.mailpit at version. It returns the
// tree, whether the step succeeded, and what it printed.
func mailpitUpdate(t *testing.T, version string, files map[string]string) (string, bool, string) {
	t.Helper()
	base := t.TempDir()
	for name, content := range files {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(base, name)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(base, name), []byte(content), 0o600))
	}
	script := filepath.Join(SourceRoot(t), "authserver", "version-manager.sh")
	out, err := exec.Command("bash", "-c", `. "$1" || exit 1; BASE_DIR="$2"; update_mailpit "$3"`,
		"bash", script, base, version).CombinedOutput()
	return base, err == nil, string(out)
}

// repositoryFiles reads files, relative to the repository root, as they are committed.
func repositoryFiles(t *testing.T, names []string) map[string]string {
	t.Helper()
	root := filepath.Dir(SourceRoot(t))
	files := map[string]string{}
	for _, name := range names {
		content, err := os.ReadFile(filepath.Join(root, name))
		require.NoError(t, err)
		files[name] = string(content)
	}
	return files
}

// assertOnlyLineChanged holds the file at name in base to before with the one line holding want
// in place of the line that held the Mailpit image the file runs, and every other line as it was.
func assertOnlyLineChanged(t *testing.T, base, name, before, want string) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(base, name))
	require.NoError(t, err)
	beforeLines := strings.Split(before, "\n")
	afterLines := strings.Split(string(content), "\n")
	require.Len(t, afterLines, len(beforeLines), "%s: update added or removed lines", name)
	changed := 0
	for i := range beforeLines {
		if strings.Contains(beforeLines[i], mailpitImages[name]) {
			assert.Equal(t, want, afterLines[i], "%s:%d", name, i+1)
			changed++
			continue
		}
		assert.Equal(t, beforeLines[i], afterLines[i], "%s:%d changed, and it names no Mailpit image", name, i+1)
	}
	assert.Equal(t, 1, changed, "%s should name Mailpit's image on one line", name)
}

// update writes the pin into the dev container's Compose file and the e2e server's default, as
// they are committed, and moves each to a new pin.
func TestMailpitUpdate_WritesThePinIntoTheComposeFileAndTheE2EDefault(t *testing.T) {
	files := repositoryFiles(t, mailpitPinnedFiles)
	base, ok, out := mailpitUpdate(t, "1.40.2", files)
	assert.True(t, ok, "update's Mailpit step failed:\n%s", out)
	assertOnlyLineChanged(t, base, "src/.devcontainer/docker-compose.yml", files["src/.devcontainer/docker-compose.yml"],
		"    image: axllent/mailpit:v1.40.2")
	assertOnlyLineChanged(t, base, "e2e/infra/lib.sh", files["e2e/infra/lib.sh"],
		`E2E_MAILPIT_IMAGE="${E2E_MAILPIT_IMAGE:-ghcr.io/leodip/goiabada-ci/mailpit:v1.40.2}"`)
}

// The dev container ran Mailpit untagged, which is latest, before the pin; another tag is replaced
// whole rather than suffixed.
func TestMailpitUpdate_AnUntaggedOrOtherTagIsPinned(t *testing.T) {
	compose := "services:\n  mailpit:\n    image: axllent/mailpit\n    ports:\n      - 8025:8025\n"
	lib := `E2E_MAILPIT_IMAGE="${E2E_MAILPIT_IMAGE:-ghcr.io/leodip/goiabada-ci/mailpit:latest}"` + "\nE2E_MAILPIT_PORT=\"${E2E_MAILPIT_PORT:-18025}\"\n"
	base, ok, out := mailpitUpdate(t, "1.33.1", map[string]string{mailpitPinnedFiles[0]: compose, mailpitPinnedFiles[1]: lib})
	assert.True(t, ok, "update's Mailpit step failed:\n%s", out)
	assertOnlyLineChanged(t, base, mailpitPinnedFiles[0], compose, "    image: axllent/mailpit:v1.33.1")
	assertOnlyLineChanged(t, base, mailpitPinnedFiles[1], lib, `E2E_MAILPIT_IMAGE="${E2E_MAILPIT_IMAGE:-ghcr.io/leodip/goiabada-ci/mailpit:v1.33.1}"`)
}

// A file that no longer names Mailpit's image, its line moved or renamed, fails update's step, so
// the pin is not silently left unwritten, and the files that do are still written.
func TestMailpitUpdate_AFileThatNamesNoMailpitImageFails(t *testing.T) {
	compose := "services:\n  mailpit:\n    image: axllent/mailpit\n"
	lib := "E2E_MAILPIT_PORT=\"${E2E_MAILPIT_PORT:-18025}\"\n"
	base, ok, out := mailpitUpdate(t, "1.33.1", map[string]string{mailpitPinnedFiles[0]: compose, mailpitPinnedFiles[1]: lib})
	assert.False(t, ok, "update's Mailpit step passed over a file that names no Mailpit image:\n%s", out)
	assert.Contains(t, out, "lib.sh")
	assertOnlyLineChanged(t, base, mailpitPinnedFiles[0], compose, "    image: axllent/mailpit:v1.33.1")
}

// mailpitPin is tools.mailpit as versions.yaml writes it.
func mailpitPin(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(SourceRoot(t), "authserver", "versions.yaml"))
	require.NoError(t, err)
	match := regexp.MustCompile(`(?m)^  mailpit: "([0-9]+\.[0-9]+\.[0-9]+)"$`).FindSubmatch(content)
	require.NotNil(t, match, "versions.yaml has no tools.mailpit written as X.Y.Z")
	return string(match[1])
}

// workflowJobs maps each job of a workflow to its lines, numbered from 1, by its key under jobs:.
func workflowJobs(lines []string) map[string][]int {
	jobs := map[string][]int{}
	job, inJobs := "", false
	key := regexp.MustCompile(`^  ([A-Za-z0-9_-]+):\s*$`)
	for i, line := range lines {
		if line == "jobs:" {
			inJobs = true
			continue
		}
		if !inJobs {
			continue
		}
		if m := key.FindStringSubmatch(line); m != nil {
			job = m[1]
		}
		if job != "" {
			jobs[job] = append(jobs[job], i+1)
		}
	}
	return jobs
}

// Check's Versions job reads tools.mailpit, every Mailpit service runs the tag it gives, and a job
// whose matrix holds the data tier starts its Mailpit only for the integration entries: the data
// tier sends no mail, and a service whose image is empty is not started.
func TestCheckWorkflow_MailpitServicesRunThePinAndNotForTheDataTier(t *testing.T) {
	file := ".github/workflows/check.yml"
	lines := workflowLines(repositoryFiles(t, []string{file})[file])
	jobs := workflowJobs(lines)

	versions := map[int]bool{}
	for _, n := range jobs["versions"] {
		versions[n] = true
	}
	outputs, reads := false, false
	for n := range versions {
		line := strings.TrimSpace(lines[n-1])
		outputs = outputs || line == "mailpit: ${{ steps.read.outputs.mailpit }}"
		if words, ok := strings.CutPrefix(line, "for k in "); ok {
			words, _, _ = strings.Cut(words, ";")
			for _, w := range strings.Fields(words) {
				reads = reads || w == "mailpit"
			}
		}
	}
	assert.True(t, reads, "%s: the Versions job's read step should read tools.mailpit with the other pins", file)
	assert.True(t, outputs, "%s: the Versions job should give the pin as its mailpit output", file)

	services := 0
	for job, numbers := range jobs {
		dataTier := false
		for _, n := range numbers {
			dataTier = dataTier || strings.Contains(lines[n-1], "tier: data")
		}
		for _, n := range numbers {
			image, ok := strings.CutPrefix(strings.TrimSpace(lines[n-1]), "image:")
			if !ok || !strings.Contains(image, "mailpit") {
				continue
			}
			services++
			image = strings.TrimSpace(image)
			at := file + ":" + strconv.Itoa(n) + " (" + job + ")"
			assert.Contains(t, image, "needs.versions.outputs.mailpit",
				"%s runs Mailpit at a tag of its own; take it from the Versions job's mailpit output", at)
			if dataTier {
				assert.True(t, strings.HasPrefix(image, "${{ matrix.tier == 'integration' && ") && strings.HasSuffix(image, "|| '' }}"),
					"%s starts Mailpit for the data tier, which sends no mail; write the image as "+
						"${{ matrix.tier == 'integration' && format('<image>:v{0}', needs.versions.outputs.mailpit) || '' }}", at)
			}
		}
	}
	assert.Positive(t, services, "%s names no Mailpit service, so this test read nothing", file)
}

// The dev container and the e2e server run the pin versions.yaml holds, as update writes it: the
// dev container from Docker Hub, the e2e server from the mirror.
func TestMailpitPin_TheComposeFileAndTheE2EDefaultRunThePin(t *testing.T) {
	for name, content := range repositoryFiles(t, mailpitPinnedFiles) {
		want := mailpitImages[name] + ":v" + mailpitPin(t)
		assert.Contains(t, content, want, "%s does not run Mailpit as %s; run ./version-manager.sh update", name, want)
	}
}
