package guard

// version-manager.sh holds every release it picks to RELEASE_MIN_AGE_DAYS, as its source records the
// publication (#520): beside GitHub's releases and the npm registry, nodejs.org's index for Node.js
// and the Go module proxy for Go, the Go tools and the Go modules deps upgrades. --now drops the
// age to 0, for an urgent fix.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// versionManager sources version-manager.sh and runs body, a bash snippet, with args as $2 onward,
// returning what it printed.
func versionManager(t *testing.T, body string, args ...string) string {
	t.Helper()
	script := filepath.Join(SourceRoot(t), "authserver", "version-manager.sh")
	cmd := exec.Command("bash", append([]string{"-c", `. "$1" || exit 1; shift; ` + body, "bash", script}, args...)...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	return strings.TrimSpace(string(out))
}

func unix(t *testing.T, at string) string {
	t.Helper()
	clock, err := time.Parse(time.RFC3339, at)
	require.NoError(t, err)
	return strconv.FormatInt(clock.Unix(), 10)
}

// goCandidates are a module's releases newest first, as hold_young_go_modules hands them on.
const goCandidates = "v5.12.0 2026-11-02T10:00:00Z\nv5.11.2 2026-10-30T09:00:00Z\nv5.11.1 2026-10-20T09:00:00Z\n"

func TestSettledGoVersion_TheNewestOldEnoughCandidateWins(t *testing.T) {
	out := versionManager(t, `settled_go_version "$1" v5.11.0 <<< "$2"`, "2026-11-01T00:00:00Z", goCandidates)
	assert.Equal(t, "v5.11.2", out)
}

func TestSettledGoVersion_ACandidateExactlyAtTheCutoffCounts(t *testing.T) {
	out := versionManager(t, `settled_go_version "$1" v5.11.0 <<< "$2"`, "2026-10-30T09:00:00Z", goCandidates)
	assert.Equal(t, "v5.11.2", out)
}

// With no candidate old enough the module stays where it was before go get -u.
func TestSettledGoVersion_NothingOldEnoughKeepsTheFallback(t *testing.T) {
	out := versionManager(t, `settled_go_version "$1" v5.11.0 <<< "$2"`, "2026-10-01T00:00:00Z", goCandidates)
	assert.Equal(t, "v5.11.0", out)
}

// A candidate whose time the proxy did not give cannot be shown old enough.
func TestSettledGoVersion_ACandidateWithoutATimeIsPassedOver(t *testing.T) {
	out := versionManager(t, `settled_go_version "$1" v5.11.0 <<< "$2"`, "2026-11-10T00:00:00Z",
		"v5.12.0\nv5.11.2 2026-10-30T09:00:00Z\n")
	assert.Equal(t, "v5.11.2", out)
}

// nodeIndex is nodejs.org's index.json cut to what node_settled_lts reads, newest first: a Current
// release, which carries false for lts, an LTS one dated 2026-10-28, an older LTS one, and a
// prerelease.
const nodeIndex = `[
  {"version": "v27.0.0-alpha.0.0.0", "date": "2026-10-29", "lts": false},
  {"version": "v27.1.0", "date": "2026-10-20", "lts": false},
  {"version": "v26.13.0", "date": "2026-10-28", "lts": "Lithium"},
  {"version": "v26.12.1", "date": "2026-10-01", "lts": "Lithium"},
  {"version": "v24.20.0", "date": "2026-10-30", "lts": "Krypton"}
]`

func nodeSettledLTS(t *testing.T, now string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "index.json")
	require.NoError(t, os.WriteFile(file, []byte(nodeIndex), 0o600))
	return versionManager(t, `node_settled_lts "$1" < "$2"`, unix(t, now), file)
}

// index.json dates a release by its day, so 26.13.0 counts from 2026-10-28T00:00:00Z.
func TestNodeSettledLTS_AnLTSReleaseThreeDaysOldIsSuggested(t *testing.T) {
	assert.Equal(t, "26.13.0", nodeSettledLTS(t, "2026-10-31T00:00:00Z"))
}

func TestNodeSettledLTS_AYoungerOneIsPassedOver(t *testing.T) {
	assert.Equal(t, "26.12.1", nodeSettledLTS(t, "2026-10-30T23:59:59Z"))
}

// A Current release is no LTS, however new its number, and an older LTS line counts by its number,
// not by being listed later.
func TestNodeSettledLTS_ACurrentReleaseIsIgnored(t *testing.T) {
	assert.Equal(t, "26.13.0", nodeSettledLTS(t, "2026-11-10T00:00:00Z"))
}

func TestGoproxyInfoFields(t *testing.T) {
	out := versionManager(t, `goproxy_info_fields <<< "$1"`,
		`{"Version":"v0.8.2","Time":"2026-10-12T13:34:44Z","Origin":{"VCS":"git"}}`)
	assert.Equal(t, "0.8.2 2026-10-12T13:34:44Z", out)
}

func TestTakeNowFlag_DropsTheAgeToZero(t *testing.T) {
	assert.Equal(t, "3", versionManager(t, `take_now_flag; echo "$RELEASE_MIN_AGE_DAYS"`))
	assert.Equal(t, "0", versionManager(t, `take_now_flag --now; echo "$RELEASE_MIN_AGE_DAYS"`))
}

func TestTakeNowFlag_RefusesAnythingElse(t *testing.T) {
	script := filepath.Join(SourceRoot(t), "authserver", "version-manager.sh")
	out, err := exec.Command("bash", "-c", `. "$1" || exit 1; take_now_flag --later`, "bash", script).CombinedOutput()
	assert.Error(t, err, "take_now_flag accepted --later:\n%s", out)
}

// A release whose publication time is unknown cannot be shown old enough, so check holds it back.
func TestReleasedTooRecently(t *testing.T) {
	assert.Equal(t, "young", versionManager(t, `released_too_recently "$(utc_timestamp $(( $(date -u +%s) - 3600 )))" && echo young || echo old`))
	assert.Equal(t, "old", versionManager(t, `released_too_recently "$(utc_timestamp $(( $(date -u +%s) - 4 * 86400 )))" && echo young || echo old`))
	assert.Equal(t, "young", versionManager(t, `released_too_recently "" && echo young || echo old`))
	assert.Equal(t, "old", versionManager(t, `take_now_flag --now; released_too_recently "$(utc_timestamp $(( $(date -u +%s) - 60 )))" && echo young || echo old`))
}
