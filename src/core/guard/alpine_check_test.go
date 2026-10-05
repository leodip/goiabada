package guard

// version-manager.sh's check reports a newer Alpine minor for the release images' final stage, which
// versions.yaml pins as tools.alpine in major.minor form (#396). The selection is alpine_latest_minor,
// a function of its own, driven here over a copy of https://alpinelinux.org/releases.json taken on
// 2026-10-05, whose newest stable release is 3.24.2, and over variants of it, through the script's
// own version_lt, the comparison check makes. It is in core's tier because that tier already reads
// the files the release images are built with.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// alpineReleasesFixture is releases.json as alpinelinux.org served it, byte for byte.
const alpineReleasesFixture = "testdata/alpine-releases.json"

// alpineCheck sources version-manager.sh and makes check's Alpine comparison of current against the
// releases.json in file: the newest stable minor it selects, and whether current is behind it.
func alpineCheck(t *testing.T, current, file string) (latest string, outdated bool) {
	t.Helper()
	script := filepath.Join(SourceRoot(t), "authserver", "version-manager.sh")
	cmd := exec.Command("bash", "-c", `
. "$1" || exit 1
latest=$(alpine_latest_minor < "$3")
if version_lt "$2" "$latest"; then echo "$latest outdated"; else echo "$latest current"; fi
`, "bash", script, current, file)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "bash could not run the check:\n%s", out)
	fields := strings.Fields(string(out))
	require.Len(t, fields, 2, "the check printed more than its answer, so sourcing the script ran something:\n%s", out)
	return fields[0], fields[1] == "outdated"
}

// alpineReleasesWith is the fixture with one more release branch, holding the versions given, written
// to a file of its own.
func alpineReleasesWith(t *testing.T, branch string, versions ...string) string {
	t.Helper()
	content, err := os.ReadFile(alpineReleasesFixture)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(content, &doc))
	releases := []any{}
	for _, v := range versions {
		releases = append(releases, map[string]any{"version": v, "date": "2026-11-01"})
	}
	branches, ok := doc["release_branches"].([]any)
	require.True(t, ok, "the fixture has no release_branches list")
	doc["release_branches"] = append([]any{branches[0], map[string]any{"rel_branch": branch, "releases": releases}}, branches[1:]...)
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	file := filepath.Join(t.TempDir(), "releases.json")
	require.NoError(t, os.WriteFile(file, out, 0o600))
	return file
}

func TestAlpineCheck_APatchReleaseIsNotANewerMinor(t *testing.T) {
	latest, outdated := alpineCheck(t, "3.24", alpineReleasesFixture)
	assert.Equal(t, "3.24", latest, "3.24.2 is the newest release, and its minor is 3.24")
	assert.False(t, outdated, "3.24 is reported behind 3.24.2, which alpine:3.24 already pulls")
}

func TestAlpineCheck_AnOlderMinorIsBehind(t *testing.T) {
	latest, outdated := alpineCheck(t, "3.23", alpineReleasesFixture)
	assert.Equal(t, "3.24", latest)
	assert.True(t, outdated, "3.23 is not reported behind 3.24")
}

// A minor counts once it is released: its first X.Y.Z version is in the list.
func TestAlpineCheck_ANewlyReleasedMinorIsNewer(t *testing.T) {
	latest, outdated := alpineCheck(t, "3.24", alpineReleasesWith(t, "v3.25", "3.25.0"))
	assert.Equal(t, "3.25", latest)
	assert.True(t, outdated, "3.24 is not reported behind a released 3.25.0")
}

// A release candidate's version carries a suffix, and is no stable release.
func TestAlpineCheck_AReleaseCandidateIsIgnored(t *testing.T) {
	latest, outdated := alpineCheck(t, "3.24", alpineReleasesWith(t, "v3.25", "3.25.0_rc1"))
	assert.Equal(t, "3.24", latest, "the release candidate 3.25.0_rc1 was selected")
	assert.False(t, outdated)
}

// edge publishes no versioned release; one that did would carry no X.Y.Z either.
func TestAlpineCheck_EdgeIsIgnored(t *testing.T) {
	latest, outdated := alpineCheck(t, "3.24", alpineReleasesWith(t, "edge", "edge", "3.25_alpha20261001"))
	assert.Equal(t, "3.24", latest)
	assert.False(t, outdated)
}

// A response holding no stable release selects nothing, which check reports as a failed check
// rather than as up to date.
func TestAlpineCheck_NoStableReleaseSelectsNothing(t *testing.T) {
	file := filepath.Join(t.TempDir(), "releases.json")
	require.NoError(t, os.WriteFile(file, []byte(`{"latest_stable":"v3.24","release_branches":[]}`), 0o600))
	script := filepath.Join(SourceRoot(t), "authserver", "version-manager.sh")
	out, err := exec.Command("bash", "-c", `. "$1" || exit 1; alpine_latest_minor < "$2"`, "bash", script, file).CombinedOutput()
	require.NoError(t, err, "%s", out)
	assert.Empty(t, strings.TrimSpace(string(out)))
}
