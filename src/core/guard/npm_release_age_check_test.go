package guard

// version-manager.sh's check suggests a newer npm-check-updates, cropperjs or acorn only once the npm
// registry records the release published for 3 days, as it does Trivy's and Grype's (#520). The
// selection is npm_settled_release, driven here with a clock over answers shaped as
// `npm view <package> time versions --json` prints them. deps upgrades the npm projects through
// npm-check-updates under the same age, to the target NCU_COMPATIBLE_CONFIG gives it.

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

// npmView is an answer for a package whose 1.65.0 was published 2026-10-30T12:00:00Z. Its 1.66.0
// was unpublished, so the time map keeps its date but versions no longer lists it.
const npmView = `{
  "time": {
    "created": "2026-01-01T00:00:00.000Z",
    "modified": "2026-10-31T00:00:00.000Z",
    "1.9.0": "2026-08-01T10:00:00.000Z",
    "1.10.0": "2026-09-01T10:00:00.000Z",
    "1.64.0": "2026-10-07T20:44:27.702Z",
    "1.64.1": "2026-10-14T11:58:13.696Z",
    "1.65.0-beta-1": "2026-10-20T00:00:00.000Z",
    "1.65.0": "2026-10-30T12:00:00.000Z",
    "1.66.0": "2026-10-25T00:00:00.000Z"
  },
  "versions": ["1.9.0", "1.10.0", "1.64.0", "1.64.1", "1.65.0-beta-1", "1.65.0"]
}`

// npmSettledRelease sources version-manager.sh and makes check's selection over the answer view,
// with the clock at now: the version it suggests, or "" when it suggests none.
func npmSettledRelease(t *testing.T, now, view string) string {
	t.Helper()
	out, err := runNpmSettledRelease(t, now, view)
	require.NoError(t, err, "the selection failed:\n%s", out)
	fields := strings.Fields(out)
	require.LessOrEqual(t, len(fields), 1, "the selection printed more than one version:\n%s", out)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func runNpmSettledRelease(t *testing.T, now, view string) (string, error) {
	t.Helper()
	clock, err := time.Parse(time.RFC3339, now)
	require.NoError(t, err)
	file := filepath.Join(t.TempDir(), "view.json")
	require.NoError(t, os.WriteFile(file, []byte(view), 0o600))
	script := filepath.Join(SourceRoot(t), "authserver", "version-manager.sh")
	cmd := exec.Command("bash", "-c", `. "$1" || exit 1; npm_settled_release "$2" < "$3"`,
		"bash", script, strconv.FormatInt(clock.Unix(), 10), file)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// At least 3 days: a release becomes the suggestion the second its third day ends.
func TestNpmReleaseAgeCheck_AReleaseExactlyThreeDaysOldIsSuggested(t *testing.T) {
	assert.Equal(t, "1.65.0", npmSettledRelease(t, "2026-11-02T12:00:00Z", npmView))
}

func TestNpmReleaseAgeCheck_ASecondShortOfThreeDaysIsNotEnough(t *testing.T) {
	assert.Equal(t, "1.64.1", npmSettledRelease(t, "2026-11-02T11:59:59Z", npmView))
}

// The prerelease is old enough on 2026-10-25, and 1.65.0 is not yet published.
func TestNpmReleaseAgeCheck_APrereleaseIsIgnored(t *testing.T) {
	assert.Equal(t, "1.64.1", npmSettledRelease(t, "2026-10-25T00:00:00Z", npmView))
}

func TestNpmReleaseAgeCheck_AnUnpublishedVersionIsIgnored(t *testing.T) {
	assert.Equal(t, "1.65.0", npmSettledRelease(t, "2026-12-01T00:00:00Z", npmView),
		"1.66.0 was unpublished, though the time map keeps its date")
}

// Versions compare by number, so 1.10.0 is newer than 1.9.0 though it sorts before it as text.
func TestNpmReleaseAgeCheck_VersionsCompareByNumber(t *testing.T) {
	assert.Equal(t, "1.10.0", npmSettledRelease(t, "2026-09-10T00:00:00Z", npmView))
}

// npm prints a lone version as a string rather than a list.
func TestNpmReleaseAgeCheck_APackageWithOneVersion(t *testing.T) {
	view := `{"time": {"0.1.0": "2026-01-01T00:00:00.000Z"}, "versions": "0.1.0"}`
	assert.Equal(t, "0.1.0", npmSettledRelease(t, "2026-02-01T00:00:00Z", view))
}

func TestNpmReleaseAgeCheck_NothingOldEnoughSuggestsNothing(t *testing.T) {
	assert.Empty(t, npmSettledRelease(t, "2026-08-02T00:00:00Z", npmView))
}

// An answer that is not npm's JSON, such as an error page, fails rather than suggesting nothing.
func TestNpmReleaseAgeCheck_AnAnswerThatIsNotJSONFails(t *testing.T) {
	out, err := runNpmSettledRelease(t, "2026-11-02T12:00:00Z", "<html>Service Unavailable</html>")
	assert.Error(t, err, "the selection accepted an answer that is not JSON:\n%s", out)
}

// deps moves a dependency within what a caret on its current version accepts: the same major from
// 1.0.0, the same minor below it, where npm-check-updates hands the target the current range parsed,
// its major as a string.
func TestNpmCompatibleTarget_KeepsTheMajorAndUnderOneTheMinor(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(SourceRoot(t), "authserver", "version-manager.sh")
	cmd := exec.Command("bash", "-c",
		`. "$1" || exit 1; printf '%s\n' "$NCU_COMPATIBLE_CONFIG" > "$2/.ncurc.cjs" || exit 1
		node -e 'const {target} = require(process.argv[1]);
			console.log(target("a", [{major: "7", minor: "4"}]), target("b", [{major: "0", minor: "42"}]))' "$2/.ncurc.cjs"`,
		"bash", script, dir)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	assert.Equal(t, "minor patch", strings.TrimSpace(string(out)))
}
