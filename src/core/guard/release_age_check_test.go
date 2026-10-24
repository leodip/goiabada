package guard

// version-manager.sh's check suggests a newer Trivy only once GitHub records the release public for
// 7 days, so a bump cannot land on a release that is already poisoned: Trivy's malicious v0.69.4 was
// public for about 12 hours (#520). The selection is github_settled_release, a function of its own,
// driven here with a clock over a copy of
// https://api.github.com/repos/aquasecurity/trivy/releases?per_page=10 taken on 2026-10-24T14:43:27Z,
// each release's assets cut to the first so the file stays small, and over variants of it. The age is
// the release's published_at, not its created_at, which is the tag's commit date and is set by
// whoever pushes the tag.

import (
	"encoding/json"
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

// trivyReleasesFixture is the releases API's answer as GitHub served it, pretty-printed, with every
// field of every release kept and each release's assets list cut to its first entry.
const trivyReleasesFixture = "testdata/trivy-releases.json"

// trivyReleasesCaptured is when the fixture was taken. Its newest release, v0.76.1, was published
// 2026-10-21T11:18:34Z, three days before; the one before it, v0.76.0, 2026-10-14T11:45:44Z.
const trivyReleasesCaptured = "2026-10-24T14:43:27Z"

// settledRelease sources version-manager.sh and makes check's selection over the releases API
// answer in file, with the clock at now: the version it suggests, or "" when it suggests none.
func settledRelease(t *testing.T, now, file string) string {
	t.Helper()
	clock, err := time.Parse(time.RFC3339, now)
	require.NoError(t, err)
	script := filepath.Join(SourceRoot(t), "authserver", "version-manager.sh")
	cmd := exec.Command("bash", "-c", `. "$1" || exit 1; github_settled_release "$2" < "$3"`,
		"bash", script, strconv.FormatInt(clock.Unix(), 10), file)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "bash could not run the selection:\n%s", out)
	fields := strings.Fields(string(out))
	require.LessOrEqual(t, len(fields), 1, "the selection printed more than one version, or sourcing the script ran something:\n%s", out)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// trivyReleasesWith is the fixture with one more release ahead of the others, given as a JSON object
// written in the order GitHub writes a release's fields, saved to a file of its own. The releases
// already there are kept as they are, compacted, so the variant is also the answer without GitHub's
// indentation.
func trivyReleasesWith(t *testing.T, release string) string {
	t.Helper()
	content, err := os.ReadFile(trivyReleasesFixture)
	require.NoError(t, err)
	var releases []json.RawMessage
	require.NoError(t, json.Unmarshal(content, &releases))
	require.NotEmpty(t, releases, "the fixture holds no release")
	out, err := json.Marshal(append([]json.RawMessage{json.RawMessage(release)}, releases...))
	require.NoError(t, err)
	file := filepath.Join(t.TempDir(), "releases.json")
	require.NoError(t, os.WriteFile(file, out, 0o600))
	return file
}

// trivyRelease is a release tagged tag, in GitHub's field order, tagged and published before the
// fixture was taken, so it is old enough to be suggested unless its flags or tag refuse it.
func trivyRelease(tag string, draft, prerelease bool, published string) string {
	return `{"url":"https://api.github.com/repos/aquasecurity/trivy/releases/1","id":1,` +
		`"tag_name":"` + tag + `","target_commitish":"main","name":"` + tag + `",` +
		`"draft":` + strconv.FormatBool(draft) + `,"immutable":true,"prerelease":` + strconv.FormatBool(prerelease) + `,` +
		`"created_at":"2026-09-01T10:00:00Z","updated_at":"2026-09-01T10:00:00Z","published_at":` + published + `,` +
		`"assets":[{"name":"bom.json","state":"uploaded","created_at":"2026-09-01T10:00:00Z","updated_at":"2026-09-01T10:00:00Z"}],` +
		`"body":"\"tag_name\": \"v9.9.9\", \"published_at\": \"2020-01-01T00:00:00Z\""}`
}

func TestReleaseAgeCheck_TheNewestReleaseYoungerThanSevenDaysIsPassedOver(t *testing.T) {
	assert.Equal(t, "0.76.0", settledRelease(t, trivyReleasesCaptured, trivyReleasesFixture),
		"v0.76.1 was public for three days and v0.76.0 for ten when the fixture was taken")
}

// At least 7 days: a release becomes the suggestion the second its seventh day ends.
func TestReleaseAgeCheck_AReleaseExactlySevenDaysOldIsSuggested(t *testing.T) {
	assert.Equal(t, "0.76.1", settledRelease(t, "2026-10-28T11:18:34Z", trivyReleasesFixture))
}

func TestReleaseAgeCheck_ASecondShortOfSevenDaysIsNotEnough(t *testing.T) {
	assert.Equal(t, "0.76.0", settledRelease(t, "2026-10-28T11:18:33Z", trivyReleasesFixture))
}

// v0.71.1 was tagged 2026-06-10 and published 2026-06-15: on 2026-06-21 its tag is eleven days old
// and the release six, so it is not suggested and v0.71.0 is.
func TestReleaseAgeCheck_ThePublicationTimeCountsNotTheTagDate(t *testing.T) {
	assert.Equal(t, "0.71.0", settledRelease(t, "2026-06-21T00:00:00Z", trivyReleasesFixture))
}

func TestReleaseAgeCheck_APrereleaseIsIgnored(t *testing.T) {
	file := trivyReleasesWith(t, trivyRelease("v0.77.0", false, true, `"2026-09-01T11:00:00Z"`))
	assert.Equal(t, "0.76.0", settledRelease(t, trivyReleasesCaptured, file), "the prerelease v0.77.0 was suggested")
}

// GitHub writes no publication time on a draft, but a draft is refused by its own flag.
func TestReleaseAgeCheck_ADraftIsIgnored(t *testing.T) {
	file := trivyReleasesWith(t, trivyRelease("v0.77.0", true, false, `"2026-09-01T11:00:00Z"`))
	assert.Equal(t, "0.76.0", settledRelease(t, trivyReleasesCaptured, file), "the draft v0.77.0 was suggested")
	file = trivyReleasesWith(t, trivyRelease("v0.77.0", true, false, `null`))
	assert.Equal(t, "0.76.0", settledRelease(t, trivyReleasesCaptured, file), "the draft v0.77.0 was suggested")
}

// The variants' other releases are compacted, so this is also the selection over an answer without
// GitHub's indentation; the new release's body names another tag and an older publication time in
// escaped quotes, which are text and not fields.
func TestReleaseAgeCheck_AnOldEnoughReleaseAheadOfTheOthersIsSuggested(t *testing.T) {
	file := trivyReleasesWith(t, trivyRelease("v0.77.0", false, false, `"2026-09-01T11:00:00Z"`))
	assert.Equal(t, "0.77.0", settledRelease(t, trivyReleasesCaptured, file))
}

// A tag that is not vX.Y.Z is no release version, whatever its flags say.
func TestReleaseAgeCheck_ATagThatIsNoVersionIsIgnored(t *testing.T) {
	file := trivyReleasesWith(t, trivyRelease("v0.77.0-rc.1", false, false, `"2026-09-01T11:00:00Z"`))
	assert.Equal(t, "0.76.0", settledRelease(t, trivyReleasesCaptured, file), "v0.77.0-rc.1 was suggested")
}

// On 2026-04-20 the newest release in the answer, v0.70.0, had been public for three days, and the
// answer holds nothing older, so check has nothing to suggest.
func TestReleaseAgeCheck_NothingOldEnoughSuggestsNothing(t *testing.T) {
	assert.Empty(t, settledRelease(t, "2026-04-20T00:00:00Z", trivyReleasesFixture))
}

// The selection reads a release's fields in the order GitHub writes them, its tag first. An answer
// whose fields come in another order cannot be read that way, so it suggests nothing rather than
// pairing one release's tag with another's publication time.
func TestReleaseAgeCheck_FieldsInAnotherOrderSuggestNothing(t *testing.T) {
	var releases []map[string]any
	content, err := os.ReadFile(trivyReleasesFixture)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(content, &releases))
	out, err := json.Marshal(releases) // a map's keys are written sorted, tag_name after the others
	require.NoError(t, err)
	file := filepath.Join(t.TempDir(), "releases.json")
	require.NoError(t, os.WriteFile(file, out, 0o600))
	assert.Empty(t, settledRelease(t, trivyReleasesCaptured, file))
}
