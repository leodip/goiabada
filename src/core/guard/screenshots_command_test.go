package guard

// e2e/screenshots.sh writes the images its capture took over the committed ones, and a run that fails
// leaves the committed ones as they were (#534 decision 1). These tests run the script in a copy of
// the folders it touches, with docker replaced by a stub that plays the Compose project and hands
// back the images a test put in its capture folder, and with cp and mv replaced by stubs that fail
// where the test says, as a full or failing disk would.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// screenshotsStubDocker plays the Compose project: every command succeeds, logs prints a line for each server,
// and cp copies the capture folder the test filled.
const screenshotsStubDocker = `#!/usr/bin/env bash
echo "docker $*" >>"$STUB/log"
case " $* " in
  *" logs "*) echo "authserver-1 | the auth server's last line"; echo "adminconsole-1 | the console's last line" ;;
  " cp "*) "$REAL_CP" -R "$STUB/out/." "${@: -1}" ;;
esac
`

// screenshotsStubCp and screenshotsStubMv fail a copy into, or a rename out of, the files the test names in FAIL_CP and
// FAIL_MV, by file name. With FULL_AFTER_RENAME set, the assets folder takes no new file once a first
// rename into it has succeeded, as a disk that has just filled.
const screenshotsStubCp = `#!/usr/bin/env bash
dst="${@: -1}"
case "$dst" in
  "$ASSETS"/*)
    for f in $FAIL_CP; do [ "$(basename "$dst")" != "$f" ] || { echo "cp: injected failure" >&2; exit 1; }; done
    [ -z "${FULL_AFTER_RENAME:-}" ] || [ ! -e "$STUB/full" ] || { echo "cp: no space left on device" >&2; exit 1; }
    ;;
esac
exec "$REAL_CP" "$@"
`

const screenshotsStubMv = `#!/usr/bin/env bash
src="${@: -2:1}"
dst="${@: -1}"
for f in $FAIL_MV; do [ "$(basename "$src")" != "$f" ] || { echo "mv: injected failure" >&2; exit 1; }; done
"$REAL_MV" "$@" || exit
case "$dst" in "$ASSETS"/*) touch "$STUB/full" ;; esac
`

// The images of these tests, committed and captured.
var screenshotsFixture = []string{"screenshot-a.png", "screenshot-b.png", "screenshot-c.png"}

// screenshotsRun is a run of the script in a fixture: what it printed, how it exited, and the files
// among the assets afterwards, by name.
type screenshotsRun struct {
	out    string
	err    error
	assets map[string]string
	tmp    []string
}

// runScreenshots runs e2e/screenshots.sh in a fixture whose assets hold "committed <name>" for each
// committed name, whose capture took "new <name>" for each captured one and lists list in
// images.txt (no images.txt when list is nil), and whose images.json is imagesJSON. env sets the
// stubs' failures.
func runScreenshots(t *testing.T, committed, captured []string, list *string, imagesJSON string, env ...string) screenshotsRun {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "repo")
	stub := filepath.Join(dir, "stub")
	tmp := filepath.Join(dir, "tmp")
	assets := filepath.Join(root, "site", "src", "assets")
	for _, d := range []string{filepath.Join(root, "e2e", "playwright", "screenshots"), assets, filepath.Join(stub, "bin"), filepath.Join(stub, "out"), tmp} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	script, err := os.ReadFile(filepath.Join(filepath.Dir(SourceRoot(t)), "e2e", "screenshots.sh"))
	require.NoError(t, err)
	write := func(path, content string, mode os.FileMode) {
		require.NoError(t, os.WriteFile(path, []byte(content), mode))
	}
	write(filepath.Join(root, "e2e", "screenshots.sh"), string(script), 0o755)
	write(filepath.Join(root, "e2e", "playwright", "package.json"), "{\n  \"devDependencies\": {\n    \"@playwright/test\": \"1.0.0\"\n  }\n}\n", 0o644)
	write(filepath.Join(root, "e2e", "playwright", "screenshots", "images.json"), imagesJSON, 0o644)
	for _, name := range committed {
		write(filepath.Join(assets, name), "committed "+name, 0o644)
	}
	write(filepath.Join(assets, "goiaba.png"), "the logo", 0o644)
	for _, name := range captured {
		write(filepath.Join(stub, "out", name), "new "+name, 0o644)
	}
	if list != nil {
		write(filepath.Join(stub, "out", "images.txt"), *list, 0o644)
	}
	write(filepath.Join(stub, "bin", "docker"), screenshotsStubDocker, 0o755)
	write(filepath.Join(stub, "bin", "cp"), screenshotsStubCp, 0o755)
	write(filepath.Join(stub, "bin", "mv"), screenshotsStubMv, 0o755)
	realCp, err := exec.LookPath("cp")
	require.NoError(t, err)
	realMv, err := exec.LookPath("mv")
	require.NoError(t, err)

	cmd := exec.Command("bash", filepath.Join(root, "e2e", "screenshots.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"PATH="+filepath.Join(stub, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"TMPDIR="+tmp, "STUB="+stub, "ASSETS="+assets, "REAL_CP="+realCp, "REAL_MV="+realMv,
		"FAIL_CP=", "FAIL_MV=", "FULL_AFTER_RENAME=")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()

	run := screenshotsRun{out: string(out), err: err, assets: map[string]string{}}
	entries, rerr := os.ReadDir(assets)
	require.NoError(t, rerr)
	for _, e := range entries {
		run.assets[e.Name()] = readFile(t, filepath.Join(assets, e.Name()))
	}
	left, rerr := os.ReadDir(tmp)
	require.NoError(t, rerr)
	for _, e := range left {
		run.tmp = append(run.tmp, e.Name())
	}
	return run
}

// screenshotAssets is what the assets folder holds when each name holds the given prefix and the name.
func screenshotAssets(prefix map[string]string) map[string]string {
	out := map[string]string{"goiaba.png": "the logo"}
	for name, p := range prefix {
		out[name] = p + " " + name
	}
	return out
}

// screenshotsLines is the capture's images.txt listing names.
func screenshotsLines(names ...string) *string {
	s := strings.Join(names, "\n") + "\n"
	return &s
}

const fixtureImagesJSON = "[\n  \"screenshot-a.png\",\n  \"screenshot-b.png\",\n  \"screenshot-c.png\"\n]\n"

// The script writes every image the capture lists, whatever the layout of images.json, which it
// leaves to the capture to read: here two names share a line, valid JSON a line-by-line reading
// would miss.
func TestScreenshotsCommand_WritesEveryImageTheCaptureLists(t *testing.T) {
	run := runScreenshots(t, screenshotsFixture, screenshotsFixture, screenshotsLines(screenshotsFixture...),
		"[\n  \"screenshot-a.png\",\n  \"screenshot-b.png\", \"screenshot-c.png\"\n]\n")
	require.NoError(t, run.err, run.out)
	assert.Equal(t, screenshotAssets(map[string]string{"screenshot-a.png": "new", "screenshot-b.png": "new", "screenshot-c.png": "new"}), run.assets)
	for _, name := range screenshotsFixture {
		assert.Contains(t, run.out, "screenshots: wrote site/src/assets/"+name)
	}
	assert.Empty(t, run.tmp, "the staging folder is left behind")
}

// An image the run adds, one not committed before, is written too.
func TestScreenshotsCommand_WritesANewImage(t *testing.T) {
	run := runScreenshots(t, screenshotsFixture[:2], screenshotsFixture, screenshotsLines(screenshotsFixture...), fixtureImagesJSON)
	require.NoError(t, run.err, run.out)
	assert.Equal(t, screenshotAssets(map[string]string{"screenshot-a.png": "new", "screenshot-b.png": "new", "screenshot-c.png": "new"}), run.assets)
}

// A run that fails leaves the committed images as they were, with nothing of its own beside them
// and no staging folder, and says which step failed.
func TestScreenshotsCommand_AFailureLeavesTheCommittedImages(t *testing.T) {
	committed := screenshotAssets(map[string]string{"screenshot-a.png": "committed", "screenshot-b.png": "committed", "screenshot-c.png": "committed"})
	for _, tc := range []struct {
		name     string
		captured []string
		list     *string
		env      []string
		step     string
	}{
		{"the capture lists nothing", screenshotsFixture, nil, nil, "checking the images captured"},
		{"the capture lists a path", screenshotsFixture, screenshotsLines("screenshot-a.png", "../screenshot-b.png"), nil, "checking the images captured"},
		{"the capture missed a listed image", screenshotsFixture[:2], screenshotsLines(screenshotsFixture...), nil, "checking the images captured"},
		{"a new image cannot be written beside the committed one", screenshotsFixture, screenshotsLines(screenshotsFixture...),
			[]string{"FAIL_CP=.screenshot-b.png.new"}, "preparing the replacements"},
		{"a committed image cannot be copied beside itself", screenshotsFixture, screenshotsLines(screenshotsFixture...),
			[]string{"FAIL_CP=.screenshot-c.png.old"}, "preparing the replacements"},
		// The disk fills once the first image has replaced its committed one, and the second
		// replacement fails: putting the first back has to write no data.
		{"the second replacement fails on a full disk", screenshotsFixture, screenshotsLines(screenshotsFixture...),
			[]string{"FAIL_MV=.screenshot-b.png.new", "FULL_AFTER_RENAME=1"}, "replacing the committed images"},
		{"the last replacement fails", screenshotsFixture, screenshotsLines(screenshotsFixture...),
			[]string{"FAIL_MV=.screenshot-c.png.new"}, "replacing the committed images"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := runScreenshots(t, screenshotsFixture, tc.captured, tc.list, fixtureImagesJSON, tc.env...)
			require.Error(t, run.err, run.out)
			assert.Equal(t, committed, run.assets, run.out)
			assert.Contains(t, run.out, "screenshots: failed while "+tc.step)
			assert.NotContains(t, run.out, "screenshots: wrote")
			assert.Empty(t, run.tmp, "the staging folder is left behind")
		})
	}
}

// A failed run after the servers were removed still shows their last log lines, kept from before
// the removal.
func TestScreenshotsCommand_AFailureAfterTheRemovalShowsTheServerLogs(t *testing.T) {
	run := runScreenshots(t, screenshotsFixture, screenshotsFixture, screenshotsLines(screenshotsFixture...), fixtureImagesJSON,
		"FAIL_MV=.screenshot-b.png.new")
	require.Error(t, run.err, run.out)
	assert.Contains(t, run.out, "screenshots: failed while replacing the committed images")
	assert.Contains(t, run.out, "--- the servers' last log lines")
	assert.Contains(t, run.out, "authserver-1 | the auth server's last line")
	assert.Contains(t, run.out, "adminconsole-1 | the console's last line")
}

// When an image replaced cannot be put back, its committed bytes stay beside it, and the run says
// where; the images it could put back or never replaced are as they were.
func TestScreenshotsCommand_ACopyNotPutBackIsKept(t *testing.T) {
	run := runScreenshots(t, screenshotsFixture, screenshotsFixture, screenshotsLines(screenshotsFixture...), fixtureImagesJSON,
		"FAIL_MV=.screenshot-c.png.new .screenshot-a.png.old")
	require.Error(t, run.err, run.out)
	want := screenshotAssets(map[string]string{"screenshot-a.png": "new", "screenshot-b.png": "committed", "screenshot-c.png": "committed"})
	want[".screenshot-a.png.old"] = "committed screenshot-a.png"
	assert.Equal(t, want, run.assets, run.out)
	assert.Contains(t, run.out, "could not put back site/src/assets/screenshot-a.png; the committed one is site/src/assets/.screenshot-a.png.old")
}
