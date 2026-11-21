package guard

// e2e/screenshots.sh writes the images its capture took over the committed ones, and a run that fails
// leaves the committed ones as they were (#534 decision 1). These tests run the script in a copy of
// the folders it touches, with docker replaced by a stub that plays the Compose project and hands
// back the images a test put in its capture folder, and with cp, mv and rm replaced by stubs that fail
// where the test says, as a full or failing disk would.

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"image/png"
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

// screenshotsStubCp, screenshotsStubMv and screenshotsStubRm fail a copy into, a rename out of, or a
// deletion of the files the test names in FAIL_CP, FAIL_MV and FAIL_RM, by file name. With
// FULL_AFTER_RENAME set, the assets folder takes no new file once a first rename into it has
// succeeded, as a disk that has just filled.
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

// The rm stub matches FAIL_RM's names as patterns, so a test can name the staging folder, whose
// suffix is random; KILL_RM's sends the script SIGTERM, as an interrupt, before deleting.
const screenshotsStubRm = `#!/usr/bin/env bash
set -f
for arg in "$@"; do
  case "$arg" in -*) continue ;; esac
  for f in $KILL_RM; do case "$(basename "$arg")" in $f) kill -TERM "$PPID" ;; esac; done
  for f in $FAIL_RM; do case "$(basename "$arg")" in $f) echo "rm: injected failure" >&2; exit 1 ;; esac; done
done
exec "$REAL_RM" "$@"
`

// The images of these tests, committed and captured.
var screenshotsFixture = []string{"screenshot-a.png", "screenshot-b.png", "screenshot-c.png"}

// screenshotsPrepared is the name the runs' own folders among the assets take in a screenshotsRun's
// assets, whatever their random suffix.
const screenshotsPrepared = ".screenshots-*"

// screenshotsRun is a run of the script in a fixture: what it printed, how it exited, the files
// among the assets afterwards, by path, with a run's own folder named screenshotsPrepared, the
// names of the run folders left among the assets, and what is left in the temporary folder.
type screenshotsRun struct {
	out      string
	err      error
	assets   map[string]string
	prepared []string
	tmp      []string
}

// screenshotsFixtureDir is a copy of the folders the script touches, with the stubs in place.
type screenshotsFixtureDir struct {
	root, stub, tmp, assets string
}

// newScreenshotsFixture makes a fixture whose assets hold "committed <name>" for each committed
// name, whose capture took "new <name>" for each captured one and lists list in images.txt (no
// images.txt when list is nil), and whose images.json is imagesJSON.
func newScreenshotsFixture(t *testing.T, committed, captured []string, list *string, imagesJSON string) screenshotsFixtureDir {
	t.Helper()
	dir := t.TempDir()
	f := screenshotsFixtureDir{root: filepath.Join(dir, "repo"), stub: filepath.Join(dir, "stub"), tmp: filepath.Join(dir, "tmp")}
	f.assets = filepath.Join(f.root, "site", "src", "assets")
	for _, d := range []string{filepath.Join(f.root, "e2e", "playwright", "screenshots"), f.assets, filepath.Join(f.stub, "bin"), filepath.Join(f.stub, "out"), f.tmp} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	script, err := os.ReadFile(filepath.Join(filepath.Dir(SourceRoot(t)), "e2e", "screenshots.sh"))
	require.NoError(t, err)
	write := func(path, content string, mode os.FileMode) {
		require.NoError(t, os.WriteFile(path, []byte(content), mode))
	}
	write(filepath.Join(f.root, "e2e", "screenshots.sh"), string(script), 0o755)
	write(filepath.Join(f.root, "e2e", "playwright", "package.json"), "{\n  \"devDependencies\": {\n    \"@playwright/test\": \"1.0.0\"\n  }\n}\n", 0o644)
	write(filepath.Join(f.root, "e2e", "playwright", "screenshots", "images.json"), imagesJSON, 0o644)
	for _, name := range committed {
		write(filepath.Join(f.assets, name), "committed "+name, 0o644)
	}
	write(filepath.Join(f.assets, "goiaba.png"), "the logo", 0o644)
	for _, name := range captured {
		write(filepath.Join(f.stub, "out", name), screenshotContent("new", name), 0o644)
	}
	if list != nil {
		write(filepath.Join(f.stub, "out", "images.txt"), *list, 0o644)
	}
	write(filepath.Join(f.stub, "bin", "docker"), screenshotsStubDocker, 0o755)
	write(filepath.Join(f.stub, "bin", "cp"), screenshotsStubCp, 0o755)
	write(filepath.Join(f.stub, "bin", "mv"), screenshotsStubMv, 0o755)
	write(filepath.Join(f.stub, "bin", "rm"), screenshotsStubRm, 0o755)
	return f
}

// run runs e2e/screenshots.sh in the fixture; env sets the stubs' failures.
func (f screenshotsFixtureDir) run(t *testing.T, env ...string) screenshotsRun {
	t.Helper()
	tools := map[string]string{}
	for _, tool := range []string{"cp", "mv", "rm"} {
		path, err := exec.LookPath(tool)
		require.NoError(t, err)
		tools[tool] = path
	}
	cmd := exec.Command("bash", filepath.Join(f.root, "e2e", "screenshots.sh"))
	cmd.Dir = f.root
	cmd.Env = append(os.Environ(),
		"PATH="+filepath.Join(f.stub, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"TMPDIR="+f.tmp, "STUB="+f.stub, "ASSETS="+f.assets,
		"REAL_CP="+tools["cp"], "REAL_MV="+tools["mv"], "REAL_RM="+tools["rm"],
		"FAIL_CP=", "FAIL_MV=", "FAIL_RM=", "KILL_RM=", "FULL_AFTER_RENAME=")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()

	run := screenshotsRun{out: string(out), err: err, assets: map[string]string{}}
	entries, rerr := os.ReadDir(f.assets)
	require.NoError(t, rerr)
	for _, e := range entries {
		if !e.IsDir() {
			run.assets[e.Name()] = readFile(t, filepath.Join(f.assets, e.Name()))
			continue
		}
		require.Regexp(t, `^\.screenshots-[A-Za-z0-9]{6}$`, e.Name(), "a folder among the assets that is not a run's own")
		run.prepared = append(run.prepared, e.Name())
		inner, readErr := os.ReadDir(filepath.Join(f.assets, e.Name()))
		require.NoError(t, readErr)
		run.assets[screenshotsPrepared] = ""
		for _, i := range inner {
			run.assets[screenshotsPrepared+"/"+i.Name()] = readFile(t, filepath.Join(f.assets, e.Name(), i.Name()))
		}
	}
	left, rerr := os.ReadDir(f.tmp)
	require.NoError(t, rerr)
	for _, e := range left {
		run.tmp = append(run.tmp, e.Name())
	}
	return run
}

// runScreenshots runs e2e/screenshots.sh once in a new fixture (see newScreenshotsFixture).
func runScreenshots(t *testing.T, committed, captured []string, list *string, imagesJSON string, env ...string) screenshotsRun {
	t.Helper()
	return newScreenshotsFixture(t, committed, captured, list, imagesJSON).run(t, env...)
}

// screenshotAssets is what the assets folder holds when each name holds its screenshotContent.
func screenshotAssets(prefix map[string]string) map[string]string {
	out := map[string]string{"goiaba.png": "the logo"}
	for name, p := range prefix {
		out[name] = screenshotContent(p, name)
	}
	return out
}

// screenshotContent is what a fixture's image named name holds: a committed one, which the script
// never reads, the prefix and the name as text; a captured one, prefix "new", a PNG holding them.
func screenshotContent(prefix, name string) string {
	if prefix == "new" {
		return fixturePNG(prefix + " " + name)
	}
	return prefix + " " + name
}

// fixturePNG is a valid PNG of one grey pixel whose tEXt chunk holds text, so each image's bytes
// are its own.
func fixturePNG(text string) string {
	var b bytes.Buffer
	b.WriteString("\x89PNG\r\n\x1a\n")
	chunk := func(kind string, data []byte) {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(data)))
		body := append([]byte(kind), data...)
		b.Write(body)
		_ = binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(body))
	}
	chunk("IHDR", []byte{0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0})
	chunk("tEXt", append([]byte("Comment\x00"), text...))
	var pixels bytes.Buffer
	z := zlib.NewWriter(&pixels)
	_, _ = z.Write([]byte{0, 0x80})
	_ = z.Close()
	chunk("IDAT", pixels.Bytes())
	chunk("IEND", nil)
	return b.String()
}

func TestScreenshotsCommand_TheFixturesImagesArePNGs(t *testing.T) {
	_, err := png.Decode(strings.NewReader(fixturePNG("new screenshot-a.png")))
	require.NoError(t, err)
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
		// setup changes, after the fixture is made, what the capture hands back, in its folder out.
		setup func(t *testing.T, out string)
	}{
		{"the capture lists nothing", screenshotsFixture, nil, nil, "checking the images captured", nil},
		{"the capture lists a path", screenshotsFixture, screenshotsLines("screenshot-a.png", "../screenshot-b.png"), nil, "checking the images captured", nil},
		{"the capture missed a listed image", screenshotsFixture[:2], screenshotsLines(screenshotsFixture...), nil, "checking the images captured", nil},
		{"a new image cannot be written beside the committed one", screenshotsFixture, screenshotsLines(screenshotsFixture...),
			[]string{"FAIL_CP=screenshot-b.png.new"}, "preparing the replacements", nil},
		{"a committed image cannot be copied beside itself", screenshotsFixture, screenshotsLines(screenshotsFixture...),
			[]string{"FAIL_CP=screenshot-c.png.old"}, "preparing the replacements", nil},
		// The disk fills once the first image has replaced its committed one, and the second
		// replacement fails: putting the first back has to write no data.
		{"the second replacement fails on a full disk", screenshotsFixture, screenshotsLines(screenshotsFixture...),
			[]string{"FAIL_MV=screenshot-b.png.new", "FULL_AFTER_RENAME=1"}, "replacing the committed images", nil},
		{"the last replacement fails", screenshotsFixture, screenshotsLines(screenshotsFixture...),
			[]string{"FAIL_MV=screenshot-c.png.new"}, "replacing the committed images", nil},
		// docker cp keeps a link the capture made, which the host would follow to a file of its own
		// and commit: here a valid PNG outside the capture's folder, which a check of the bytes alone
		// would take.
		{"a captured image is a link", screenshotsFixture, screenshotsLines(screenshotsFixture...), nil, "checking the images captured",
			func(t *testing.T, out string) {
				outside := filepath.Join(filepath.Dir(out), "outside.png")
				require.NoError(t, os.WriteFile(outside, []byte(fixturePNG("a file of the host's")), 0o644))
				require.NoError(t, os.Remove(filepath.Join(out, "screenshot-b.png")))
				require.NoError(t, os.Symlink(outside, filepath.Join(out, "screenshot-b.png")))
			}},
		{"the capture's list is a link", screenshotsFixture, nil, nil, "checking the images captured",
			func(t *testing.T, out string) {
				outside := filepath.Join(filepath.Dir(out), "outside.txt")
				require.NoError(t, os.WriteFile(outside, []byte(*screenshotsLines(screenshotsFixture...)), 0o644))
				require.NoError(t, os.Symlink(outside, filepath.Join(out, "images.txt")))
			}},
		{"a captured image is a folder", screenshotsFixture[:2], screenshotsLines(screenshotsFixture...), nil, "checking the images captured",
			func(t *testing.T, out string) {
				require.NoError(t, os.Mkdir(filepath.Join(out, "screenshot-c.png"), 0o755))
			}},
		{"a captured image is not a PNG", screenshotsFixture, screenshotsLines(screenshotsFixture...), nil, "checking the images captured",
			func(t *testing.T, out string) {
				require.NoError(t, os.WriteFile(filepath.Join(out, "screenshot-b.png"), []byte("SECRET=a credential\n"), 0o644))
			}},
		{"a captured image is a PNG cut short", screenshotsFixture, screenshotsLines(screenshotsFixture...), nil, "checking the images captured",
			func(t *testing.T, out string) {
				image := fixturePNG("new screenshot-b.png")
				require.NoError(t, os.WriteFile(filepath.Join(out, "screenshot-b.png"), []byte(image[:len(image)-12]), 0o644))
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newScreenshotsFixture(t, screenshotsFixture, tc.captured, tc.list, fixtureImagesJSON)
			if tc.setup != nil {
				tc.setup(t, filepath.Join(f.stub, "out"))
			}
			run := f.run(t, tc.env...)
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
		"FAIL_MV=screenshot-b.png.new")
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
		"FAIL_MV=screenshot-c.png.new screenshot-a.png.old")
	require.Error(t, run.err, run.out)
	want := screenshotAssets(map[string]string{"screenshot-a.png": "new", "screenshot-b.png": "committed", "screenshot-c.png": "committed"})
	want[screenshotsPrepared] = ""
	want[screenshotsPrepared+"/screenshot-a.png.old"] = "committed screenshot-a.png"
	assert.Equal(t, want, run.assets, run.out)
	require.Len(t, run.prepared, 1)
	assert.Contains(t, run.out, "could not put back site/src/assets/screenshot-a.png; the committed one is site/src/assets/"+run.prepared[0]+"/screenshot-a.png.old")
}

// A run that fails after an earlier one kept a copy it could not put back leaves that copy where it
// is: each run prepares in a folder of its own and discards only that one.
func TestScreenshotsCommand_ARetryKeepsAnEarlierRunsCopy(t *testing.T) {
	f := newScreenshotsFixture(t, screenshotsFixture, screenshotsFixture, screenshotsLines(screenshotsFixture...), fixtureImagesJSON)
	first := f.run(t, "FAIL_MV=screenshot-b.png.new screenshot-a.png.old")
	require.Error(t, first.err, first.out)
	require.Len(t, first.prepared, 1, first.out)

	retry := f.run(t, "FAIL_CP=screenshot-a.png.new")
	require.Error(t, retry.err, retry.out)
	assert.Contains(t, retry.out, "screenshots: failed while preparing the replacements")
	want := screenshotAssets(map[string]string{"screenshot-a.png": "new", "screenshot-b.png": "committed", "screenshot-c.png": "committed"})
	want[screenshotsPrepared] = ""
	want[screenshotsPrepared+"/screenshot-a.png.old"] = "committed screenshot-a.png"
	assert.Equal(t, want, retry.assets, retry.out)
	assert.Equal(t, first.prepared, retry.prepared, "the retry left a folder of its own, or removed the first run's")
}

// Once every image is replaced the run has succeeded: a copy of a committed image it then cannot
// delete is reported and kept, and the run exits zero having written every image, the copies
// deleted before and after it gone.
func TestScreenshotsCommand_ACopyNotDeletedAfterTheReplacementsIsAWarning(t *testing.T) {
	run := runScreenshots(t, screenshotsFixture, screenshotsFixture, screenshotsLines(screenshotsFixture...), fixtureImagesJSON,
		"FAIL_RM=screenshot-b.png.old")
	require.NoError(t, run.err, run.out)
	want := screenshotAssets(map[string]string{"screenshot-a.png": "new", "screenshot-b.png": "new", "screenshot-c.png": "new"})
	want[screenshotsPrepared] = ""
	want[screenshotsPrepared+"/screenshot-b.png.old"] = "committed screenshot-b.png"
	assert.Equal(t, want, run.assets, run.out)
	require.Len(t, run.prepared, 1)
	assert.Contains(t, run.out, "screenshots: warning: could not delete site/src/assets/"+run.prepared[0]+"/screenshot-b.png.old")
	assert.NotContains(t, run.out, "screenshots: failed")
	for _, name := range screenshotsFixture {
		assert.Contains(t, run.out, "screenshots: wrote site/src/assets/"+name)
	}
	assert.Empty(t, run.tmp, "the staging folder is left behind")
}

// The staging folder the run cannot delete, once every image is written, is only reported: the run
// succeeds and keeps the folder.
func TestScreenshotsCommand_AStagingFolderNotDeletedAfterTheReplacementsIsAWarning(t *testing.T) {
	run := runScreenshots(t, screenshotsFixture, screenshotsFixture, screenshotsLines(screenshotsFixture...), fixtureImagesJSON,
		"FAIL_RM=goiabada-screenshots.*")
	require.NoError(t, run.err, run.out)
	assert.Equal(t, screenshotAssets(map[string]string{"screenshot-a.png": "new", "screenshot-b.png": "new", "screenshot-c.png": "new"}), run.assets, run.out)
	require.Len(t, run.tmp, 1, "the staging folder the run could not delete")
	assert.Contains(t, run.out, "screenshots: warning: could not delete the staging folder ")
	assert.Contains(t, run.out, string(filepath.Separator)+run.tmp[0]+"; delete it by hand")
	assert.NotContains(t, run.out, "screenshots: failed")
	for _, name := range screenshotsFixture {
		assert.Contains(t, run.out, "screenshots: wrote site/src/assets/"+name)
	}
}

// An interrupt once every image is written does not make the run fail: it exits zero and names the
// folder of copies it may leave.
func TestScreenshotsCommand_AnInterruptAfterTheReplacementsIsAWarning(t *testing.T) {
	run := runScreenshots(t, screenshotsFixture, screenshotsFixture, screenshotsLines(screenshotsFixture...), fixtureImagesJSON,
		"KILL_RM=screenshot-b.png.old")
	require.NoError(t, run.err, run.out)
	want := screenshotAssets(map[string]string{"screenshot-a.png": "new", "screenshot-b.png": "new", "screenshot-c.png": "new"})
	want[screenshotsPrepared] = ""
	want[screenshotsPrepared+"/screenshot-c.png.old"] = "committed screenshot-c.png"
	assert.Equal(t, want, run.assets, run.out)
	require.Len(t, run.prepared, 1)
	assert.Contains(t, run.out, "screenshots: warning: stopped while deleting the copies of the committed images, after every image was written; delete site/src/assets/"+run.prepared[0]+" if it is left")
	assert.NotContains(t, run.out, "screenshots: failed")
	assert.Empty(t, run.tmp, "the staging folder is left behind")
}
