package guard

// The screenshots of Goiabada, held to the pages that show them (#534).
//
// The docs home page and the README show screenshots kept among the site's assets, which
// e2e/screenshots.sh retakes: it writes the images its list, images.json, names. Every screenshot
// among the assets is one the command writes, so one added by hand, which nobody could retake,
// fails here; every image the command writes is shown by the home page or the README, so the
// command retakes none that nothing shows; and each image a page shows is a file that exists, so
// a file renamed or removed fails here rather than leaving a broken image on the home page or on
// GitHub. Each file is named for what it shows rather than numbered, so a page names an image by
// what it shows.
//
// It is a test rather than a guard: it reads two pages, one folder and one list, and core's tier
// runs it.

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The pages that show screenshots, the folder that holds them and the list of the images
// e2e/screenshots.sh writes there, relative to the source root.
const (
	homePage         = "../site/src/content/docs/index.mdx"
	readmePage       = "../README.md"
	siteAssetsFolder = "../site/src/assets"
	screenshotsList  = "../e2e/playwright/screenshots/images.json"
)

// numberedScreenshot is a screenshot's file name that says nothing of what it shows.
var numberedScreenshot = regexp.MustCompile(`^screenshot[0-9]*\.[A-Za-z]+$`)

// Every screenshot the home page or the README shows is a file among the site's assets, and each
// page shows at least one.
func TestSiteScreenshots_EveryOneThePagesShowExists(t *testing.T) {
	root := SourceRoot(t)
	for _, page := range []string{homePage, readmePage} {
		shown := screenshotsShown(readFile(t, filepath.Join(root, page)))
		require.NotEmptyf(t, shown, "%s shows no screenshot", page)
		for _, src := range shown {
			file := filepath.Join(root, filepath.Dir(page), filepath.FromSlash(src))
			_, err := os.Stat(file)
			assert.NoErrorf(t, err, "%s shows %s, which does not exist", page, src)
		}
	}
}

// Every screenshot among the site's assets is one e2e/screenshots.sh writes.
func TestSiteScreenshots_EveryOneAmongTheAssetsIsOneTheCommandWrites(t *testing.T) {
	root := SourceRoot(t)
	written := screenshotsWritten(t, readFile(t, filepath.Join(root, screenshotsList)))
	entries, err := os.ReadDir(filepath.Join(root, siteAssetsFolder))
	require.NoError(t, err, "unable to read %s", siteAssetsFolder)
	for _, entry := range entries {
		if isScreenshot(entry.Name()) {
			assert.Containsf(t, written, entry.Name(),
				"%s/%s is not one %s lists, so e2e/screenshots.sh cannot retake it; add it to the list and to the capture",
				siteAssetsFolder, entry.Name(), screenshotsList)
		}
	}
}

// Every image e2e/screenshots.sh writes is among the site's assets and shown by the home page or
// the README.
func TestSiteScreenshots_EveryOneTheCommandWritesIsShown(t *testing.T) {
	root := SourceRoot(t)
	shown := map[string]bool{}
	for _, page := range []string{homePage, readmePage} {
		for _, src := range screenshotsShown(readFile(t, filepath.Join(root, page))) {
			shown[path.Base(src)] = true
		}
	}
	for _, name := range screenshotsWritten(t, readFile(t, filepath.Join(root, screenshotsList))) {
		_, err := os.Stat(filepath.Join(root, siteAssetsFolder, name))
		assert.NoErrorf(t, err, "%s lists %s, which is not among %s", screenshotsList, name, siteAssetsFolder)
		assert.Truef(t, shown[name], "%s lists %s, which neither %s nor %s shows", screenshotsList, name, homePage, readmePage)
	}
}

// No screenshot among the site's assets, and none either page shows, is numbered rather than
// named for what it shows.
func TestSiteScreenshots_EachIsNamedForWhatItShows(t *testing.T) {
	root := SourceRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, siteAssetsFolder))
	require.NoError(t, err, "unable to read %s", siteAssetsFolder)
	names := 0
	for _, entry := range entries {
		if isScreenshot(entry.Name()) {
			names++
			assert.Falsef(t, numberedScreenshot.MatchString(entry.Name()),
				"%s/%s is numbered; name it for what it shows", siteAssetsFolder, entry.Name())
		}
	}
	require.NotZero(t, names, "%s holds no screenshot", siteAssetsFolder)

	for _, page := range []string{homePage, readmePage} {
		for _, src := range screenshotsShown(readFile(t, filepath.Join(root, page))) {
			assert.Falsef(t, numberedScreenshot.MatchString(path.Base(src)),
				"%s shows %s, which is numbered; name it for what it shows", page, src)
		}
	}
}

func TestSiteScreenshots_TheReader(t *testing.T) {
	page := "# Title\n\n![The sign-in page](../../assets/screenshot-signin.png)\n\n" +
		"<p align=\"center\">\n  <img src=\"site/src/assets/screenshot-users.png\" alt=\"Users\">\n</p>\n\n" +
		"<img alt=\"Card\" src=\"site/src/assets/screenshot-signin-card.png\" width=\"320\">\n\n" +
		"![The logo](../../assets/goiaba.png)\n<img src=\"site/src/assets/goiaba.png\" alt=\"Logo\">\n" +
		"A screenshot.png named in prose is not shown.\n"
	assert.Equal(t, []string{
		"../../assets/screenshot-signin.png",
		"site/src/assets/screenshot-users.png",
		"site/src/assets/screenshot-signin-card.png",
	}, screenshotsShown(page))

	assert.True(t, numberedScreenshot.MatchString("screenshot2.png"))
	assert.True(t, numberedScreenshot.MatchString("screenshot.png"))
	assert.False(t, numberedScreenshot.MatchString("screenshot-users.png"))
	assert.True(t, numberedScreenshot.MatchString("screenshot3.jpg"))
	assert.True(t, isScreenshot("screenshot-users.jpg"))
	assert.False(t, isScreenshot("goiaba.png"))

	assert.Equal(t, []string{"screenshot-a.png", "screenshot-b.png"},
		screenshotsWritten(t, "[\n  \"screenshot-a.png\",\n  \"screenshot-b.png\"\n]\n"))
}

// screenshotsWritten is the file names e2e/screenshots.sh writes, read from its list: a JSON array
// of names, each a screenshot's, at least one.
func screenshotsWritten(t *testing.T, list string) []string {
	t.Helper()
	var names []string
	require.NoError(t, json.Unmarshal([]byte(list), &names), "%s is not a JSON array of file names", screenshotsList)
	require.NotEmpty(t, names, "%s lists no image", screenshotsList)
	for _, name := range names {
		require.Truef(t, isScreenshot(name) && name == path.Base(name),
			"%s lists %q, which is not a screenshot's file name", screenshotsList, name)
	}
	return names
}

// imageSource matches the target of a Markdown image, ![alt](target), and the src of an HTML
// <img>, in the order the page shows them.
var imageSource = regexp.MustCompile(`!\[[^\]]*\]\(([^)\s]+)\)|<img\b[^>]*\bsrc="([^"]+)"`)

// screenshotsShown is the target of every image a page shows whose file is a screenshot, in order.
func screenshotsShown(page string) []string {
	var out []string
	for _, m := range imageSource.FindAllStringSubmatch(page, -1) {
		src := m[1]
		if src == "" {
			src = m[2]
		}
		if isScreenshot(path.Base(src)) {
			out = append(out, src)
		}
	}
	return out
}

// isScreenshot is whether a file name is a screenshot's, whatever its format.
func isScreenshot(name string) bool {
	return strings.HasPrefix(name, "screenshot")
}
