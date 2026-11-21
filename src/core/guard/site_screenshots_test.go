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

// The pages that show screenshots.
var screenshotPages = []string{homePage, readmePage}

// Every screenshot the home page or the README shows is a file in the repository, and each page
// shows at least one.
func TestSiteScreenshots_EveryOneThePagesShowExists(t *testing.T) {
	root := SourceRoot(t)
	for _, page := range screenshotPages {
		shown := screenshotsShown(page, readFile(t, filepath.Join(root, page)))
		require.NotEmptyf(t, shown, "%s shows no screenshot", page)
		assert.Emptyf(t, missingScreenshots(root, shown), "%s shows screenshots that are not files in the repository", page)
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

// Every image e2e/screenshots.sh writes is among the site's assets and shown, that file and not
// another of the same name, by the home page or the README.
func TestSiteScreenshots_EveryOneTheCommandWritesIsShown(t *testing.T) {
	root := SourceRoot(t)
	var shown []shownScreenshot
	for _, page := range screenshotPages {
		shown = append(shown, screenshotsShown(page, readFile(t, filepath.Join(root, page)))...)
	}
	written := screenshotsWritten(t, readFile(t, filepath.Join(root, screenshotsList)))
	for _, name := range written {
		_, err := os.Stat(filepath.Join(root, siteAssetsFolder, name))
		require.NoErrorf(t, err, "%s lists %s, which is not among %s", screenshotsList, name, siteAssetsFolder)
	}
	assert.Emptyf(t, unshownScreenshots(shown, written), "%s lists images that neither %s nor %s shows from %s",
		screenshotsList, homePage, readmePage, siteAssetsFolder)
}

// The two checks over what the pages show fail on a page that breaks them, whichever way it writes
// the image.
func TestSiteScreenshots_TheChecksFail(t *testing.T) {
	root := SourceRoot(t)

	// A missing image, however its HTML source is quoted, or shown by URL.
	readme := "<img src='site/src/assets/screenshot-missing.png' alt=\"Gone\">\n" +
		"<img alt=Gone src=site/src/assets/screenshot-gone.png>\n" +
		"<img src=\"site/src/assets/screenshot-users.png\" alt=\"Users\">\n" +
		"![Remote](https://example.com/screenshot-remote.png)\n"
	assert.Equal(t, []string{
		"site/src/assets/screenshot-missing.png",
		"site/src/assets/screenshot-gone.png",
		"https://example.com/screenshot-remote.png",
	}, missingScreenshots(root, screenshotsShown(readmePage, readme)))

	// A listed image the home page shows only through a copy of the same name beside it.
	home := "![The Phone page](./screenshot-account-phone.png)\n![Users](../../assets/screenshot-users.png)\n"
	assert.Equal(t, []string{"screenshot-account-phone.png"},
		unshownScreenshots(screenshotsShown(homePage, home), []string{"screenshot-account-phone.png", "screenshot-users.png"}))

	// Listed images the README names only inside comments: an inline image and an HTML <img>
	// commented out, a reference image whose definition is commented out, and an image after a
	// comment that is never closed. The visible one beside them is still shown.
	readme = "<!-- ![Hidden](site/src/assets/screenshot-a.png) -->\n" +
		"<!--\n<img src=\"site/src/assets/screenshot-b.png\">\n-->\n" +
		"![Defined][c]\n\n<!-- [c]: site/src/assets/screenshot-c.png -->\n" +
		"![Visible](site/src/assets/screenshot-users.png)\n" +
		"<!-- never closed\n![Unclosed](site/src/assets/screenshot-d.png)\n"
	written := []string{"screenshot-a.png", "screenshot-b.png", "screenshot-c.png", "screenshot-d.png", "screenshot-users.png"}
	assert.Equal(t, []string{"screenshot-a.png", "screenshot-b.png", "screenshot-c.png", "screenshot-d.png"},
		unshownScreenshots(screenshotsShown(readmePage, readme), written))

	// On the home page, an MDX page, an MDX comment hides its image too.
	home = "{/* ![Hidden](../../assets/screenshot-a.png) */}\n{/*\n  ![Hidden](../../assets/screenshot-b.png)\n*/}\n" +
		"![Visible](../../assets/screenshot-users.png)\n"
	assert.Equal(t, []string{"screenshot-a.png", "screenshot-b.png"},
		unshownScreenshots(screenshotsShown(homePage, home), []string{"screenshot-a.png", "screenshot-b.png", "screenshot-users.png"}))
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

	for _, page := range screenshotPages {
		for _, s := range screenshotsShown(page, readFile(t, filepath.Join(root, page))) {
			assert.Falsef(t, numberedScreenshot.MatchString(path.Base(s.file)),
				"%s shows %s, which is numbered; name it for what it shows", page, s.target)
		}
	}
}

func TestSiteScreenshots_TheReader(t *testing.T) {
	page := "# Title\n\n![The sign-in page](../../assets/screenshot-signin.png)\n\n" +
		"<p align=\"center\">\n  <img src=\"site/src/assets/screenshot-users.png\" alt=\"Users\">\n</p>\n\n" +
		"<img alt=\"Card\" src=\"site/src/assets/screenshot-signin-card.png\" width=\"320\">\n\n" +
		"<IMG width=320\n  SRC = 'site/src/assets/screenshot-single.png'>\n" +
		"<img alt=x src=site/src/assets/screenshot-bare.png>\n" +
		"<img data-src=\"site/src/assets/screenshot-lazy.png\" src=\"site/src/assets/goiaba.png\">\n" +
		"![Titled](<site/src/assets/screenshot-titled.png> \"A title\")\n" +
		"![Queried](site/src/assets/screenshot-queried.png?v=2#top)\n" +
		"![Full][phone] ![Collapsed][] ![Shortcut] ![Undefined][nothing]\n\n" +
		"[phone]: site/src/assets/screenshot-full.png\n" +
		"[collapsed]: <site/src/assets/screenshot-collapsed.png>\n" +
		"  [Shortcut]: site/src/assets/screenshot-shortcut.png \"Title\"\n" +
		"![The logo](../../assets/goiaba.png)\n<img src=\"site/src/assets/goiaba.png\" alt=\"Logo\">\n" +
		"A screenshot.png named in prose is not shown, nor [a link](site/src/assets/screenshot-link.png).\n"
	assert.Equal(t, []shownScreenshot{
		{"../../assets/screenshot-signin.png", "../../../assets/screenshot-signin.png"},
		{"site/src/assets/screenshot-users.png", "../site/src/assets/screenshot-users.png"},
		{"site/src/assets/screenshot-signin-card.png", "../site/src/assets/screenshot-signin-card.png"},
		{"site/src/assets/screenshot-single.png", "../site/src/assets/screenshot-single.png"},
		{"site/src/assets/screenshot-bare.png", "../site/src/assets/screenshot-bare.png"},
		{"site/src/assets/screenshot-titled.png", "../site/src/assets/screenshot-titled.png"},
		{"site/src/assets/screenshot-queried.png?v=2#top", "../site/src/assets/screenshot-queried.png"},
		{"site/src/assets/screenshot-full.png", "../site/src/assets/screenshot-full.png"},
		{"site/src/assets/screenshot-collapsed.png", "../site/src/assets/screenshot-collapsed.png"},
		{"site/src/assets/screenshot-shortcut.png", "../site/src/assets/screenshot-shortcut.png"},
	}, screenshotsShown("../README.md", page))

	// A target resolves against the page's folder; one that is a URL or absolute is no file here.
	assert.Equal(t, []shownScreenshot{
		{"../../assets/screenshot-a.png", "../site/src/assets/screenshot-a.png"},
		{"./screenshot-a.png", "../site/src/content/docs/screenshot-a.png"},
		{"/screenshot-a.png", ""},
		{"https://example.com/screenshot-a.png", ""},
	}, screenshotsShown(homePage, "![a](../../assets/screenshot-a.png) ![b](./screenshot-a.png)\n"+
		"![c](/screenshot-a.png) ![d](https://example.com/screenshot-a.png)\n"))

	assert.True(t, numberedScreenshot.MatchString("screenshot2.png"))
	assert.True(t, numberedScreenshot.MatchString("screenshot.png"))
	assert.False(t, numberedScreenshot.MatchString("screenshot-users.png"))
	assert.True(t, numberedScreenshot.MatchString("screenshot3.jpg"))
	assert.True(t, isScreenshot("screenshot-users.jpg"))
	assert.False(t, isScreenshot("goiaba.png"))

	assert.Equal(t, []string{"screenshot-a.png", "screenshot-b.png"},
		screenshotsWritten(t, "[\n  \"screenshot-a.png\",\n  \"screenshot-b.png\"\n]\n"))
	assert.Equal(t, []string{"screenshot-a.png", "screenshot-b.png"},
		screenshotsWritten(t, `["screenshot-a.png", "screenshot-b.png"]`))
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

// shownScreenshot is an image a page shows whose file is a screenshot: its target as the page
// writes it, and the file that target names, relative to the source root and slash-separated, or
// empty when the target is a URL or an absolute path, which names no file in the repository.
type shownScreenshot struct {
	target string
	file   string
}

// imageReference matches, in the order a page shows them, a Markdown inline image,
// ![alt](target "title"), its target in angle brackets or not; a Markdown reference image, full
// ![alt][label], collapsed ![alt][] or shortcut ![alt]; and the src of an HTML <img>, quoted with
// double quotes, single quotes or none.
var imageReference = regexp.MustCompile(
	`!\[([^\]]*)\]\(\s*(<[^>]*>|[^)\s]+)(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)` +
		`|!\[([^\]]*)\]\[([^\]]*)\]` +
		`|!\[([^\]]*)\]` +
		`|(?i:<img)\s(?:[^>]*\s)?(?i:src)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>` + "`" + `]+))`)

// linkDefinition matches a Markdown link reference definition, [label]: target, which a reference
// image names.
var linkDefinition = regexp.MustCompile(`(?m)^ {0,3}\[([^\]]+)\]:[ \t]*(<[^>]*>|\S+)`)

// pageComment matches a comment, which a page does not render, so an image or a link definition
// inside one is not shown: an HTML comment, which runs to the end of the page when it is not
// closed, and, on an MDX page, an MDX comment, {/* ... */}.
var (
	pageComment = regexp.MustCompile(`(?s)<!--.*?(?:-->|$)`)
	mdxComment  = regexp.MustCompile(`(?s)\{\s*/\*.*?\*/\s*\}`)
)

// withoutComments is a page's content with its comments taken out, each left as the line breaks it
// held, so the lines around it stay lines of their own.
func withoutComments(page, content string) string {
	blank := func(comment string) string { return strings.Repeat("\n", strings.Count(comment, "\n")) }
	content = pageComment.ReplaceAllStringFunc(content, blank)
	if path.Ext(page) == ".mdx" {
		content = mdxComment.ReplaceAllStringFunc(content, blank)
	}
	return content
}

// screenshotsShown is every image a page shows whose file is a screenshot, in order, each target
// resolved against the folder of the page, given relative to the source root. An image inside a
// comment is not shown, nor one that only a definition inside a comment names.
func screenshotsShown(page, content string) []shownScreenshot {
	content = withoutComments(page, content)
	definitions := map[string]string{}
	for _, m := range linkDefinition.FindAllStringSubmatch(content, -1) {
		label := referenceLabel(m[1])
		if _, ok := definitions[label]; !ok {
			definitions[label] = m[2]
		}
	}
	var out []shownScreenshot
	for _, m := range imageReference.FindAllStringSubmatchIndex(content, -1) {
		group := func(k int) (string, bool) {
			if m[2*k] < 0 {
				return "", false
			}
			return content[m[2*k]:m[2*k+1]], true
		}
		var target string
		if inline, ok := group(2); ok {
			target = inline
		} else if alt, ok := group(3); ok {
			label, _ := group(4)
			if label == "" {
				label = alt
			}
			target = definitions[referenceLabel(label)]
		} else if alt, ok := group(5); ok {
			target = definitions[referenceLabel(alt)]
		} else {
			for k := 6; k <= 8; k++ {
				if src, ok := group(k); ok {
					target = src
				}
			}
		}
		target = strings.TrimSuffix(strings.TrimPrefix(target, "<"), ">")
		if target == "" {
			continue
		}
		file := target
		if i := strings.IndexAny(file, "?#"); i >= 0 {
			file = file[:i]
		}
		if !isScreenshot(path.Base(file)) {
			continue
		}
		if strings.Contains(file, ":") || strings.HasPrefix(file, "/") {
			file = ""
		} else {
			file = path.Join(path.Dir(page), file)
		}
		out = append(out, shownScreenshot{target: target, file: file})
	}
	return out
}

// referenceLabel is a Markdown reference label as it matches a definition: case and runs of
// whitespace ignored.
func referenceLabel(label string) string {
	return strings.ToLower(strings.Join(strings.Fields(label), " "))
}

// missingScreenshots is the target of every screenshot shown that names no file in the repository.
func missingScreenshots(root string, shown []shownScreenshot) []string {
	var missing []string
	for _, s := range shown {
		if s.file == "" {
			missing = append(missing, s.target)
			continue
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(s.file))); err != nil {
			missing = append(missing, s.target)
		}
	}
	return missing
}

// unshownScreenshots is every image e2e/screenshots.sh writes, named in written, whose file among the
// site's assets none of shown names.
func unshownScreenshots(shown []shownScreenshot, written []string) []string {
	files := map[string]bool{}
	for _, s := range shown {
		files[s.file] = true
	}
	var unshown []string
	for _, name := range written {
		if !files[path.Join(siteAssetsFolder, name)] {
			unshown = append(unshown, name)
		}
	}
	return unshown
}

// isScreenshot is whether a file name is a screenshot's, whatever its format.
func isScreenshot(name string) bool {
	return strings.HasPrefix(name, "screenshot")
}
