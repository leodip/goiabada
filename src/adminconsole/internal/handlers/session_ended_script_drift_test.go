package handlers

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionEndedScripts_EveryFetchSiteFollowsTheCode holds the browser's half of #427 decision 17
// to the Go half HandleAPIErrorJson writes.
//
// An admin API 401 reaches an AJAX request as a 403 carrying sessionEndedCode, and the browser, not
// the server, has to go to sessionEndedPath: a redirect answered to fetch() is followed invisibly
// and hands the script the home page's HTML to parse as JSON. So every script that sends a request
// has to recognise the code, and nothing in this repository executes JavaScript to check that one
// does. This test is therefore a drift guard and no more:
//
//   - utils.js declares the code and the path with the literals the helper emits and the route is
//     mounted at, so renaming either on one side fails here;
//   - the recount of request sites under web/ still finds exactly the three this change handled,
//     sendAjaxRequest in utils.js and uploadImage and handleDelete in image-upload.js, so a fourth
//     raw fetch() fails until it is handled too;
//   - each of the three, within its own function, calls isSessionEnded and goToSessionEnded.
//
// It does not prove that any of them navigates. That is read, not run.
func TestSessionEndedScripts_EveryFetchSiteFollowsTheCode(t *testing.T) {
	// go test runs with the package directory as the working directory, so this is
	// src/adminconsole/web.
	const webRoot = "../../web"

	requestSite := regexp.MustCompile(`\bfetch\(|XMLHttpRequest\(|\$\.ajax\(|\baxios\b`)
	// A function declaration at any indentation ends the function a request site sits in. The
	// three sites use arrow functions inside, so the next declaration is the next function.
	nextFunction := regexp.MustCompile(`\n\s*function `)

	sources := map[string]string{}
	sites := map[string]int{}
	err := filepath.WalkDir(webRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (!strings.HasSuffix(path, ".js") && !strings.HasSuffix(path, ".html")) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(strings.TrimPrefix(path, webRoot+string(filepath.Separator)))
		sources[name] = string(content)
		if n := len(requestSite.FindAllStringIndex(string(content), -1)); n > 0 {
			sites[name] = n
		}
		return nil
	})
	require.NoError(t, err)
	require.Contains(t, sources, "static/utils.js", "the walk reached nothing: is %s the web directory?", webRoot)
	require.Contains(t, sources, "static/image-upload.js")

	var found []string
	for name := range sites {
		found = append(found, name)
	}
	sort.Strings(found)
	assert.Equal(t, map[string]int{"static/utils.js": 1, "static/image-upload.js": 2}, sites,
		"a request site was added or removed under web/ (%v): one that can receive an admin API 401 "+
			"must follow %q to %s the way the three handled here do, and then this count moves", found,
		sessionEndedCode, sessionEndedPath)

	utils := sources["static/utils.js"]
	assert.Contains(t, utils, `const SESSION_ENDED_CODE = "`+sessionEndedCode+`";`,
		"utils.js must key on the code HandleAPIErrorJson answers")
	assert.Contains(t, utils, `const SESSION_ENDED_PATH = "`+sessionEndedPath+`";`,
		"utils.js must navigate to the route the page helpers redirect to")

	for name, count := range sites {
		source := sources[name]
		for i, loc := range requestSite.FindAllStringIndex(source, -1) {
			body := source[loc[0]:]
			if end := nextFunction.FindStringIndex(body); end != nil {
				body = body[:end[0]]
			}
			assert.Containsf(t, body, "isSessionEnded(", "%s, request site %d of %d, does not check for the session-ended code", name, i+1, count)
			assert.Containsf(t, body, "goToSessionEnded", "%s, request site %d of %d, does not go to the session-ended route", name, i+1, count)
		}
	}
}
