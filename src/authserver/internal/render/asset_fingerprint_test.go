package render

import (
	"regexp"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var fingerprinted = regexp.MustCompile(`^/static/main\.css\?v=[0-9a-f]{12}$`)

// A page names a static file by its contents: the URL carries a fingerprint that stays put while
// the file does and changes the moment it changes, which is what makes a browser fetch a new
// stylesheet straight after an upgrade rather than keep the old one for its five minutes (#617).
func TestAssetFingerprints_TheURLChangesExactlyWhenTheFileDoes(t *testing.T) {
	fsys := fstest.MapFS{"main.css": {Data: []byte("body{color:red}"), ModTime: time.Unix(1, 0)}}
	assets := newAssetFingerprints(fsys)

	first, err := assets.url("/static/main.css")
	require.NoError(t, err)
	assert.Regexp(t, fingerprinted, first)

	again, err := assets.url("/static/main.css")
	require.NoError(t, err)
	assert.Equal(t, first, again, "an unchanged file keeps its URL")

	fsys["main.css"] = &fstest.MapFile{Data: []byte("body{color:blue}"), ModTime: time.Unix(2, 0)}
	changed, err := assets.url("/static/main.css")
	require.NoError(t, err)
	assert.Regexp(t, fingerprinted, changed)
	assert.NotEqual(t, first, changed, "a changed file gets a new URL")
}

// A layout naming a file the server does not serve fails its render, rather than shipping a page
// whose stylesheet or script answers 404.
func TestAssetFingerprints_AFileTheServerDoesNotServeIsAnError(t *testing.T) {
	assets := newAssetFingerprints(fstest.MapFS{"main.css": {Data: []byte("x")}})

	for _, path := range []string{"/static/missing.js", "/elsewhere/main.css", "main.css"} {
		_, err := assets.url(path)
		require.Error(t, err, path)
	}

	_, err := newAssetFingerprints(nil).url("/static/main.css")
	require.Error(t, err, "a renderer built with no static files names none")
}
