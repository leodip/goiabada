package render

import (
	"io/fs"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A page names a static file by its contents, read once: the fingerprint is kept, and a page
// linking the file again opens nothing, since the built-in files cannot change while the server
// runs.
func TestAssetFingerprints_AFileIsReadOnceForItsFingerprint(t *testing.T) {
	fsys := &openCountingFS{FS: fstest.MapFS{"main.css": {Data: []byte("body{color:red}")}}}
	assets := newAssetFingerprints(fsys)

	first, err := assets.url("/static/main.css")
	require.NoError(t, err)
	assert.Equal(t, "/static/main.css?v=15c42ab7768d", first)
	opened := fsys.opens.Load()
	require.Positive(t, opened, "the first link reads the file")

	again, err := assets.url("/static/main.css")
	require.NoError(t, err)
	assert.Equal(t, first, again)
	assert.Equal(t, opened, fsys.opens.Load(), "a second link opens nothing")
}

// openCountingFS is a set of static files that counts what is opened, a Stat among them.
type openCountingFS struct {
	fs.FS
	opens atomic.Int64
}

func (f *openCountingFS) Open(name string) (fs.File, error) {
	f.opens.Add(1)
	return f.FS.Open(name)
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

// The static file server keeps a file for a year only when the bytes it answers with have the
// fingerprint the URL names, which is the one a page links those contents by: the first 12 hex
// digits of their SHA-256 (#810 decision 7).
func TestAssetFingerprint_IsTheFingerprintAPageLinksTheseContentsBy(t *testing.T) {
	assert.Equal(t, "15c42ab7768d", AssetFingerprint([]byte("body{color:red}")))
	assert.Equal(t, "fab4811e9952", AssetFingerprint([]byte("body{color:blue}")))

	fsys := fstest.MapFS{"main.css": {Data: []byte("body{color:red}")}}
	linked, err := newAssetFingerprints(fsys).url("/static/main.css")
	require.NoError(t, err)
	assert.Equal(t, "/static/main.css?v=15c42ab7768d", linked)
}
