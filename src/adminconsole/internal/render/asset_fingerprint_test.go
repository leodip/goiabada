package render

import (
	"io/fs"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

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

// openCountingFS is a set of files, static files or templates, that counts what is opened, a Stat
// among them.
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

// pausedReadFS is a set of static files whose ReadFile, the read for a fingerprint, counts each
// call and waits for release, so a second first link can arrive while the first is still reading.
type pausedReadFS struct {
	fs.FS
	reads   atomic.Int64
	started chan struct{}
	release chan struct{}
}

func (f *pausedReadFS) ReadFile(name string) ([]byte, error) {
	f.reads.Add(1)
	f.started <- struct{}{}
	<-f.release
	return fs.ReadFile(f.FS, name)
}

// Two pages that both link a file before its fingerprint is known read it once between them: the
// second waits for the first's fingerprint rather than computing it again, and both link the file
// by it.
func TestAssetFingerprints_ConcurrentFirstLinksReadAFileOnce(t *testing.T) {
	fsys := &pausedReadFS{
		FS:      fstest.MapFS{"main.css": {Data: []byte("body{color:red}")}},
		started: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	assets := newAssetFingerprints(fsys)

	var wg sync.WaitGroup
	urls := make([]string, 2)
	failures := make([]error, len(urls))
	link := func(i int) func() {
		return func() { urls[i], failures[i] = assets.url("/static/main.css") }
	}
	wg.Go(link(0))
	select {
	case <-fsys.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the first link did not read the file for its fingerprint")
	}
	wg.Go(link(1))
	select {
	case <-fsys.started:
	case <-time.After(time.Second):
	}
	close(fsys.release)
	wg.Wait()

	for i, got := range urls {
		require.NoError(t, failures[i])
		assert.Equal(t, "/static/main.css?v=15c42ab7768d", got)
	}
	assert.Equal(t, int64(1), fsys.reads.Load(), "the file is read once for its fingerprint")
}
