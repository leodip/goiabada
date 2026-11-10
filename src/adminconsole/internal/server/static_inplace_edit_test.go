package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// editedInPlaceFS is a real static directory whose one file an operator edits in place: an open
// file's first read finds the file already rewritten with the next of edits, and dated
// editedAt, after its metadata was taken. Once the edits run out the file stays as it is.
type editedInPlaceFS struct {
	fs.FS
	path     string
	edits    [][]byte
	editedAt time.Time
}

func (f *editedInPlaceFS) Open(name string) (fs.File, error) {
	file, err := f.FS.Open(name)
	if err != nil {
		return nil, err
	}
	return &editedInPlaceFile{File: file, fsys: f}, nil
}

type editedInPlaceFile struct {
	fs.File
	fsys *editedInPlaceFS
	read bool
}

func (f *editedInPlaceFile) Read(p []byte) (int, error) {
	if !f.read && len(f.fsys.edits) > 0 {
		edit := f.fsys.edits[0]
		f.fsys.edits = f.fsys.edits[1:]
		if err := os.WriteFile(f.fsys.path, edit, 0o600); err != nil {
			return 0, err
		}
		if err := os.Chtimes(f.fsys.path, f.fsys.editedAt, f.fsys.editedAt); err != nil {
			return 0, err
		}
	}
	f.read = true
	return f.File.Read(p)
}

func (f *editedInPlaceFile) Seek(offset int64, whence int) (int64, error) {
	return f.File.(io.Seeker).Seek(offset, whence)
}

// newEditedInPlaceFS writes original to a temporary probe.css dated originalAt, to be edited in
// place with edits.
func newEditedInPlaceFS(t *testing.T, original []byte, originalAt time.Time, edits [][]byte, editedAt time.Time) *editedInPlaceFS {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.css")
	require.NoError(t, os.WriteFile(path, original, 0o600))
	require.NoError(t, os.Chtimes(path, originalAt, originalAt))
	return &editedInPlaceFS{FS: os.DirFS(dir), path: path, edits: edits, editedAt: editedAt}
}

// A static file edited in place while it is read is answered with metadata describing the bytes
// read: their length, their range bounds, and the edit's date, not the size and date taken before
// the edit. Otherwise a grown file goes out cut short under its full fingerprint, kept for a year,
// and a conditional request is answered 304 on the old date (#810 decision 7).
func TestServeStaticFiles_AFileEditedInPlaceMidReadIsAnsweredWithTheMetadataOfTheBytesRead(t *testing.T) {
	originalAt := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	editedAt := originalAt.Add(24 * time.Hour)
	edited := []byte("body { color: green; }")
	digest := sha256.Sum256(edited)
	fingerprint := hex.EncodeToString(digest[:6])
	last := len(edited) - 1

	for _, change := range []struct {
		name     string
		original []byte
	}{
		{name: "grown", original: []byte("body { color: blue; }")},
		{name: "shrunk", original: []byte("body { color: darkmagenta; }")},
	} {
		for _, tc := range []struct {
			name         string
			method       string
			header       http.Header
			status       int
			body         string
			length       int
			contentRange string
		}{
			{name: "GET", method: http.MethodGet, status: http.StatusOK, body: string(edited), length: len(edited)},
			{name: "HEAD", method: http.MethodHead, status: http.StatusOK, body: "", length: len(edited)},
			{
				name: "the last byte's range", method: http.MethodGet,
				header: http.Header{"Range": {fmt.Sprintf("bytes=%d-%d", last, last)}},
				status: http.StatusPartialContent, body: "}", length: 1,
				contentRange: fmt.Sprintf("bytes %d-%d/%d", last, last, len(edited)),
			},
			{
				name: "modified since the original's date", method: http.MethodGet,
				header: http.Header{"If-Modified-Since": {originalAt.Format(http.TimeFormat)}},
				status: http.StatusOK, body: string(edited), length: len(edited),
			},
		} {
			t.Run(change.name+", "+tc.name, func(t *testing.T) {
				s := newStaticBranchTestServer("http://unused.test", newTestSessionStoreOver(sessiontest.NewMemoryBackend()))
				s.staticFS = newEditedInPlaceFS(t, change.original, originalAt, [][]byte{edited}, editedAt)
				_ = s.initMiddleware()
				s.serveStaticFiles(http.NotFoundHandler())

				request := httptest.NewRequest(tc.method, "/static/probe.css?v="+fingerprint, nil)
				for name, values := range tc.header {
					request.Header[name] = values
				}
				rr := httptest.NewRecorder()
				s.router.ServeHTTP(rr, request)

				require.Equal(t, tc.status, rr.Code, rr.Body.String())
				assert.Equal(t, staticLongCache, rr.Header().Get("Cache-Control"))
				assert.Equal(t, tc.body, rr.Body.String())
				assert.Equal(t, strconv.Itoa(tc.length), rr.Header().Get("Content-Length"))
				assert.Equal(t, tc.contentRange, rr.Header().Get("Content-Range"))
				assert.Equal(t, editedAt.Format(http.TimeFormat), rr.Header().Get("Last-Modified"))
			})
		}
	}
}

// A static file still changing on every read is answered with the bytes of the last read, sized
// as they are, and with no modification date, so no conditional request is answered 304 on a date
// that does not describe them.
func TestServeStaticFiles_AFileChangingOnEveryReadIsAnsweredWithNoModificationDate(t *testing.T) {
	originalAt := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	edits := [][]byte{
		[]byte("body { color: green; }"),
		[]byte("body { color: red; }"),
		[]byte("body { color: orange; }"),
	}

	s := newStaticBranchTestServer("http://unused.test", newTestSessionStoreOver(sessiontest.NewMemoryBackend()))
	s.staticFS = newEditedInPlaceFS(t, []byte("body { color: blue; }"), originalAt, edits, originalAt.Add(24*time.Hour))
	_ = s.initMiddleware()
	s.serveStaticFiles(http.NotFoundHandler())

	request := httptest.NewRequest(http.MethodGet, "/static/probe.css?v=000000000000", nil)
	request.Header.Set("If-Modified-Since", originalAt.Add(48*time.Hour).Format(http.TimeFormat))
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, request)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "body { color: orange; }", rr.Body.String())
	assert.Equal(t, "23", rr.Header().Get("Content-Length"))
	assert.Empty(t, rr.Header().Get("Last-Modified"))
	assert.Equal(t, staticShortCache, rr.Header().Get("Cache-Control"))
}
