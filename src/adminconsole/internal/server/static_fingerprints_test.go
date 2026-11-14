package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newStaticFileTestServer serves fsys as the static files.
func newStaticFileTestServer(t *testing.T, fsys fs.FS) *Server {
	t.Helper()
	s := newStaticBranchTestServer("http://unused.test", newTestSessionStoreOver(sessiontest.NewMemoryBackend()))
	s.staticFS = fsys
	_ = s.initMiddleware()
	s.serveStaticFiles(http.NotFoundHandler())
	return s
}

// countingFS is a set of static files that counts the bytes read from them.
type countingFS struct {
	fs.FS
	read atomic.Int64
}

func (f *countingFS) Open(name string) (fs.File, error) {
	file, err := f.FS.Open(name)
	if err != nil {
		return nil, err
	}
	return &countingFile{File: file, fsys: f}, nil
}

type countingFile struct {
	fs.File
	fsys *countingFS
}

func (f *countingFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	f.fsys.read.Add(int64(n))
	return n, err
}

func (f *countingFile) Seek(offset int64, whence int) (int64, error) {
	return f.File.(io.Seeker).Seek(offset, whence)
}

// staticFingerprint is the fingerprint a page links content by: the first 12 hex digits of its
// SHA-256 (#810 decision 7).
func staticFingerprint(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:6])
}

func serveStaticRequest(s *Server, target string, header http.Header) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	for name, values := range header {
		request.Header[name] = values
	}
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, request)
	return rr
}

// A static file earns the year by its fingerprint whatever its size, for the whole file and for a
// range of it: no file is too large to fingerprint, as none is held in memory to be answered.
func TestServeStaticFiles_AFileOfAnySizeEarnsTheYearByItsFingerprint(t *testing.T) {
	large := bytes.Repeat([]byte("a"), 2<<20)
	s := newStaticFileTestServer(t, fstest.MapFS{"probe.css": {Data: large}})
	target := "/static/probe.css?v=" + staticFingerprint(large)

	whole := serveStaticRequest(s, target, nil)
	require.Equal(t, http.StatusOK, whole.Code)
	assert.True(t, bytes.Equal(large, whole.Body.Bytes()), "the whole file is answered")
	assert.Equal(t, strconv.Itoa(len(large)), whole.Header().Get("Content-Length"))
	assert.Equal(t, staticLongCache, whole.Header().Get("Cache-Control"))

	ranged := serveStaticRequest(s, target, http.Header{"Range": {"bytes=0-0"}})
	require.Equal(t, http.StatusPartialContent, ranged.Code)
	assert.Equal(t, "a", ranged.Body.String())
	assert.Equal(t, "bytes 0-0/"+strconv.Itoa(len(large)), ranged.Header().Get("Content-Range"))
	assert.Equal(t, staticLongCache, ranged.Header().Get("Cache-Control"))
}

// A file is read once for its fingerprint, which is kept, and every answer is read from the static
// files: three requests by the fingerprint read the file four times, never twice for one request.
func TestServeStaticFiles_AFileIsReadOnceForItsFingerprintAndOnceForEachAnswer(t *testing.T) {
	content := []byte("body { color: blue; }")
	fsys := &countingFS{FS: fstest.MapFS{"probe.css": {Data: content}}}
	s := newStaticFileTestServer(t, fsys)

	for range 3 {
		rr := serveStaticRequest(s, "/static/probe.css?v="+staticFingerprint(content), nil)
		require.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, string(content), rr.Body.String())
		assert.Equal(t, staticLongCache, rr.Header().Get("Cache-Control"))
	}
	assert.Equal(t, int64(4*len(content)), fsys.read.Load(), "one read for the fingerprint, one for each answer")
}

// Concurrent requests for one file share its kept fingerprint safely, each answered with the file
// and the year its fingerprint earns.
func TestServeStaticFiles_ConcurrentRequestsForAFileEachEarnTheYear(t *testing.T) {
	content := []byte("body { color: blue; }")
	s := newStaticFileTestServer(t, fstest.MapFS{"probe.css": {Data: content}})
	target := "/static/probe.css?v=" + staticFingerprint(content)

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			rr := serveStaticRequest(s, target, nil)
			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, string(content), rr.Body.String())
			assert.Equal(t, staticLongCache, rr.Header().Get("Cache-Control"))
		})
	}
	wg.Wait()
}
