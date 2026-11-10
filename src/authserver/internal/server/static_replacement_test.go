package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// replacedOnReadFS is a static directory whose one file an operator replaces the moment its
// contents have been read in full once: every open after that finds the new file.
type replacedOnReadFS struct {
	mu       sync.Mutex
	content  []byte
	replaced []byte
}

func (f *replacedOnReadFS) Open(name string) (fs.File, error) {
	f.mu.Lock()
	content := f.content
	f.mu.Unlock()
	file, err := fstest.MapFS{"probe.css": {Data: content}}.Open(name)
	if err != nil {
		return nil, err
	}
	return &replacedOnReadFile{File: file, fsys: f}, nil
}

type replacedOnReadFile struct {
	fs.File
	fsys *replacedOnReadFS
}

func (f *replacedOnReadFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	if errors.Is(err, io.EOF) {
		f.fsys.mu.Lock()
		f.fsys.content = f.fsys.replaced
		f.fsys.mu.Unlock()
	}
	return n, err
}

func (f *replacedOnReadFile) Seek(offset int64, whence int) (int64, error) {
	return f.File.(io.Seeker).Seek(offset, whence)
}

// A static file replaced while it is being answered never earns the year for bytes its URL does
// not name: the fingerprint is checked on the very bytes the answer carries (#810 decision 7). A
// URL holding a year what it does not name would hand a stale page, or a rollback reusing the
// URL, the replacement from cache.
func TestServeStaticFiles_AFileReplacedMidAnswerKeepsTheYearOnlyForTheBytesItNames(t *testing.T) {
	before := []byte("body { color: blue; }")
	after := []byte("body { color: green; }")
	digest := sha256.Sum256(before)
	fingerprint := hex.EncodeToString(digest[:6])

	for _, tc := range []struct {
		name   string
		method string
		header http.Header
		status int
		body   []byte
	}{
		{name: "GET", method: http.MethodGet, status: http.StatusOK, body: before},
		{name: "HEAD", method: http.MethodHead, status: http.StatusOK, body: nil},
		{name: "a range", method: http.MethodGet, header: http.Header{"Range": {"bytes=14-17"}}, status: http.StatusPartialContent, body: []byte("blue")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStaticBranchTestServer(datamocks.NewDatabase(t))
			s.staticFS = &replacedOnReadFS{content: before, replaced: after}
			_ = s.initMiddleware()
			s.serveStaticFiles()

			request := httptest.NewRequest(tc.method, "/static/probe.css?v="+fingerprint, nil)
			for name, values := range tc.header {
				request.Header[name] = values
			}
			rr := httptest.NewRecorder()
			s.router.ServeHTTP(rr, request)

			require.Equal(t, tc.status, rr.Code, rr.Body.String())
			assert.Equal(t, staticLongCache, rr.Header().Get("Cache-Control"))
			assert.True(t, bytes.Equal(tc.body, rr.Body.Bytes()), "the answer is the bytes the fingerprint names: %q", rr.Body.String())
			assert.Equal(t, "text/css; charset=utf-8", rr.Header().Get("Content-Type"))
			if tc.status == http.StatusOK {
				assert.Equal(t, strconv.Itoa(len(before)), rr.Header().Get("Content-Length"))
			}
		})
	}
}
