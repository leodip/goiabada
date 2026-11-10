package server

import (
	"bytes"
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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newStaticSnapshotTestServer serves fsys as the static files.
func newStaticSnapshotTestServer(t *testing.T, fsys fs.FS) *Server {
	t.Helper()
	s := newStaticBranchTestServer(datamocks.NewDatabase(t))
	s.staticFS = fsys
	_ = s.initMiddleware()
	s.serveStaticFiles()
	return s
}

// countingFS is a real static directory that counts the bytes read from its files.
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

// newCountingFS writes content to a temporary probe.css and returns the directory, counting the
// bytes read from it, and the file's path.
func newCountingFS(t *testing.T, content []byte) (*countingFS, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.css")
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return &countingFS{FS: os.DirFS(dir)}, path
}

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

// A file over the snapshot limit is streamed from the static files, never read whole, and kept
// five minutes even by its current fingerprint: a one-byte range request costs one byte, where
// reading the file whole for each request let anyone make the server hold it in memory (#810).
// A file of exactly the limit still earns the year.
func TestServeStaticFiles_AFileOverTheSnapshotLimitIsStreamedAndKeptFiveMinutes(t *testing.T) {
	over := bytes.Repeat([]byte("a"), staticSnapshotLimit+1)
	fsys, _ := newCountingFS(t, over)
	s := newStaticSnapshotTestServer(t, fsys)
	target := "/static/probe.css?v=" + staticFingerprint(over)

	ranged := serveStaticRequest(s, target, http.Header{"Range": {"bytes=0-0"}})
	require.Equal(t, http.StatusPartialContent, ranged.Code)
	assert.Equal(t, "a", ranged.Body.String())
	assert.Equal(t, "bytes 0-0/"+strconv.Itoa(len(over)), ranged.Header().Get("Content-Range"))
	assert.Equal(t, staticShortCache, ranged.Header().Get("Cache-Control"))
	assert.Less(t, fsys.read.Load(), int64(staticSnapshotLimit), "a range of an oversized file reads only the range")

	whole := serveStaticRequest(s, target, nil)
	require.Equal(t, http.StatusOK, whole.Code)
	assert.True(t, bytes.Equal(over, whole.Body.Bytes()), "the whole file is streamed")
	assert.Equal(t, staticShortCache, whole.Header().Get("Cache-Control"))

	limit := bytes.Repeat([]byte("b"), staticSnapshotLimit)
	limitFS, _ := newCountingFS(t, limit)
	rr := serveStaticRequest(newStaticSnapshotTestServer(t, limitFS), "/static/probe.css?v="+staticFingerprint(limit), nil)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, staticLongCache, rr.Header().Get("Cache-Control"))
}

// A file that grows past the snapshot limit while it is read is not read further: the snapshot's
// read stops a byte past the limit, and the file is streamed as an oversized file is, kept five
// minutes even by the fingerprint of what it grew to.
func TestServeStaticFiles_AFileGrowingPastTheSnapshotLimitWhileReadIsStreamed(t *testing.T) {
	originalAt := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	grown := bytes.Repeat([]byte("a"), 4*staticSnapshotLimit)
	fsys := &countingFS{FS: newEditedInPlaceFS(t, []byte("body { color: blue; }"), originalAt,
		[][]byte{grown}, originalAt.Add(24*time.Hour))}
	s := newStaticSnapshotTestServer(t, fsys)
	target := "/static/probe.css?v=" + staticFingerprint(grown)

	ranged := serveStaticRequest(s, target, http.Header{"Range": {"bytes=0-0"}})
	require.Equal(t, http.StatusPartialContent, ranged.Code)
	assert.Equal(t, "a", ranged.Body.String())
	assert.Equal(t, staticShortCache, ranged.Header().Get("Cache-Control"))
	assert.Less(t, fsys.read.Load(), int64(2*staticSnapshotLimit), "the snapshot's read stops past the limit")

	whole := serveStaticRequest(s, target, nil)
	require.Equal(t, http.StatusOK, whole.Code)
	assert.True(t, bytes.Equal(grown, whole.Body.Bytes()), "the grown file is streamed whole")
	assert.Equal(t, staticShortCache, whole.Header().Get("Cache-Control"))
}

// A file is read once for every request naming it while its size and modification date stay the
// same, and read again when they change, the new bytes then earning the year by their own
// fingerprint and the old fingerprint five minutes.
func TestServeStaticFiles_AnUnchangedFileIsReadOnceAcrossRequests(t *testing.T) {
	before := []byte("body { color: blue; }")
	after := []byte("body { color: green; }")
	fsys, path := newCountingFS(t, before)
	s := newStaticSnapshotTestServer(t, fsys)

	for range 3 {
		rr := serveStaticRequest(s, "/static/probe.css?v="+staticFingerprint(before), nil)
		require.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, string(before), rr.Body.String())
		assert.Equal(t, staticLongCache, rr.Header().Get("Cache-Control"))
	}
	assert.Equal(t, int64(len(before)), fsys.read.Load(), "three requests read the file once")

	require.NoError(t, os.WriteFile(path, after, 0o600))
	changedAt := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, os.Chtimes(path, changedAt, changedAt))

	current := serveStaticRequest(s, "/static/probe.css?v="+staticFingerprint(after), nil)
	require.Equal(t, http.StatusOK, current.Code)
	assert.Equal(t, string(after), current.Body.String())
	assert.Equal(t, staticLongCache, current.Header().Get("Cache-Control"))

	stale := serveStaticRequest(s, "/static/probe.css?v="+staticFingerprint(before), nil)
	require.Equal(t, http.StatusOK, stale.Code)
	assert.Equal(t, string(after), stale.Body.String())
	assert.Equal(t, staticShortCache, stale.Header().Get("Cache-Control"))
	assert.Equal(t, int64(len(before)+len(after)), fsys.read.Load(), "the changed file is read once more")
}

// Concurrent requests for one file share the snapshots safely, each answered with the file and
// the year its fingerprint earns.
func TestServeStaticFiles_ConcurrentRequestsForAFileEachEarnTheYear(t *testing.T) {
	content := []byte("body { color: blue; }")
	fsys, _ := newCountingFS(t, content)
	s := newStaticSnapshotTestServer(t, fsys)
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

// Spellings that reach one file are kept apart, here through directory symlinks as on a
// case-insensitive file system, so requests could multiply one file's snapshot. The snapshots
// together, each buffer counted whole, never pass the budget however many spellings are asked for.
// The file's size is one io.ReadAll leaves more room to spare after than the overhead allows for.
func TestStaticSnapshots_ManySpellingsOfOneFileNeverPassTheBudget(t *testing.T) {
	content := bytes.Repeat([]byte("a"), 837000)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "probe.css"), content, 0o600))
	require.NoError(t, os.Symlink(".", filepath.Join(dir, "a")))
	require.NoError(t, os.Symlink(".", filepath.Join(dir, "b")))
	snapshots := newStaticSnapshots(os.DirFS(dir))

	// a/a/a/a/a/a/a/a/probe.css, a/a/a/a/a/a/a/b/probe.css and on: eight symlinks deep at most, as a
	// lookup follows forty.
	steps := strings.NewReplacer("0", "a/", "1", "b/")
	for spelling := range 2 * staticSnapshotsBudget / staticSnapshotLimit {
		name := steps.Replace(fmt.Sprintf("%08b", spelling)) + "probe.css"
		snapshot, ok := snapshots.read("/static/" + name)
		require.True(t, ok, name)
		require.Equal(t, staticFingerprint(content), snapshot.fingerprint)

		kept := 0
		for keptName, keptSnapshot := range snapshots.files {
			kept += len(keptName) + cap(keptSnapshot.content)
		}
		require.LessOrEqual(t, kept, staticSnapshotsBudget, "the snapshots kept after %d spellings", spelling+1)
	}
}
