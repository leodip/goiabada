package server

import (
	"bytes"
	"io"
	"io/fs"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/leodip/goiabada/authserver/internal/render"
)

// staticSnapshot is a static file read once, over the static files it was read from: the bytes
// whose fingerprint decides the cache are the bytes the file server sends. Checking the
// fingerprint on one read and serving another would let an operator's replacement of a file in the
// static directory between the two go out under the old file's URL, kept for a year (#810
// decision 7). Every other name is opened from the static files as before.
type staticSnapshot struct {
	fs.FS
	name        string
	info        fs.FileInfo
	content     []byte
	fingerprint string
}

// staticSnapshotReads is how many times a file found changing while it is read is read again
// before its bytes are served without a modification date.
const staticSnapshotReads = 3

// staticSnapshotLimit is the largest file read whole for a snapshot. A larger one is streamed
// from the static files as any other request is, kept five minutes: reading it whole would let
// anyone make the server hold the whole file in memory with a one-byte range request.
const staticSnapshotLimit = 1 << 20

// staticSnapshotsBudget is the most the kept snapshots hold together, each costing the buffer its
// bytes are in, its name and staticSnapshotOverhead. Keeping one that would pass it empties the snapshots first: the
// names are the requests' spellings, and on a case-insensitive file system or through a directory
// symlink many spellings reach one file, each kept apart. They can make the server read the file
// again, but never hold more than the budget.
const staticSnapshotsBudget = 32 << 20

// staticSnapshotOverhead is what a kept snapshot costs beyond its bytes and its name, its entry and
// metadata, rounded up.
const staticSnapshotOverhead = 1 << 10

// staticSnapshots are the snapshots of the static files, each kept while its file's size and
// modification date stay the same, so a request for an unchanged file costs a stat and no read.
// Each file is at most staticSnapshotLimit, and all of them together at most staticSnapshotsBudget.
type staticSnapshots struct {
	fsys  fs.FS
	mu    sync.Mutex
	files map[string]staticSnapshot
	cost  int64 // the kept snapshots' costs together, as staticSnapshotCost counts them
}

func newStaticSnapshots(fsys fs.FS) *staticSnapshots {
	return &staticSnapshots{fsys: fsys, files: map[string]staticSnapshot{}}
}

// read returns the snapshot of the file urlPath names under /static, as http.FileServer names it,
// and reports false for a directory, a file over staticSnapshotLimit or a file that cannot be
// read, which the file server then answers as it always has.
//
// The file server sizes and dates the answer from the snapshot's metadata, so the metadata has to
// describe the bytes read: the size is always theirs, and the modification date is the file's only
// when the file did not change while it was read. A file edited in place mid-read is read again;
// one still changing after staticSnapshotReads reads is served with no modification date, so no
// conditional request is answered 304 on a date that does not describe the bytes, and is not kept.
func (s *staticSnapshots) read(urlPath string) (staticSnapshot, bool) {
	name := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(urlPath, staticPrefix)), "/")
	if !fs.ValidPath(name) || name == "." {
		return staticSnapshot{}, false
	}
	info, err := fs.Stat(s.fsys, name)
	if err != nil || info.IsDir() || info.Size() > staticSnapshotLimit {
		s.mu.Lock()
		s.forgetLocked(name)
		s.mu.Unlock()
		return staticSnapshot{}, false
	}
	s.mu.Lock()
	kept, ok := s.files[name]
	s.mu.Unlock()
	if ok && kept.info.Size() == info.Size() && kept.info.ModTime().Equal(info.ModTime()) {
		return kept, true
	}
	for read := 1; ; read++ {
		snapshot, unchanged, ok := readStaticFileOnce(s.fsys, name)
		if !ok {
			return staticSnapshot{}, false
		}
		if unchanged {
			s.keep(name, snapshot)
			return snapshot, true
		}
		if read == staticSnapshotReads {
			return snapshot, true
		}
	}
}

// keep keeps the snapshot under name, in place of any kept before, emptying the snapshots first
// when it would take them past staticSnapshotsBudget.
func (s *staticSnapshots) keep(name string, snapshot staticSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forgetLocked(name)
	cost := staticSnapshotCost(name, snapshot)
	if s.cost+cost > staticSnapshotsBudget {
		// A new map, not clear: a cleared map keeps the storage its entries took, outside the budget.
		s.files = map[string]staticSnapshot{}
		s.cost = 0
	}
	s.files[name] = snapshot
	s.cost += cost
}

// forgetLocked drops the snapshot kept under name, if any. s.mu is held.
func (s *staticSnapshots) forgetLocked(name string) {
	if kept, ok := s.files[name]; ok {
		s.cost -= staticSnapshotCost(name, kept)
		delete(s.files, name)
	}
}

// staticSnapshotCost is what the snapshot kept under name costs the budget: the whole buffer its
// bytes are in, which io.ReadAll can leave with room to spare, its name and the overhead.
func staticSnapshotCost(name string, snapshot staticSnapshot) int64 {
	return int64(len(name)+cap(snapshot.content)) + staticSnapshotOverhead
}

// readStaticFileOnce reads the file once and reports whether it stayed unchanged while read: the
// same size and modification date before and after, the size being the bytes read. A file that
// grows past staticSnapshotLimit while it is read is not read further, and reports false.
func readStaticFileOnce(fsys fs.FS, name string) (snapshot staticSnapshot, unchanged, ok bool) {
	file, err := fsys.Open(name)
	if err != nil {
		return staticSnapshot{}, false, false
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil || before.IsDir() {
		return staticSnapshot{}, false, false
	}
	content, err := io.ReadAll(io.LimitReader(file, staticSnapshotLimit+1))
	if err != nil || len(content) > staticSnapshotLimit {
		return staticSnapshot{}, false, false
	}
	after, err := file.Stat()
	if err != nil {
		return staticSnapshot{}, false, false
	}
	unchanged = before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()) &&
		after.Size() == int64(len(content))
	info := snapshotInfo{FileInfo: after, size: int64(len(content))}
	if unchanged {
		info.modTime = after.ModTime()
	}
	return staticSnapshot{
		FS: fsys, name: name, info: info, content: content, fingerprint: render.AssetFingerprint(content),
	}, unchanged, true
}

// snapshotInfo is the file's metadata as the snapshot's bytes have it: their size, and the file's
// modification date only when it describes them, the zero time otherwise.
type snapshotInfo struct {
	fs.FileInfo
	size    int64
	modTime time.Time
}

func (i snapshotInfo) Size() int64 { return i.size }

func (i snapshotInfo) ModTime() time.Time { return i.modTime }

// Open answers the snapshot's own name with the bytes read, and any other from the static files.
func (s staticSnapshot) Open(name string) (fs.File, error) {
	if name != s.name {
		return s.FS.Open(name)
	}
	return &snapshotFile{Reader: bytes.NewReader(s.content), info: s.info}, nil
}

// snapshotFile is the snapshot's bytes as a file, seekable as http.FileServer needs for ranges.
type snapshotFile struct {
	*bytes.Reader
	info fs.FileInfo
}

func (f *snapshotFile) Stat() (fs.FileInfo, error) { return f.info, nil }

func (f *snapshotFile) Close() error { return nil }
