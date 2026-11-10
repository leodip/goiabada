package server

import (
	"bytes"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"
)

// staticSnapshot is a static file read once, over the static files it was read from: the bytes
// whose fingerprint decides the cache are the bytes the file server sends. Checking the
// fingerprint on one read and serving another would let an operator's replacement of a file in the
// static directory between the two go out under the old file's URL, kept for a year (#810
// decision 7). Every other name is opened from the static files as before.
type staticSnapshot struct {
	fs.FS
	name    string
	info    fs.FileInfo
	content []byte
}

// staticSnapshotReads is how many times a file found changing while it is read is read again
// before its bytes are served without a modification date.
const staticSnapshotReads = 3

// readStaticSnapshot reads the file urlPath names under /static, as http.FileServer names it, and
// reports false for a directory or a file that cannot be read, which the file server then answers
// as it always has.
//
// The file server sizes and dates the answer from the snapshot's metadata, so the metadata has to
// describe the bytes read: the size is always theirs, and the modification date is the file's only
// when the file did not change while it was read. A file edited in place mid-read is read again;
// one still changing after staticSnapshotReads reads is served with no modification date, so no
// conditional request is answered 304 on a date that does not describe the bytes.
func readStaticSnapshot(fsys fs.FS, urlPath string) (staticSnapshot, bool) {
	name := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(urlPath, staticPrefix)), "/")
	if !fs.ValidPath(name) || name == "." {
		return staticSnapshot{}, false
	}
	for read := 1; ; read++ {
		snapshot, unchanged, ok := readStaticFileOnce(fsys, name)
		if !ok {
			return staticSnapshot{}, false
		}
		if unchanged || read == staticSnapshotReads {
			return snapshot, true
		}
	}
}

// readStaticFileOnce reads the file once and reports whether it stayed unchanged while read: the
// same size and modification date before and after, the size being the bytes read.
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
	content, err := io.ReadAll(file)
	if err != nil {
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
	return staticSnapshot{FS: fsys, name: name, info: info, content: content}, unchanged, true
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
