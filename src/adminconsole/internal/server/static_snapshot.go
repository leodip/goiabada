package server

import (
	"bytes"
	"io"
	"io/fs"
	"path"
	"strings"
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

// readStaticSnapshot reads the file urlPath names under /static, as http.FileServer names it, and
// reports false for a directory or a file that cannot be read, which the file server then answers
// as it always has.
func readStaticSnapshot(fsys fs.FS, urlPath string) (staticSnapshot, bool) {
	name := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(urlPath, staticPrefix)), "/")
	if !fs.ValidPath(name) || name == "." {
		return staticSnapshot{}, false
	}
	file, err := fsys.Open(name)
	if err != nil {
		return staticSnapshot{}, false
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || info.IsDir() {
		return staticSnapshot{}, false
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return staticSnapshot{}, false
	}
	return staticSnapshot{FS: fsys, name: name, info: info, content: content}, true
}

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
