package mocks

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path"
	"time"
)

type TestFS struct {
	FileContents map[string]string
}

func (fs *TestFS) Open(name string) (fs.File, error) {
	content, ok := fs.FileContents[name]
	if !ok {
		return nil, &os.PathError{Op: "open", Path: name, Err: errors.New("file does not exist")}
	}
	return &TestFile{
		Reader: bytes.NewReader([]byte(content)),
		name:   path.Base(name),
	}, nil
}

type TestFile struct {
	*bytes.Reader
	name string
}

func (f *TestFile) Close() error {
	return nil
}

func (f *TestFile) Stat() (fs.FileInfo, error) {
	return &TestFileInfo{
		name: f.name,
		size: int64(f.Reader.Len()),
	}, nil
}

func (f *TestFile) Read(b []byte) (int, error) {
	return f.Reader.Read(b)
}

type TestFileInfo struct {
	name string
	size int64
}

func (fi *TestFileInfo) Name() string       { return fi.name }
func (fi *TestFileInfo) Size() int64        { return fi.size }
func (fi *TestFileInfo) Mode() fs.FileMode  { return 0444 }
func (fi *TestFileInfo) ModTime() time.Time { return time.Time{} }
func (fi *TestFileInfo) IsDir() bool        { return false }
func (fi *TestFileInfo) Sys() interface{}   { return nil }
