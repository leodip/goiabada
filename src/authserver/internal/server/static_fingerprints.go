package server

import (
	"io/fs"
	"path"
	"strings"
	"sync"

	"github.com/leodip/goiabada/authserver/internal/render"
)

// staticFingerprints are the static files' fingerprints, each computed the first time a request
// names its file by one and kept: the built-in files cannot change while the server runs, so a
// file's fingerprint is read once and the file is answered from the static files as any other
// request is. Only a file that was read is kept, under the one name the built-in files have for
// it, so there are never more than the files.
type staticFingerprints struct {
	fsys  fs.FS
	mu    sync.Mutex
	known map[string]string
}

func newStaticFingerprints(fsys fs.FS) *staticFingerprints {
	return &staticFingerprints{fsys: fsys, known: map[string]string{}}
}

// fingerprint returns the fingerprint of the file urlPath names under /static, as http.FileServer
// names it, and reports false for a name that is not a file that can be read, which the file
// server then answers as it always has.
func (s *staticFingerprints) fingerprint(urlPath string) (string, bool) {
	name := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(urlPath, staticPrefix)), "/")
	if !fs.ValidPath(name) || name == "." {
		return "", false
	}
	s.mu.Lock()
	sum, ok := s.known[name]
	s.mu.Unlock()
	if ok {
		return sum, true
	}
	content, err := fs.ReadFile(s.fsys, name)
	if err != nil {
		return "", false
	}
	sum = render.AssetFingerprint(content)
	s.mu.Lock()
	s.known[name] = sum
	s.mu.Unlock()
	return sum, true
}
