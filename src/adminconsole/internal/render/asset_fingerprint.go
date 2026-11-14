package render

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"strings"
	"sync"

	"github.com/leodip/goiabada/core/errs"
)

// assetFingerprints answers a static file's URL with a fingerprint of the file's contents after
// it, as the layouts' asset template function: /static/main.css?v=3f9a1c2b7d4e. The server lets a
// browser keep a static file for five minutes, so a page naming its stylesheet by path alone
// could arrive after an upgrade with the stylesheet of the release before it. Named by its
// contents, the URL changes exactly when the file does, and the new file is fetched at once
// (#617).
//
// A file is read for its fingerprint the first time a page links it, and the fingerprint is kept:
// the built-in files cannot change while the server runs.
type assetFingerprints struct {
	fsys  fs.FS
	mu    sync.Mutex
	known map[string]string
}

func newAssetFingerprints(staticFS fs.FS) *assetFingerprints {
	return &assetFingerprints{fsys: staticFS, known: map[string]string{}}
}

// AssetFingerprint is the fingerprint a page links a static file with these contents by, for the
// static file server: a URL whose fingerprint is that of the bytes it answers with may be kept for
// a year, since the URL changes whenever the file does (#810 decision 7).
func AssetFingerprint(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:6])
}

// url returns path with its file's fingerprint. path names a file under /static/; anything else,
// or a file that is not there, is an error, which fails the page rather than linking it to nothing.
func (a *assetFingerprints) url(path string) (string, error) {
	sum, err := a.fingerprint(path)
	if err != nil {
		return "", err
	}
	return path + "?v=" + sum, nil
}

// fingerprint returns the fingerprint of the file at path, under /static/, as url does.
func (a *assetFingerprints) fingerprint(path string) (string, error) {
	name, ok := strings.CutPrefix(path, "/static/")
	if !ok || a.fsys == nil {
		return "", errs.Errorf("asset %q is not a static file this server serves", path)
	}
	// The lock is held through the read, so a page that links a file while it is first read waits
	// for its fingerprint instead of reading the file again.
	a.mu.Lock()
	defer a.mu.Unlock()
	if sum, ok := a.known[name]; ok {
		return sum, nil
	}

	content, err := fs.ReadFile(a.fsys, name)
	if err != nil {
		return "", errs.Wrapf(err, "unable to read static file %q", path)
	}
	sum := AssetFingerprint(content)
	a.known[name] = sum
	return sum, nil
}
