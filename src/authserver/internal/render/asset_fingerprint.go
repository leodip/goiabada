package render

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"strings"
	"sync"
	"time"

	"github.com/leodip/goiabada/core/errs"
)

// assetFingerprints answers a static file's URL with a fingerprint of the file's contents after
// it, as the layouts' asset template function: /static/main.css?v=3f9a1c2b7d4e. The server lets a
// browser keep a static file for five minutes, so a page naming its stylesheet by path alone
// could arrive after an upgrade with the stylesheet of the release before it. Named by its
// contents, the URL changes exactly when the file does, and the new file is fetched at once
// (#617).
//
// The fingerprint is read from the file system the server serves, so a deployment serving its own
// static directory gets its own files' fingerprints. A file is hashed again only when its size or
// modification time changes, which the embedded files never do.
type assetFingerprints struct {
	fsys  fs.FS
	mu    sync.Mutex
	known map[string]assetFingerprint
}

type assetFingerprint struct {
	size    int64
	modTime time.Time
	sum     string
}

// NewAssetURLs answers static file URLs with their fingerprints over staticFS, as the layouts'
// asset function does, for the one page rendered outside a Renderer: the form_post page.
func NewAssetURLs(staticFS fs.FS) func(path string) (string, error) {
	return newAssetFingerprints(staticFS).url
}

func newAssetFingerprints(staticFS fs.FS) *assetFingerprints {
	return &assetFingerprints{fsys: staticFS, known: map[string]assetFingerprint{}}
}

// url returns path with its file's fingerprint. path names a file under /static/; anything else,
// or a file that is not there, is an error, which fails the page rather than linking it to nothing.
func (a *assetFingerprints) url(path string) (string, error) {
	name, ok := strings.CutPrefix(path, "/static/")
	if !ok || a.fsys == nil {
		return "", errs.Errorf("asset %q is not a static file this server serves", path)
	}
	info, err := fs.Stat(a.fsys, name)
	if err != nil {
		return "", errs.Wrapf(err, "unable to read static file %q", path)
	}

	a.mu.Lock()
	known, ok := a.known[name]
	a.mu.Unlock()
	if ok && known.size == info.Size() && known.modTime.Equal(info.ModTime()) {
		return path + "?v=" + known.sum, nil
	}

	content, err := fs.ReadFile(a.fsys, name)
	if err != nil {
		return "", errs.Wrapf(err, "unable to read static file %q", path)
	}
	digest := sha256.Sum256(content)
	sum := hex.EncodeToString(digest[:6])

	a.mu.Lock()
	a.known[name] = assetFingerprint{size: info.Size(), modTime: info.ModTime(), sum: sum}
	a.mu.Unlock()
	return path + "?v=" + sum, nil
}
