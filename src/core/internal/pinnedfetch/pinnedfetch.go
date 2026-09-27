// Package pinnedfetch is the download the two reference-data generators share: a GET through an
// injectable doer, read under a ceiling, and a SHA-256 check against a digest pinned in the
// generator's source.
//
// The countries generator fetches its CSV at a pinned dataset commit and the timezones generator
// its tzdata tarball at a pinned release, and each refuses bytes whose digest is not the one it
// pins, so the same source always renders the same table and a changed upstream stops the run for a
// human to review. What differs between them -- the URL, the ceiling, the parsing -- stays in each
// generator; what is here is only what both do the same way. It lives under core/internal because
// nothing outside core has a reason to name it (#432).
package pinnedfetch

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/leodip/goiabada/core/boundedread"
	"github.com/leodip/goiabada/core/errs"
)

// Doer sends one request. A generator's main passes an *http.Client's Do, which carries the
// timeout; a test passes a fake, so no test reaches the network.
type Doer func(req *http.Request) (*http.Response, error)

// Get fetches url with userAgent through doer, refuses any status but 200, and reads the body
// through boundedread.Read under limit, so an oversized answer is refused rather than cut.
func Get(doer Doer, url, userAgent string, limit int64) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, errs.Wrapf(err, "build the request for %s", url)
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := doer(req)
	if err != nil {
		return nil, errs.Wrapf(err, "GET %s", url)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errs.Errorf("GET %s: unexpected status %d", url, resp.StatusCode)
	}
	return boundedread.Read(resp.Body, limit)
}

// CheckSHA256 returns the lower-case hex SHA-256 of body, and refuses body unless that digest is
// exactly pinned. The error names both digests, because updating a pin is: edit the release or
// commit, run, and paste the digest this error printed.
//
// The comparison is exact rather than case-folded: a pin is written in lower-case hex, as
// sha256sum prints it, and one in any other spelling is a typo worth failing on.
func CheckSHA256(body []byte, pinned string) (string, error) {
	sum := sha256.Sum256(body)
	got := hex.EncodeToString(sum[:])
	if got != pinned {
		return "", errs.Errorf("SHA-256 mismatch: pinned %s, received %s", pinned, got)
	}
	return got, nil
}
