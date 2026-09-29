package imageupload

import (
	"errors"
	"io"
	"net/http"

	"github.com/leodip/goiabada/core/errs"
)

// multipartOverhead is what Read admits above the image itself for the boundaries and part headers
// around it. The server's request-body table allows 64 KiB there, wider on purpose, so this bound
// is the one that answers and the caller gets ErrUploadTooLarge rather than a cut body (#426).
const multipartOverhead = 1024

var (
	// ErrUploadTooLarge is a body over the bound, or one that is not a multipart form: the two
	// are one answer on the wire, as they were before Read held the sequence.
	ErrUploadTooLarge = errors.New("upload too large or not a multipart form")

	// ErrNoUpload is a multipart form without the named file field.
	ErrNoUpload = errors.New("no file in the upload")
)

// Read takes the file in field from a multipart request of at most maxSize bytes of image plus the
// multipart overhead. It answers ErrUploadTooLarge or ErrNoUpload for the two failures the client
// caused, and a wrapped error for a read that failed on the server's side, which the caller
// answers as a 500. The bytes are not validated; Validate does that.
func Read(w http.ResponseWriter, r *http.Request, field string, maxSize int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSize+multipartOverhead)

	//nolint:gosec // G120: bounded by the MaxBytesReader above and the server's request-body table; G120 flags every multipart parse
	if err := r.ParseMultipartForm(maxSize); err != nil {
		return nil, ErrUploadTooLarge
	}

	file, _, err := r.FormFile(field)
	if err != nil {
		return nil, ErrNoUpload
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the uploaded file")
	}
	return data, nil
}
