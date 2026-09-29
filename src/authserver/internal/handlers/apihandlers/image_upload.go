package apihandlers

import (
	"errors"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/imageupload"
)

// readUploadedImage reads the "picture" field for the three image upload endpoints and answers
// the request itself when it cannot: FILE_TOO_LARGE and NO_FILE for the two client failures, the
// 500 for anything else. ok is false once it has answered.
func readUploadedImage(w http.ResponseWriter, r *http.Request, maxUploadBytes int64) (data []byte, ok bool) {
	data, err := imageupload.Read(w, r, "picture", maxUploadBytes)
	switch {
	case err == nil:
		return data, true
	case errors.Is(err, imageupload.ErrUploadTooLarge):
		writeJSONError(w, "File too large or invalid form data", "FILE_TOO_LARGE", http.StatusBadRequest)
	case errors.Is(err, imageupload.ErrNoUpload):
		writeJSONError(w, "No picture file provided", "NO_FILE", http.StatusBadRequest)
	default:
		writeInternalServerError(w, r, err)
	}
	return nil, false
}
