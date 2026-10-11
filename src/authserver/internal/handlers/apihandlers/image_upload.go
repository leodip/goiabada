package apihandlers

import (
	"errors"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/imageupload"
	"github.com/leodip/goiabada/core/i18n"
)

// readUploadedImage reads the "picture" field for the three image upload endpoints and answers
// the request itself when it cannot: FILE_TOO_LARGE and NO_FILE for the two client failures, in the
// request's language, the 500 for anything else. ok is false once it has answered.
func readUploadedImage(w http.ResponseWriter, r *http.Request, maxUploadBytes int64) (data []byte, ok bool) {
	data, err := imageupload.Read(w, r, "picture", maxUploadBytes)
	switch {
	case err == nil:
		return data, true
	case errors.Is(err, imageupload.ErrUploadTooLarge):
		writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeImageUploadTooLarge, nil), "FILE_TOO_LARGE", http.StatusBadRequest)
	case errors.Is(err, imageupload.ErrNoUpload):
		writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeImageUploadNoFile, nil), "NO_FILE", http.StatusBadRequest)
	default:
		writeInternalServerError(w, r, err)
	}
	return nil, false
}
