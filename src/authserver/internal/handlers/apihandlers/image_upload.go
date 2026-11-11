package apihandlers

import (
	"errors"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/brandasset"
	"github.com/leodip/goiabada/authserver/internal/imageupload"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/i18n"
)

// readUploadedImage reads the "picture" field for the three image upload endpoints and answers
// the request itself when it cannot: FILE_TOO_LARGE and NO_FILE for the two client failures, in the
// request's language, the 500 for anything else. A body too large and one that is not a multipart
// form are one answer on these endpoints, as they have always been. ok is false once it has answered.
func readUploadedImage(w http.ResponseWriter, r *http.Request, maxUploadBytes int64) (data []byte, ok bool) {
	data, err := imageupload.Read(w, r, "picture", maxUploadBytes)
	switch {
	case err == nil:
		return data, true
	case errors.Is(err, imageupload.ErrUploadTooLarge), errors.Is(err, imageupload.ErrNotMultipart):
		writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeImageUploadTooLarge, nil), "FILE_TOO_LARGE", http.StatusBadRequest)
	case errors.Is(err, imageupload.ErrNoUpload):
		writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeImageUploadNoFile, nil), "NO_FILE", http.StatusBadRequest)
	default:
		writeInternalServerError(w, r, err)
	}
	return nil, false
}

// readUploadedBrandAsset reads the "file" field of a brand asset upload of kind, as readUploadedImage
// reads a picture: a brand asset may be a font, so the field and the NO_FILE sentence name a file. A
// body cut at the read's bound is refused with the kind's byte limit, as a file one byte over it is
// (#813 decision 3); FILE_TOO_LARGE is left for a body that is not a multipart form.
func readUploadedBrandAsset(w http.ResponseWriter, r *http.Request, kind record.BrandAssetKind) (data []byte, ok bool) {
	data, err := imageupload.Read(w, r, "file", brandasset.MaxBytes(kind))
	switch {
	case err == nil:
		return data, true
	case errors.Is(err, imageupload.ErrUploadTooLarge):
		writeValidationError(w, r, brandasset.TooLarge(kind))
	case errors.Is(err, imageupload.ErrNotMultipart):
		writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeImageUploadTooLarge, nil), "FILE_TOO_LARGE", http.StatusBadRequest)
	case errors.Is(err, imageupload.ErrNoUpload):
		writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeBrandAssetUploadNoFile, nil), "NO_FILE", http.StatusBadRequest)
	default:
		writeInternalServerError(w, r, err)
	}
	return nil, false
}
