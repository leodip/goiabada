// Package imageupload is the one way the auth server takes an image from a request: Read bounds and
// reads the multipart upload, and Validate decides whether the bytes are an image this server
// stores, answering a refusal in the error-code vocabulary every other admin and account API
// validator uses. The profile picture and client logo endpoints are its three callers (#435).
package imageupload

import (
	"bytes"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"net/http"

	"github.com/leodip/goiabada/core/i18n"

	_ "golang.org/x/image/webp"
)

const (
	MaxDimension = 512 // 512x512 max
	MinDimension = 10  // 10x10 min
)

// allowedContentTypes is what http.DetectContentType must answer for an image to be stored, each a
// type a decoder is registered for above. Unexported so no caller can widen it at runtime.
var allowedContentTypes = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/gif":  true,
	"image/webp": true,
}

// Info is what Validate learned about an accepted image.
type Info struct {
	ContentType string
	Width       int
	Height      int
}

// Validate accepts an image of at most maxSize bytes, of an allowed type, that decodes, with each
// side between MinDimension and MaxDimension pixels. maxSize is the configured size, which config
// holds positive. A refusal is an *i18n.LocalizedError naming the first check that failed; the
// decoder's own text is not carried, because it is Go's wording about the bytes and not something
// the caller can act on beyond "this is not a readable image".
func Validate(data []byte, maxSize int64) (Info, error) {
	if int64(len(data)) > maxSize {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageTooLarge, map[string]any{"max": maxSize})
	}

	if len(data) == 0 {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageEmpty, nil)
	}

	// Detect content type from magic bytes
	contentType := http.DetectContentType(data)
	if !allowedContentTypes[contentType] {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageUnsupportedType, nil)
	}

	img, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageUndecodable, nil)
	}

	if img.Width < MinDimension || img.Height < MinDimension {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageDimensionsTooSmall, map[string]any{"min": MinDimension})
	}

	if img.Width > MaxDimension || img.Height > MaxDimension {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageDimensionsTooLarge, map[string]any{"max": MaxDimension})
	}

	return Info{
		ContentType: contentType,
		Width:       img.Width,
		Height:      img.Height,
	}, nil
}
