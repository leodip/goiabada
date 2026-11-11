// Package imageupload is the one way the auth server takes an image from a request: Read bounds and
// reads the multipart upload, and Validate decides whether the bytes are an image the rules of its
// kind allow, answering a refusal in the error-code vocabulary every other admin and account API
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

// userImageTypes is what http.DetectContentType must answer for a profile picture or a client logo
// to be stored, each a type a decoder is registered for above.
var userImageTypes = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/gif":  true,
	"image/webp": true,
}

// Rules is what an upload of one kind is held to: the content types it may be, the pixel bounds
// each side must fall within, and the most bytes it may hold. Its fields are unexported, so a
// caller takes a kind's rules from this package and cannot widen them at runtime.
type Rules struct {
	contentTypes map[string]bool
	minSide      int
	maxSide      int
	maxBytes     int64
}

// userImage is the rules a profile picture and a client logo share: JPEG, PNG, GIF or WebP, each
// side from 10 to 512 pixels, at most the configured size, which config holds positive.
func userImage(maxBytes int64) Rules {
	return Rules{contentTypes: userImageTypes, minSide: 10, maxSide: 512, maxBytes: maxBytes}
}

// ProfilePicture is the rules a profile picture is held to, maxBytes being the configured size.
func ProfilePicture(maxBytes int64) Rules { return userImage(maxBytes) }

// ClientLogo is the rules a client logo is held to, maxBytes being the configured size.
func ClientLogo(maxBytes int64) Rules { return userImage(maxBytes) }

// MaxBytes is the most bytes an upload of this kind may hold, which bounds the read of its body.
func (r Rules) MaxBytes() int64 { return r.maxBytes }

// Info is what Validate learned about an accepted image.
type Info struct {
	ContentType string
	Width       int
	Height      int
}

// Validate accepts an image its kind's rules allow: at most their byte limit, of one of their
// types, that decodes, with each side within their pixel bounds. A refusal is an
// *i18n.LocalizedError naming the first check that failed; the decoder's own text is not carried,
// because it is Go's wording about the bytes and not something the caller can act on beyond "this
// is not a readable image".
func Validate(data []byte, rules Rules) (Info, error) {
	if int64(len(data)) > rules.maxBytes {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageTooLarge, map[string]any{"max": rules.maxBytes})
	}

	if len(data) == 0 {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageEmpty, nil)
	}

	// Detect content type from magic bytes
	contentType := http.DetectContentType(data)
	if !rules.contentTypes[contentType] {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageUnsupportedType, nil)
	}

	img, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageUndecodable, nil)
	}

	if img.Width < rules.minSide || img.Height < rules.minSide {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageDimensionsTooSmall, map[string]any{"min": rules.minSide})
	}

	if img.Width > rules.maxSide || img.Height > rules.maxSide {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageDimensionsTooLarge, map[string]any{"max": rules.maxSide})
	}

	return Info{
		ContentType: contentType,
		Width:       img.Width,
		Height:      img.Height,
	}, nil
}
