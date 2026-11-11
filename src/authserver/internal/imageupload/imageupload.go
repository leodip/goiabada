// Package imageupload is the one way the auth server takes an image from a request: Read bounds and
// reads the multipart upload, and Validate decides whether the bytes are an image the rules of its
// kind allow, answering a refusal in the error-code vocabulary every other admin and account API
// validator uses. The profile picture and client logo endpoints are its first three callers (#435);
// a brand's logo, favicon and background uploads are held to their own kinds' rules (#813 decision 3).
package imageupload

import (
	"bytes"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"net/http"

	"github.com/leodip/goiabada/core/brandkit"
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

// brandImageTypes is what a brand's logo and background may be: no GIF, which is made to animate,
// and no SVG, which http.DetectContentType does not answer as an image (#813 decision 3).
var brandImageTypes = map[string]bool{
	"image/png":  true,
	"image/jpeg": true,
	"image/webp": true,
}

// faviconTypes is what a brand's favicon may be: a PNG, which every browser draws as a tab icon.
var faviconTypes = map[string]bool{
	"image/png": true,
}

// Rules is what an upload of one kind is held to: the content types it may be and the refusal that
// names them, the pixel bounds each side must fall within, whether it must be square or still, and
// the most bytes it may hold. Its fields are unexported, so a caller takes a kind's rules from this
// package and cannot widen them at runtime.
type Rules struct {
	contentTypes map[string]bool
	typeRefusal  string
	minSide      int
	maxSide      int
	square       bool
	still        bool
	maxBytes     int64
}

// userImage is the rules a profile picture and a client logo share: a still JPEG, PNG, GIF or
// WebP, each side from 10 to 512 pixels, at most the configured size, which config holds positive.
// Still, because a client's logo is drawn beside the sign-in form, where a looping animation has
// no pause control, and a profile picture is held to the same rule (#840's follow-up).
func userImage(maxBytes int64) Rules {
	return Rules{contentTypes: userImageTypes, typeRefusal: i18n.ErrCodeImageUnsupportedType,
		minSide: 10, maxSide: 512, still: true, maxBytes: maxBytes}
}

// The byte limits of a brand's image kinds, fixed so the admin API behaves alike on every
// deployment (#813 decision 3). They are brandkit's, which the admin console's request-body table
// sizes its upload routes from.
const (
	BrandLogoMaxBytes       = brandkit.LogoMaxBytes
	BrandFaviconMaxBytes    = brandkit.FaviconMaxBytes
	BrandBackgroundMaxBytes = brandkit.BackgroundMaxBytes
)

// BrandLogo is the rules a brand's logo and dark logo are held to: a still PNG, JPEG or WebP, each
// side from 10 to 512 pixels, up to 1 MiB.
func BrandLogo() Rules {
	return Rules{contentTypes: brandImageTypes, typeRefusal: i18n.ErrCodeImageUnsupportedTypePngJpegWebp,
		minSide: 10, maxSide: 512, still: true, maxBytes: BrandLogoMaxBytes}
}

// BrandFavicon is the rules a brand's favicon is held to: a still, square PNG from 48 to 512 pixels
// a side, up to 1 MiB.
func BrandFavicon() Rules {
	return Rules{contentTypes: faviconTypes, typeRefusal: i18n.ErrCodeImageUnsupportedTypePng,
		minSide: 48, maxSide: 512, square: true, still: true, maxBytes: BrandFaviconMaxBytes}
}

// BrandBackground is the rules the image behind a brand's card is held to: a still PNG, JPEG or
// WebP, each side from 10 to 3840 pixels, up to 2 MiB.
func BrandBackground() Rules {
	return Rules{contentTypes: brandImageTypes, typeRefusal: i18n.ErrCodeImageUnsupportedTypePngJpegWebp,
		minSide: 10, maxSide: 3840, still: true, maxBytes: BrandBackgroundMaxBytes}
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
// types, that decodes, still where they ask for a still image, with each side within their pixel
// bounds, and square where they ask for a square. A refusal is an *i18n.LocalizedError naming the
// first check that failed; the decoder's own text is not carried, because it is Go's wording about
// the bytes and not something the caller can act on beyond "this is not a readable image".
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
		return Info{}, i18n.NewLocalizedError(rules.typeRefusal, nil)
	}

	img, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageUndecodable, nil)
	}

	if rules.still && animated(contentType, data) {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageAnimated, nil)
	}

	if img.Width < rules.minSide || img.Height < rules.minSide {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageDimensionsTooSmall, map[string]any{"min": rules.minSide})
	}

	if img.Width > rules.maxSide || img.Height > rules.maxSide {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageDimensionsTooLarge, map[string]any{"max": rules.maxSide})
	}

	if rules.square && img.Width != img.Height {
		return Info{}, i18n.NewLocalizedError(i18n.ErrCodeImageNotSquare,
			map[string]any{"width": img.Width, "height": img.Height})
	}

	return Info{
		ContentType: contentType,
		Width:       img.Width,
		Height:      img.Height,
	}, nil
}
