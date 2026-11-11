package imageupload

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestPNG creates a valid PNG image with the specified dimensions
func createTestPNG(width, height int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	// Fill with a solid color
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 100, G: 150, B: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// createTestJPEG creates a valid JPEG image with the specified dimensions
func createTestJPEG(width, height int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	// Fill with a solid color
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 100, G: 150, B: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	_ = jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90})
	return buf.Bytes()
}

// createTestGIF creates a valid GIF image with the specified dimensions
func createTestGIF(width, height int) []byte {
	img := image.NewPaletted(image.Rect(0, 0, width, height), color.Palette{
		color.RGBA{R: 100, G: 150, B: 200, A: 255},
		color.RGBA{R: 255, G: 255, B: 255, A: 255},
	})
	var buf bytes.Buffer
	_ = gif.Encode(&buf, img, nil)
	return buf.Bytes()
}

// webpOfSize is the head of a WebP file in the extended format: a VP8X chunk naming a canvas of
// width by height pixels, which is as far as a decoder reads to answer the size.
func webpOfSize(width, height int) []byte {
	vp8x := []byte{
		0, 0, 0, 0,
		byte(width - 1), byte((width - 1) >> 8), byte((width - 1) >> 16),
		byte(height - 1), byte((height - 1) >> 8), byte((height - 1) >> 16),
	}
	body := append([]byte("WEBPVP8X\x0a\x00\x00\x00"), vp8x...)
	size := len(body)
	riff := append([]byte("RIFF"), byte(size), byte(size>>8), byte(size>>16), byte(size>>24))
	return append(riff, body...)
}

// testMaxSize is a configured size well above every image built here.
const testMaxSize = int64(3 << 20)

// configuredKinds are the two kinds whose byte limit is the configured size, each held to the same
// rules: JPEG, PNG, GIF or WebP, each side from 10 to 512 pixels.
var configuredKinds = []struct {
	name  string
	rules func(maxBytes int64) Rules
}{
	{"profile picture", ProfilePicture},
	{"client logo", ClientLogo},
}

func TestValidate_Accepts(t *testing.T) {
	square := createTestPNG(100, 100)

	tests := []struct {
		name        string
		data        []byte
		maxSize     int64
		contentType string
		width       int
		height      int
	}{
		{"a PNG", square, testMaxSize, "image/png", 100, 100},
		{"a JPEG", createTestJPEG(200, 150), testMaxSize, "image/jpeg", 200, 150},
		{"a GIF", createTestGIF(50, 50), testMaxSize, "image/gif", 50, 50},
		{"a WebP", webpOfSize(120, 80), testMaxSize, "image/webp", 120, 80},
		{"a non-square image", createTestPNG(200, 100), testMaxSize, "image/png", 200, 100},
		{"a PNG at the minimum dimensions", createTestPNG(10, 10), testMaxSize, "image/png", 10, 10},
		{"a PNG at the maximum dimensions", createTestPNG(512, 512), testMaxSize, "image/png", 512, 512},
		{"a JPEG at the minimum dimensions", createTestJPEG(10, 10), testMaxSize, "image/jpeg", 10, 10},
		{"a JPEG at the maximum dimensions", createTestJPEG(512, 512), testMaxSize, "image/jpeg", 512, 512},
		{"a GIF at the minimum dimensions", createTestGIF(10, 10), testMaxSize, "image/gif", 10, 10},
		{"a GIF at the maximum dimensions", createTestGIF(512, 512), testMaxSize, "image/gif", 512, 512},
		{"a WebP at the maximum dimensions", webpOfSize(512, 512), testMaxSize, "image/webp", 512, 512},
		// The bound is inclusive: an image of exactly the configured size is stored.
		{"an image of exactly the configured size", square, int64(len(square)), "image/png", 100, 100},
	}
	for _, kind := range configuredKinds {
		for _, tt := range tests {
			t.Run(kind.name+"/"+tt.name, func(t *testing.T) {
				info, err := Validate(tt.data, kind.rules(tt.maxSize))

				require.NoError(t, err)
				assert.Equal(t, Info{ContentType: tt.contentType, Width: tt.width, Height: tt.height}, info)
			})
		}
	}
}

// TestRules_MaxBytes: a configured kind's byte limit is the size it was given, which is what the
// handler bounds the request body by.
func TestRules_MaxBytes(t *testing.T) {
	for _, kind := range configuredKinds {
		t.Run(kind.name, func(t *testing.T) {
			assert.Equal(t, int64(2_000_000), kind.rules(2_000_000).MaxBytes())
		})
	}
}

// corruptedPNG carries PNG's magic bytes, so it passes the type check and fails the decode.
var corruptedPNG = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF}

// webpHeader is a RIFF WebP container header and nothing after it: http.DetectContentType reads
// it as image/webp, and the decoder cannot read it.
var webpHeader = []byte("RIFF\x24\x00\x00\x00WEBPVP8 \x18\x00\x00\x00")

// TestValidate_Refuses holds each of the six codes to the input that reaches it, its arguments and
// its English sentence, and the order the checks run in: the size first, so an oversized body is
// never decoded, then emptiness, the type, the decode, and the dimensions.
func TestValidate_Refuses(t *testing.T) {
	square := createTestPNG(100, 100)

	tests := []struct {
		name    string
		data    []byte
		maxSize int64
		code    string
		args    map[string]any
		english string
	}{
		{"one byte over the configured size", square, int64(len(square)) - 1,
			i18n.ErrCodeImageTooLarge, map[string]any{"max": int64(len(square)) - 1},
			"The image can be at most " + strconv.Itoa(len(square)-1) + " bytes."},
		{"text over the configured size is refused for its size first", []byte("plain text, and too long"), 4,
			i18n.ErrCodeImageTooLarge, map[string]any{"max": int64(4)},
			"The image can be at most 4 bytes."},
		{"an empty file", []byte{}, testMaxSize,
			i18n.ErrCodeImageEmpty, nil, "The image file is empty."},
		{"plain text", []byte("This is just plain text, not an image"), testMaxSize,
			i18n.ErrCodeImageUnsupportedType, nil, unsupportedTypeSentence},
		{"HTML", []byte("<html><body>Not an image</body></html>"), testMaxSize,
			i18n.ErrCodeImageUnsupportedType, nil, unsupportedTypeSentence},
		{"bytes matching no signature", []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}, testMaxSize,
			i18n.ErrCodeImageUnsupportedType, nil, unsupportedTypeSentence},
		// A BMP is an image the standard library recognises and this server does not store.
		{"a BMP", []byte("BM\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), testMaxSize,
			i18n.ErrCodeImageUnsupportedType, nil, unsupportedTypeSentence},
		{"a PNG signature over garbage", corruptedPNG, testMaxSize,
			i18n.ErrCodeImageUndecodable, nil, "The image could not be read. The file may be damaged."},
		// WebP is an allowed type, so a header that does not decode is undecodable, not unsupported.
		{"a WebP header with no image", webpHeader, testMaxSize,
			i18n.ErrCodeImageUndecodable, nil, "The image could not be read. The file may be damaged."},
		{"too narrow", createTestPNG(9, 10), testMaxSize,
			i18n.ErrCodeImageDimensionsTooSmall, map[string]any{"min": 10}, "The image must be at least 10x10 pixels."},
		{"too short", createTestPNG(10, 9), testMaxSize,
			i18n.ErrCodeImageDimensionsTooSmall, map[string]any{"min": 10}, "The image must be at least 10x10 pixels."},
		{"too small both ways", createTestPNG(5, 5), testMaxSize,
			i18n.ErrCodeImageDimensionsTooSmall, map[string]any{"min": 10}, "The image must be at least 10x10 pixels."},
		{"too wide", createTestPNG(513, 512), testMaxSize,
			i18n.ErrCodeImageDimensionsTooLarge, map[string]any{"max": 512}, "The image can be at most 512x512 pixels."},
		{"too tall", createTestPNG(512, 513), testMaxSize,
			i18n.ErrCodeImageDimensionsTooLarge, map[string]any{"max": 512}, "The image can be at most 512x512 pixels."},
		{"too large both ways", createTestPNG(600, 600), testMaxSize,
			i18n.ErrCodeImageDimensionsTooLarge, map[string]any{"max": 512}, "The image can be at most 512x512 pixels."},
		{"a WebP too wide", webpOfSize(513, 100), testMaxSize,
			i18n.ErrCodeImageDimensionsTooLarge, map[string]any{"max": 512}, "The image can be at most 512x512 pixels."},
	}
	for _, kind := range configuredKinds {
		for _, tt := range tests {
			t.Run(kind.name+"/"+tt.name, func(t *testing.T) {
				info, err := Validate(tt.data, kind.rules(tt.maxSize))

				assertRefusal(t, info, err, tt.code, tt.args, tt.english)
			})
		}
	}
}

func assertRefusal(t *testing.T, info Info, err error, code string, args map[string]any, english string) {
	t.Helper()
	assert.Equal(t, Info{}, info)
	var localized *i18n.LocalizedError
	require.ErrorAs(t, err, &localized, "want an *i18n.LocalizedError, got %T: %v", err, err)
	assert.Equal(t, code, localized.Code)
	assert.Equal(t, args, localized.Args)
	assert.Equal(t, english, localized.Localize(context.Background()))
}

// TestValidate_HoldsAnUploadToItsKindsRules: the types, pixel bounds and byte limit an upload is
// checked against are the ones its rules name, not one fixed set. These rules take PNG alone, each
// side from 48 to 64 pixels, up to 4000 bytes, so each check answers at a bound no configured kind
// shares.
func TestValidate_HoldsAnUploadToItsKindsRules(t *testing.T) {
	rules := Rules{
		contentTypes: map[string]bool{"image/png": true},
		typeRefusal:  i18n.ErrCodeImageUnsupportedType,
		minSide:      48,
		maxSide:      64,
		maxBytes:     4000,
	}

	t.Run("accepts at both pixel bounds", func(t *testing.T) {
		for _, side := range []int{48, 64} {
			info, err := Validate(createTestPNG(side, side), rules)

			require.NoError(t, err)
			assert.Equal(t, Info{ContentType: "image/png", Width: side, Height: side}, info)
		}
	})

	refusals := []struct {
		name    string
		data    []byte
		code    string
		args    map[string]any
		english string
	}{
		{"a JPEG, a type another kind takes", createTestJPEG(50, 50),
			i18n.ErrCodeImageUnsupportedType, nil, unsupportedTypeSentence},
		{"a GIF, a type another kind takes", createTestGIF(50, 50),
			i18n.ErrCodeImageUnsupportedType, nil, unsupportedTypeSentence},
		{"a WebP, a type another kind takes", webpOfSize(50, 50),
			i18n.ErrCodeImageUnsupportedType, nil, unsupportedTypeSentence},
		{"one pixel under the minimum", createTestPNG(47, 48),
			i18n.ErrCodeImageDimensionsTooSmall, map[string]any{"min": 48}, "The image must be at least 48x48 pixels."},
		{"one pixel over the maximum", createTestPNG(64, 65),
			i18n.ErrCodeImageDimensionsTooLarge, map[string]any{"max": 64}, "The image can be at most 64x64 pixels."},
		{"one byte over the limit", make([]byte, 4001),
			i18n.ErrCodeImageTooLarge, map[string]any{"max": int64(4000)}, "The image can be at most 4000 bytes."},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			info, err := Validate(tt.data, rules)

			assertRefusal(t, info, err, tt.code, tt.args, tt.english)
		})
	}
}

const unsupportedTypeSentence = "The image type is not supported. Allowed types are JPEG, PNG, GIF and WebP."

// TestValidate_TheRefusalIsLocalized: the codes resolve in the second catalog too, arguments
// included, which is what writeValidationError hands a pt-BR caller.
func TestValidate_TheRefusalIsLocalized(t *testing.T) {
	_, err := Validate(createTestPNG(100, 100), ProfilePicture(64))

	var localized *i18n.LocalizedError
	require.ErrorAs(t, err, &localized)
	assert.Equal(t, "A imagem pode ter no máximo 64 bytes.", localized.Localize(i18n.WithLocale(context.Background(), true, "pt-BR")))
}
