package imageupload

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"maps"
	"slices"
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

// testMaxSize is a configured size well above every image built here.
const testMaxSize = int64(3 << 20)

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
		{"a non-square image", createTestPNG(200, 100), testMaxSize, "image/png", 200, 100},
		{"a PNG at the minimum dimensions", createTestPNG(MinDimension, MinDimension), testMaxSize, "image/png", MinDimension, MinDimension},
		{"a PNG at the maximum dimensions", createTestPNG(MaxDimension, MaxDimension), testMaxSize, "image/png", MaxDimension, MaxDimension},
		{"a JPEG at the minimum dimensions", createTestJPEG(MinDimension, MinDimension), testMaxSize, "image/jpeg", MinDimension, MinDimension},
		{"a JPEG at the maximum dimensions", createTestJPEG(MaxDimension, MaxDimension), testMaxSize, "image/jpeg", MaxDimension, MaxDimension},
		{"a GIF at the minimum dimensions", createTestGIF(MinDimension, MinDimension), testMaxSize, "image/gif", MinDimension, MinDimension},
		{"a GIF at the maximum dimensions", createTestGIF(MaxDimension, MaxDimension), testMaxSize, "image/gif", MaxDimension, MaxDimension},
		// The bound is inclusive: an image of exactly the configured size is stored.
		{"an image of exactly the configured size", square, int64(len(square)), "image/png", 100, 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := Validate(tt.data, tt.maxSize)

			require.NoError(t, err)
			assert.Equal(t, Info{ContentType: tt.contentType, Width: tt.width, Height: tt.height}, info)
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
		{"too narrow", createTestPNG(MinDimension-1, MinDimension), testMaxSize,
			i18n.ErrCodeImageDimensionsTooSmall, map[string]any{"min": MinDimension}, "The image must be at least 10x10 pixels."},
		{"too short", createTestPNG(MinDimension, MinDimension-1), testMaxSize,
			i18n.ErrCodeImageDimensionsTooSmall, map[string]any{"min": MinDimension}, "The image must be at least 10x10 pixels."},
		{"too small both ways", createTestPNG(5, 5), testMaxSize,
			i18n.ErrCodeImageDimensionsTooSmall, map[string]any{"min": MinDimension}, "The image must be at least 10x10 pixels."},
		{"too wide", createTestPNG(MaxDimension+1, MaxDimension), testMaxSize,
			i18n.ErrCodeImageDimensionsTooLarge, map[string]any{"max": MaxDimension}, "The image can be at most 512x512 pixels."},
		{"too tall", createTestPNG(MaxDimension, MaxDimension+1), testMaxSize,
			i18n.ErrCodeImageDimensionsTooLarge, map[string]any{"max": MaxDimension}, "The image can be at most 512x512 pixels."},
		{"too large both ways", createTestPNG(600, 600), testMaxSize,
			i18n.ErrCodeImageDimensionsTooLarge, map[string]any{"max": MaxDimension}, "The image can be at most 512x512 pixels."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := Validate(tt.data, tt.maxSize)

			assert.Equal(t, Info{}, info)
			var localized *i18n.LocalizedError
			require.True(t, errors.As(err, &localized), "want an *i18n.LocalizedError, got %T: %v", err, err)
			assert.Equal(t, tt.code, localized.Code)
			assert.Equal(t, tt.args, localized.Args)
			assert.Equal(t, tt.english, localized.Localize(context.Background()))
		})
	}
}

const unsupportedTypeSentence = "The image type is not supported. Allowed types are JPEG, PNG, GIF and WebP."

// TestValidate_TheRefusalIsLocalized: the codes resolve in the second catalog too, arguments
// included, which is what writeValidationError hands a pt-BR caller.
func TestValidate_TheRefusalIsLocalized(t *testing.T) {
	_, err := Validate(createTestPNG(100, 100), 64)

	var localized *i18n.LocalizedError
	require.True(t, errors.As(err, &localized))
	assert.Equal(t, "A imagem pode ter no máximo 64 bytes.", localized.Localize(i18n.WithLocale(context.Background(), true, "pt-BR")))
}

// TestAllowedContentTypes: the four types a decoder is registered for, and nothing else. The
// sentence every unsupported_type refusal renders names the same four.
func TestAllowedContentTypes(t *testing.T) {
	assert.Equal(t, []string{"image/gif", "image/jpeg", "image/png", "image/webp"},
		slices.Sorted(maps.Keys(allowedContentTypes)))
}
