package imageupload

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A brand's three image kinds, each held to its own fixed rules (#813 decision 3): a logo is a
// still PNG, JPEG or WebP, each side from 10 to 512 pixels, up to 1 MiB; a favicon a still, square
// PNG from 48 to 512 pixels a side, up to 1 MiB; a background a still PNG, JPEG or WebP, each side
// from 10 to 3840 pixels, up to 2 MiB. Each limit is tested at the bound and one past it.

// pngChunk is one PNG chunk: its length, its type, its data and the CRC over the type and data.
func pngChunk(chunkType string, data []byte) []byte {
	var chunk bytes.Buffer
	_ = binary.Write(&chunk, binary.BigEndian, uint32(len(data)))
	chunk.WriteString(chunkType)
	chunk.Write(data)
	_ = binary.Write(&chunk, binary.BigEndian, crc32.ChecksumIEEE(append([]byte(chunkType), data...)))
	return chunk.Bytes()
}

// pngOfSize is a PNG's signature, its IHDR naming width by height pixels, the chunks given, and
// IEND: as far as a decoder reads to answer the size, without the megabytes a large image's pixels
// would take to build.
func pngOfSize(width, height int, chunks ...[]byte) []byte {
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], uint32(width))
	binary.BigEndian.PutUint32(ihdr[4:], uint32(height))
	ihdr[8], ihdr[9] = 8, 6 // eight bits a sample, RGBA
	png := append([]byte("\x89PNG\r\n\x1a\n"), pngChunk("IHDR", ihdr)...)
	for _, chunk := range chunks {
		png = append(png, chunk...)
	}
	return append(png, pngChunk("IEND", nil)...)
}

// animatedPNG is an APNG: a real PNG of width by height pixels with an acTL chunk, two frames
// played for ever, after its IHDR, where the APNG specification places it.
func animatedPNG(width, height int) []byte {
	png := createTestPNG(width, height)
	acTL := pngChunk("acTL", []byte{0, 0, 0, 2, 0, 0, 0, 0})
	const afterIHDR = 8 + 25
	return append(append(append([]byte{}, png[:afterIHDR]...), acTL...), png[afterIHDR:]...)
}

// webpOfSizeWithFlags is webpOfSize with the VP8X flags byte given, then the chunks given. Bit 1
// (0x02) is the animation flag (RFC 9649 section 2.7).
func webpOfSizeWithFlags(width, height int, flags byte, chunks ...[]byte) []byte {
	vp8x := []byte{
		flags, 0, 0, 0,
		byte(width - 1), byte((width - 1) >> 8), byte((width - 1) >> 16),
		byte(height - 1), byte((height - 1) >> 8), byte((height - 1) >> 16),
	}
	body := append([]byte("WEBPVP8X\x0a\x00\x00\x00"), vp8x...)
	for _, chunk := range chunks {
		body = append(body, chunk...)
	}
	size := len(body)
	riff := append([]byte("RIFF"), byte(size), byte(size>>8), byte(size>>16), byte(size>>24))
	return append(riff, body...)
}

// animatedWebP is a WebP whose VP8X sets the animation flag and which carries an ANIM chunk, as
// an animated WebP does.
func animatedWebP(width, height int) []byte {
	anim := append([]byte("ANIM\x06\x00\x00\x00"), 0, 0, 0, 0, 0, 0)
	return webpOfSizeWithFlags(width, height, 0x02, anim)
}

// paddedTo is data followed by zero bytes, size bytes in all: a file of exactly a byte limit.
func paddedTo(data []byte, size int) []byte {
	return append(append([]byte{}, data...), make([]byte, size-len(data))...)
}

const svgLogo = `<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><rect width="100" height="100"/></svg>`

const (
	pngJpegWebpSentence = "The image type is not supported. Allowed types are PNG, JPEG and WebP."
	pngOnlySentence     = "The image type is not supported. The only allowed type is PNG."
	animatedSentence    = "Animated images are not allowed. Upload a still image."
)

func TestBrandKinds_MaxBytes(t *testing.T) {
	assert.Equal(t, int64(1048576), BrandLogo().MaxBytes())
	assert.Equal(t, int64(1048576), BrandFavicon().MaxBytes())
	assert.Equal(t, int64(2097152), BrandBackground().MaxBytes())
}

func TestBrandKinds_Accept(t *testing.T) {
	tests := []struct {
		name        string
		rules       Rules
		data        []byte
		contentType string
		width       int
		height      int
	}{
		{"logo/a PNG at the minimum sides", BrandLogo(), createTestPNG(10, 10), "image/png", 10, 10},
		{"logo/a PNG at the maximum sides", BrandLogo(), pngOfSize(512, 512), "image/png", 512, 512},
		{"logo/a wide PNG", BrandLogo(), pngOfSize(512, 10), "image/png", 512, 10},
		{"logo/a JPEG", BrandLogo(), createTestJPEG(200, 100), "image/jpeg", 200, 100},
		{"logo/a still WebP", BrandLogo(), webpOfSizeWithFlags(300, 120, 0x10), "image/webp", 300, 120},
		{"logo/exactly 1 MiB", BrandLogo(), paddedTo(createTestPNG(100, 100), 1048576), "image/png", 100, 100},

		{"favicon/a PNG at the minimum side", BrandFavicon(), createTestPNG(48, 48), "image/png", 48, 48},
		{"favicon/a PNG at the maximum side", BrandFavicon(), pngOfSize(512, 512), "image/png", 512, 512},
		{"favicon/exactly 1 MiB", BrandFavicon(), paddedTo(createTestPNG(64, 64), 1048576), "image/png", 64, 64},

		{"background/a PNG at the minimum sides", BrandBackground(), createTestPNG(10, 10), "image/png", 10, 10},
		{"background/a PNG at the maximum sides", BrandBackground(), pngOfSize(3840, 3840), "image/png", 3840, 3840},
		{"background/a JPEG", BrandBackground(), createTestJPEG(640, 360), "image/jpeg", 640, 360},
		{"background/a still WebP", BrandBackground(), webpOfSizeWithFlags(3840, 2160, 0), "image/webp", 3840, 2160},
		{"background/exactly 2 MiB", BrandBackground(), paddedTo(createTestPNG(100, 100), 2097152), "image/png", 100, 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := Validate(tt.data, tt.rules)

			require.NoError(t, err)
			assert.Equal(t, Info{ContentType: tt.contentType, Width: tt.width, Height: tt.height}, info)
		})
	}
}

func TestBrandKinds_Refuse(t *testing.T) {
	tests := []struct {
		name    string
		rules   Rules
		data    []byte
		code    string
		args    map[string]any
		english string
	}{
		{"logo/one byte over 1 MiB", BrandLogo(), paddedTo(createTestPNG(100, 100), 1048577),
			i18n.ErrCodeImageTooLarge, map[string]any{"max": int64(1048576)}, "The image can be at most 1048576 bytes."},
		{"logo/a GIF", BrandLogo(), createTestGIF(50, 50),
			i18n.ErrCodeImageUnsupportedTypePngJpegWebp, nil, pngJpegWebpSentence},
		{"logo/an SVG", BrandLogo(), []byte(svgLogo),
			i18n.ErrCodeImageUnsupportedTypePngJpegWebp, nil, pngJpegWebpSentence},
		{"logo/one pixel under the minimum", BrandLogo(), createTestPNG(9, 10),
			i18n.ErrCodeImageDimensionsTooSmall, map[string]any{"min": 10}, "The image must be at least 10x10 pixels."},
		{"logo/one pixel over the maximum", BrandLogo(), pngOfSize(513, 512),
			i18n.ErrCodeImageDimensionsTooLarge, map[string]any{"max": 512}, "The image can be at most 512x512 pixels."},
		{"logo/an animated PNG", BrandLogo(), animatedPNG(100, 100),
			i18n.ErrCodeImageAnimated, nil, animatedSentence},
		{"logo/an animated WebP", BrandLogo(), animatedWebP(100, 100),
			i18n.ErrCodeImageAnimated, nil, animatedSentence},

		{"favicon/one byte over 1 MiB", BrandFavicon(), paddedTo(createTestPNG(64, 64), 1048577),
			i18n.ErrCodeImageTooLarge, map[string]any{"max": int64(1048576)}, "The image can be at most 1048576 bytes."},
		{"favicon/a JPEG", BrandFavicon(), createTestJPEG(64, 64),
			i18n.ErrCodeImageUnsupportedTypePng, nil, pngOnlySentence},
		{"favicon/a WebP", BrandFavicon(), webpOfSizeWithFlags(64, 64, 0),
			i18n.ErrCodeImageUnsupportedTypePng, nil, pngOnlySentence},
		{"favicon/a GIF", BrandFavicon(), createTestGIF(64, 64),
			i18n.ErrCodeImageUnsupportedTypePng, nil, pngOnlySentence},
		{"favicon/one pixel under the minimum", BrandFavicon(), createTestPNG(47, 47),
			i18n.ErrCodeImageDimensionsTooSmall, map[string]any{"min": 48}, "The image must be at least 48x48 pixels."},
		{"favicon/one pixel over the maximum", BrandFavicon(), pngOfSize(513, 513),
			i18n.ErrCodeImageDimensionsTooLarge, map[string]any{"max": 512}, "The image can be at most 512x512 pixels."},
		{"favicon/one pixel taller than wide", BrandFavicon(), createTestPNG(48, 49),
			i18n.ErrCodeImageNotSquare, map[string]any{"width": 48, "height": 49},
			"The image must be square. This one is 48x49 pixels."},
		{"favicon/wider than tall", BrandFavicon(), createTestPNG(100, 60),
			i18n.ErrCodeImageNotSquare, map[string]any{"width": 100, "height": 60},
			"The image must be square. This one is 100x60 pixels."},
		{"favicon/an animated PNG", BrandFavicon(), animatedPNG(64, 64),
			i18n.ErrCodeImageAnimated, nil, animatedSentence},

		{"background/one byte over 2 MiB", BrandBackground(), paddedTo(createTestPNG(100, 100), 2097153),
			i18n.ErrCodeImageTooLarge, map[string]any{"max": int64(2097152)}, "The image can be at most 2097152 bytes."},
		{"background/a GIF", BrandBackground(), createTestGIF(50, 50),
			i18n.ErrCodeImageUnsupportedTypePngJpegWebp, nil, pngJpegWebpSentence},
		{"background/one pixel under the minimum", BrandBackground(), createTestPNG(10, 9),
			i18n.ErrCodeImageDimensionsTooSmall, map[string]any{"min": 10}, "The image must be at least 10x10 pixels."},
		{"background/one pixel over the maximum", BrandBackground(), pngOfSize(3841, 100),
			i18n.ErrCodeImageDimensionsTooLarge, map[string]any{"max": 3840}, "The image can be at most 3840x3840 pixels."},
		{"background/a WebP one pixel over the maximum", BrandBackground(), webpOfSizeWithFlags(100, 3841, 0),
			i18n.ErrCodeImageDimensionsTooLarge, map[string]any{"max": 3840}, "The image can be at most 3840x3840 pixels."},
		{"background/an animated PNG", BrandBackground(), animatedPNG(100, 100),
			i18n.ErrCodeImageAnimated, nil, animatedSentence},
		{"background/an animated WebP", BrandBackground(), animatedWebP(1920, 1080),
			i18n.ErrCodeImageAnimated, nil, animatedSentence},
		// The flag alone is enough: a WebP that says it animates is refused before any frame is read.
		{"background/a WebP flagged as animated", BrandBackground(), webpOfSizeWithFlags(100, 100, 0x02),
			i18n.ErrCodeImageAnimated, nil, animatedSentence},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := Validate(tt.data, tt.rules)

			assertRefusal(t, info, err, tt.code, tt.args, tt.english)
		})
	}
}

// An acTL chunk anywhere before IEND makes a PNG animated, wherever an encoder put it, and an
// ancillary chunk of another name does not.
func TestBrandKinds_APNGIsToldByItsAnimationChunk(t *testing.T) {
	acTL := pngChunk("acTL", []byte{0, 0, 0, 2, 0, 0, 0, 0})
	text := pngChunk("tEXt", []byte("Comment\x00still"))

	_, err := Validate(pngOfSize(64, 64, text, acTL), BrandFavicon())
	var localized *i18n.LocalizedError
	require.ErrorAs(t, err, &localized)
	assert.Equal(t, i18n.ErrCodeImageAnimated, localized.Code)

	info, err := Validate(pngOfSize(64, 64, text), BrandFavicon())
	require.NoError(t, err)
	assert.Equal(t, Info{ContentType: "image/png", Width: 64, Height: 64}, info)
}
