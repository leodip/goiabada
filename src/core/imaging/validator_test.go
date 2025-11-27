package imaging

import (
	"bytes"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestValidateProfilePicture_ValidPNG(t *testing.T) {
	data := createTestPNG(100, 100)

	result := ValidateProfilePicture(data, 0)

	assert.True(t, result.Valid)
	assert.Empty(t, result.Error)
	assert.Equal(t, "image/png", result.ContentType)
	assert.Equal(t, 100, result.Width)
	assert.Equal(t, 100, result.Height)
}

func TestValidateProfilePicture_ValidJPEG(t *testing.T) {
	data := createTestJPEG(200, 150)

	result := ValidateProfilePicture(data, 0)

	assert.True(t, result.Valid)
	assert.Empty(t, result.Error)
	assert.Equal(t, "image/jpeg", result.ContentType)
	assert.Equal(t, 200, result.Width)
	assert.Equal(t, 150, result.Height)
}

func TestValidateProfilePicture_ValidGIF(t *testing.T) {
	data := createTestGIF(50, 50)

	result := ValidateProfilePicture(data, 0)

	assert.True(t, result.Valid)
	assert.Empty(t, result.Error)
	assert.Equal(t, "image/gif", result.ContentType)
	assert.Equal(t, 50, result.Width)
	assert.Equal(t, 50, result.Height)
}

func TestValidateProfilePicture_ValidMaxDimensions(t *testing.T) {
	// Test at exactly max dimensions (512x512)
	data := createTestPNG(MaxDimension, MaxDimension)

	result := ValidateProfilePicture(data, 0)

	assert.True(t, result.Valid)
	assert.Empty(t, result.Error)
	assert.Equal(t, MaxDimension, result.Width)
	assert.Equal(t, MaxDimension, result.Height)
}

func TestValidateProfilePicture_ValidMinDimensions(t *testing.T) {
	// Test at exactly min dimensions (10x10)
	data := createTestPNG(MinDimension, MinDimension)

	result := ValidateProfilePicture(data, 0)

	assert.True(t, result.Valid)
	assert.Empty(t, result.Error)
	assert.Equal(t, MinDimension, result.Width)
	assert.Equal(t, MinDimension, result.Height)
}

func TestValidateProfilePicture_EmptyFile(t *testing.T) {
	data := []byte{}

	result := ValidateProfilePicture(data, 0)

	assert.False(t, result.Valid)
	assert.Equal(t, "file is empty", result.Error)
}

func TestValidateProfilePicture_FileTooLarge(t *testing.T) {
	// Create a small image but test with a very small max size
	data := createTestPNG(100, 100)
	smallMaxSize := int64(100) // 100 bytes, much smaller than any real image

	result := ValidateProfilePicture(data, smallMaxSize)

	assert.False(t, result.Valid)
	assert.Contains(t, result.Error, "file size exceeds maximum allowed size")
}

func TestValidateProfilePicture_FileTooLarge_DefaultMaxSize(t *testing.T) {
	// Create data larger than default max (3MB)
	data := make([]byte, DefaultMaxFileSize+1)
	// Add PNG magic bytes to pass content type check (though it won't be a valid image)
	copy(data, []byte{0x89, 0x50, 0x4E, 0x47})

	result := ValidateProfilePicture(data, 0)

	assert.False(t, result.Valid)
	assert.Contains(t, result.Error, "file size exceeds maximum allowed size")
}

func TestValidateProfilePicture_InvalidType_Text(t *testing.T) {
	data := []byte("This is just plain text, not an image")

	result := ValidateProfilePicture(data, 0)

	assert.False(t, result.Valid)
	assert.Contains(t, result.Error, "unsupported image type")
}

func TestValidateProfilePicture_InvalidType_HTML(t *testing.T) {
	data := []byte("<html><body>Not an image</body></html>")

	result := ValidateProfilePicture(data, 0)

	assert.False(t, result.Valid)
	assert.Contains(t, result.Error, "unsupported image type")
}

func TestValidateProfilePicture_InvalidType_RandomBytes(t *testing.T) {
	// Random bytes that don't match any image magic bytes
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}

	result := ValidateProfilePicture(data, 0)

	assert.False(t, result.Valid)
	assert.Contains(t, result.Error, "unsupported image type")
}

func TestValidateProfilePicture_DimensionsTooSmall_Width(t *testing.T) {
	// Width below minimum
	data := createTestPNG(MinDimension-1, MinDimension)

	result := ValidateProfilePicture(data, 0)

	assert.False(t, result.Valid)
	assert.Contains(t, result.Error, "image dimensions too small")
}

func TestValidateProfilePicture_DimensionsTooSmall_Height(t *testing.T) {
	// Height below minimum
	data := createTestPNG(MinDimension, MinDimension-1)

	result := ValidateProfilePicture(data, 0)

	assert.False(t, result.Valid)
	assert.Contains(t, result.Error, "image dimensions too small")
}

func TestValidateProfilePicture_DimensionsTooSmall_Both(t *testing.T) {
	// Both dimensions below minimum
	data := createTestPNG(5, 5)

	result := ValidateProfilePicture(data, 0)

	assert.False(t, result.Valid)
	assert.Contains(t, result.Error, "image dimensions too small")
}

func TestValidateProfilePicture_DimensionsTooLarge_Width(t *testing.T) {
	// Width above maximum
	data := createTestPNG(MaxDimension+1, MaxDimension)

	result := ValidateProfilePicture(data, 0)

	assert.False(t, result.Valid)
	assert.Contains(t, result.Error, "image dimensions too large")
}

func TestValidateProfilePicture_DimensionsTooLarge_Height(t *testing.T) {
	// Height above maximum
	data := createTestPNG(MaxDimension, MaxDimension+1)

	result := ValidateProfilePicture(data, 0)

	assert.False(t, result.Valid)
	assert.Contains(t, result.Error, "image dimensions too large")
}

func TestValidateProfilePicture_DimensionsTooLarge_Both(t *testing.T) {
	// Both dimensions above maximum
	data := createTestPNG(600, 600)

	result := ValidateProfilePicture(data, 0)

	assert.False(t, result.Valid)
	assert.Contains(t, result.Error, "image dimensions too large")
}

func TestValidateProfilePicture_CustomMaxFileSize(t *testing.T) {
	data := createTestPNG(100, 100)
	// Set a custom max size larger than the image
	customMaxSize := int64(1024 * 1024) // 1MB

	result := ValidateProfilePicture(data, customMaxSize)

	assert.True(t, result.Valid)
	assert.Empty(t, result.Error)
}

func TestValidateProfilePicture_ZeroMaxFileSizeUsesDefault(t *testing.T) {
	data := createTestPNG(100, 100)

	// With maxFileSize = 0, should use DefaultMaxFileSize
	result := ValidateProfilePicture(data, 0)

	assert.True(t, result.Valid)
	assert.Empty(t, result.Error)
}

func TestValidateProfilePicture_NegativeMaxFileSizeUsesDefault(t *testing.T) {
	data := createTestPNG(100, 100)

	// With negative maxFileSize, should use DefaultMaxFileSize
	result := ValidateProfilePicture(data, -100)

	assert.True(t, result.Valid)
	assert.Empty(t, result.Error)
}

func TestValidateProfilePicture_CorruptedImage(t *testing.T) {
	// Create valid PNG header but corrupt the rest
	data := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A} // PNG magic bytes
	// Add some garbage data
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF}...)

	result := ValidateProfilePicture(data, 0)

	assert.False(t, result.Valid)
	assert.Contains(t, result.Error, "unable to decode image")
}

func TestValidateProfilePicture_NonSquareImage(t *testing.T) {
	// Non-square images should be valid as long as dimensions are within limits
	data := createTestPNG(200, 100)

	result := ValidateProfilePicture(data, 0)

	assert.True(t, result.Valid)
	assert.Equal(t, 200, result.Width)
	assert.Equal(t, 100, result.Height)
}

func TestValidateProfilePicture_AllFormats_AtBoundary(t *testing.T) {
	testCases := []struct {
		name        string
		createFunc  func(w, h int) []byte
		contentType string
	}{
		{"PNG", createTestPNG, "image/png"},
		{"JPEG", createTestJPEG, "image/jpeg"},
		{"GIF", createTestGIF, "image/gif"},
	}

	for _, tc := range testCases {
		t.Run(tc.name+"_MinDimensions", func(t *testing.T) {
			data := tc.createFunc(MinDimension, MinDimension)
			result := ValidateProfilePicture(data, 0)
			assert.True(t, result.Valid, "Expected valid for %s at min dimensions", tc.name)
			assert.Equal(t, tc.contentType, result.ContentType)
		})

		t.Run(tc.name+"_MaxDimensions", func(t *testing.T) {
			data := tc.createFunc(MaxDimension, MaxDimension)
			result := ValidateProfilePicture(data, 0)
			assert.True(t, result.Valid, "Expected valid for %s at max dimensions", tc.name)
			assert.Equal(t, tc.contentType, result.ContentType)
		})
	}
}

func TestConstants(t *testing.T) {
	// Verify constants have expected values
	assert.Equal(t, int64(3*1024*1024), int64(DefaultMaxFileSize), "DefaultMaxFileSize should be 3MB")
	assert.Equal(t, 512, MaxDimension, "MaxDimension should be 512")
	assert.Equal(t, 10, MinDimension, "MinDimension should be 10")
}

func TestAllowedContentTypes(t *testing.T) {
	// Verify allowed content types
	assert.True(t, AllowedContentTypes["image/jpeg"])
	assert.True(t, AllowedContentTypes["image/png"])
	assert.True(t, AllowedContentTypes["image/gif"])
	assert.True(t, AllowedContentTypes["image/webp"])

	// Verify non-allowed types
	assert.False(t, AllowedContentTypes["image/bmp"])
	assert.False(t, AllowedContentTypes["image/tiff"])
	assert.False(t, AllowedContentTypes["text/plain"])
	assert.False(t, AllowedContentTypes["application/octet-stream"])
}
