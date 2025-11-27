package imaging

import (
	"bytes"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"net/http"

	_ "golang.org/x/image/webp"
)

const (
	DefaultMaxFileSize = 3 * 1024 * 1024 // 3MB default
	MaxDimension       = 512             // 512x512 max
	MinDimension       = 10              // 10x10 min
)

var AllowedContentTypes = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/gif":  true,
	"image/webp": true,
}

type ValidationResult struct {
	Valid       bool
	Error       string
	ContentType string
	Width       int
	Height      int
}

// ValidateProfilePicture validates an image for use as a profile picture.
// maxFileSize is the maximum allowed file size in bytes. If 0, DefaultMaxFileSize is used.
func ValidateProfilePicture(data []byte, maxFileSize int64) ValidationResult {
	if maxFileSize <= 0 {
		maxFileSize = DefaultMaxFileSize
	}

	// Check file size
	if int64(len(data)) > maxFileSize {
		return ValidationResult{
			Valid: false,
			Error: fmt.Sprintf("file size exceeds maximum allowed size of %d bytes", maxFileSize),
		}
	}

	// Check minimum size
	if len(data) == 0 {
		return ValidationResult{
			Valid: false,
			Error: "file is empty",
		}
	}

	// Detect content type from magic bytes
	contentType := http.DetectContentType(data)
	if !AllowedContentTypes[contentType] {
		return ValidationResult{
			Valid: false,
			Error: fmt.Sprintf("unsupported image type: %s. Allowed types: JPEG, PNG, GIF, WebP", contentType),
		}
	}

	// Decode image to get dimensions
	img, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return ValidationResult{
			Valid: false,
			Error: fmt.Sprintf("unable to decode image: %v", err),
		}
	}

	// Check dimensions
	if img.Width < MinDimension || img.Height < MinDimension {
		return ValidationResult{
			Valid: false,
			Error: fmt.Sprintf("image dimensions too small. Minimum size is %dx%d pixels", MinDimension, MinDimension),
		}
	}

	if img.Width > MaxDimension || img.Height > MaxDimension {
		return ValidationResult{
			Valid: false,
			Error: fmt.Sprintf("image dimensions too large. Maximum size is %dx%d pixels", MaxDimension, MaxDimension),
		}
	}

	return ValidationResult{
		Valid:       true,
		ContentType: contentType,
		Width:       img.Width,
		Height:      img.Height,
	}
}
