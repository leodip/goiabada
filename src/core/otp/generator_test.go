package otp

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOTPSecretGenerator(t *testing.T) {
	generator := NewOTPSecretGenerator()
	assert.NotNil(t, generator, "NewOTPSecretGenerator should return a non-nil generator")
}

func TestGenerateOTPSecret(t *testing.T) {
	generator := NewOTPSecretGenerator()

	t.Run("Valid input", func(t *testing.T) {
		email := "test@example.com"
		appName := "TestApp"

		base64QR, secret, err := generator.GenerateOTPSecret(email, appName)

		require.NoError(t, err, "GenerateOTPSecret should not return an error for valid input")
		assert.NotEmpty(t, base64QR, "Base64 QR code should not be empty")
		assert.NotEmpty(t, secret, "Secret key should not be empty")

		// Verify that base64QR is a valid base64-encoded string
		decodedQR, err := base64.StdEncoding.DecodeString(base64QR)
		require.NoError(t, err, "Base64 QR code should be a valid base64-encoded string")

		// Verify that the decoded data is a valid PNG image
		_, err = png.Decode(bytes.NewReader(decodedQR))
		assert.NoError(t, err, "Decoded QR code should be a valid PNG image")
	})

	t.Run("Empty email", func(t *testing.T) {
		_, _, err := generator.GenerateOTPSecret("", "TestApp")

		assert.Error(t, err, "GenerateOTPSecret should return an error for empty email")
		assert.Contains(t, err.Error(), "email is empty", "Error message should mention empty email")
	})

	t.Run("Whitespace email", func(t *testing.T) {
		_, _, err := generator.GenerateOTPSecret("   ", "TestApp")

		assert.Error(t, err, "GenerateOTPSecret should return an error for whitespace email")
		assert.Contains(t, err.Error(), "email is empty", "Error message should mention empty email")
	})

	t.Run("Empty app name", func(t *testing.T) {
		_, _, err := generator.GenerateOTPSecret("test@example.com", "")

		assert.Error(t, err, "GenerateOTPSecret should return an error for empty app name")
		assert.Contains(t, err.Error(), "app name is empty", "Error message should mention empty app name")
	})

	t.Run("Whitespace app name", func(t *testing.T) {
		_, _, err := generator.GenerateOTPSecret("test@example.com", "   ")

		assert.Error(t, err, "GenerateOTPSecret should return an error for whitespace app name")
		assert.Contains(t, err.Error(), "app name is empty", "Error message should mention empty app name")
	})

	t.Run("Different output for different inputs", func(t *testing.T) {
		base64QR1, secret1, err1 := generator.GenerateOTPSecret("test1@example.com", "TestApp1")
		require.NoError(t, err1)

		base64QR2, secret2, err2 := generator.GenerateOTPSecret("test2@example.com", "TestApp2")
		require.NoError(t, err2)

		assert.NotEqual(t, secret1, secret2, "Secret keys should be different for different inputs")
		assert.NotEqual(t, base64QR1, base64QR2, "QR codes should be different for different inputs")
	})

	t.Run("Input length restrictions", func(t *testing.T) {
		t.Run("Valid lengths", func(t *testing.T) {
			email := gofakeit.LetterN(58) + "@b.com" // 64 characters
			appName := gofakeit.LetterN(32)

			base64QR, secret, err := generator.GenerateOTPSecret(email, appName)

			require.NoError(t, err, "GenerateOTPSecret should not return an error for maximum valid lengths")
			assert.NotEmpty(t, base64QR, "Base64 QR code should not be empty for maximum valid lengths")
			assert.NotEmpty(t, secret, "Secret key should not be empty for maximum valid lengths")
		})

		t.Run("Email too long", func(t *testing.T) {
			longEmail := strings.Repeat("a", 61) + "@b.com" // 65 characters
			appName := "TestApp"

			_, _, err := generator.GenerateOTPSecret(longEmail, appName)

			require.Error(t, err, "GenerateOTPSecret should return an error for email longer than 64 characters")
			assert.Contains(t, err.Error(), "email is too long", "Error message should mention email is too long")
		})

		t.Run("App name too long", func(t *testing.T) {
			email := "test@example.com"
			longAppName := strings.Repeat("b", 33) // 33 characters

			_, _, err := generator.GenerateOTPSecret(email, longAppName)

			require.Error(t, err, "GenerateOTPSecret should return an error for app name longer than 32 characters")
			assert.Contains(t, err.Error(), "app name is too long", "Error message should mention app name is too long")
		})
	})

	t.Run("QR code size", func(t *testing.T) {
		email := "test@example.com"
		appName := "TestApp"

		base64QR, _, err := generator.GenerateOTPSecret(email, appName)
		require.NoError(t, err)

		decodedQR, err := base64.StdEncoding.DecodeString(base64QR)
		require.NoError(t, err)

		img, err := png.Decode(bytes.NewReader(decodedQR))
		require.NoError(t, err)

		assert.Equal(t, 180, img.Bounds().Dx(), "QR code width should be 180 pixels")
		assert.Equal(t, 180, img.Bounds().Dy(), "QR code height should be 180 pixels")
	})
}
