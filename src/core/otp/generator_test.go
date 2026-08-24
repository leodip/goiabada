package otp

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	pquernaotp "github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
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

		keyURL, err := generator.GenerateOTPSecret(email, appName)

		require.NoError(t, err, "GenerateOTPSecret should not return an error for valid input")
		require.NotEmpty(t, keyURL, "the otpauth URL should not be empty")

		// The URL is the whole record of the key, so what it says about the key matters as
		// much as that it parses: an authenticator scanning it configures itself from these
		// parameters, and the server verifies against the library defaults.
		key, err := pquernaotp.NewKeyFromURL(keyURL)
		require.NoError(t, err, "the URL should be a valid otpauth URL")
		assert.Equal(t, "totp", key.Type())
		assert.Equal(t, appName, key.Issuer())
		assert.Equal(t, email, key.AccountName())
		assert.NotEmpty(t, key.Secret())
		assert.Equal(t, uint64(30), key.Period())
		assert.Equal(t, pquernaotp.AlgorithmSHA1, key.Algorithm())
		assert.Equal(t, pquernaotp.DigitsSix, key.Digits())
	})

	t.Run("Empty email", func(t *testing.T) {
		_, err := generator.GenerateOTPSecret("", "TestApp")

		assert.Error(t, err, "GenerateOTPSecret should return an error for empty email")
		assert.Contains(t, err.Error(), "email is empty", "Error message should mention empty email")
	})

	t.Run("Whitespace email", func(t *testing.T) {
		_, err := generator.GenerateOTPSecret("   ", "TestApp")

		assert.Error(t, err, "GenerateOTPSecret should return an error for whitespace email")
		assert.Contains(t, err.Error(), "email is empty", "Error message should mention empty email")
	})

	t.Run("Empty app name", func(t *testing.T) {
		_, err := generator.GenerateOTPSecret("test@example.com", "")

		assert.Error(t, err, "GenerateOTPSecret should return an error for empty app name")
		assert.Contains(t, err.Error(), "app name is empty", "Error message should mention empty app name")
	})

	t.Run("Whitespace app name", func(t *testing.T) {
		_, err := generator.GenerateOTPSecret("test@example.com", "   ")

		assert.Error(t, err, "GenerateOTPSecret should return an error for whitespace app name")
		assert.Contains(t, err.Error(), "app name is empty", "Error message should mention empty app name")
	})

	t.Run("Different output for different inputs", func(t *testing.T) {
		url1, err1 := generator.GenerateOTPSecret("test1@example.com", "TestApp1")
		require.NoError(t, err1)

		url2, err2 := generator.GenerateOTPSecret("test2@example.com", "TestApp2")
		require.NoError(t, err2)

		assert.NotEqual(t, url1, url2, "URLs should be different for different inputs")

		secret1, err := SecretFromKeyURL(url1)
		require.NoError(t, err)
		secret2, err := SecretFromKeyURL(url2)
		require.NoError(t, err)
		assert.NotEqual(t, secret1, secret2, "Secret keys should be different for different inputs")
	})

	t.Run("Input length restrictions", func(t *testing.T) {
		t.Run("Valid lengths", func(t *testing.T) {
			email := gofakeit.LetterN(58) + "@b.com" // 64 characters
			appName := gofakeit.LetterN(32)

			keyURL, err := generator.GenerateOTPSecret(email, appName)

			require.NoError(t, err, "GenerateOTPSecret should not return an error for maximum valid lengths")
			assert.NotEmpty(t, keyURL, "the otpauth URL should not be empty for maximum valid lengths")

			secret, err := SecretFromKeyURL(keyURL)
			require.NoError(t, err)
			assert.NotEmpty(t, secret, "Secret key should not be empty for maximum valid lengths")
		})

		t.Run("Email too long", func(t *testing.T) {
			longEmail := strings.Repeat("a", 61) + "@b.com" // 65 characters
			appName := "TestApp"

			_, err := generator.GenerateOTPSecret(longEmail, appName)

			require.Error(t, err, "GenerateOTPSecret should return an error for email longer than 64 characters")
			assert.Contains(t, err.Error(), "email is too long", "Error message should mention email is too long")
		})

		t.Run("App name too long", func(t *testing.T) {
			email := "test@example.com"
			longAppName := strings.Repeat("b", 33) // 33 characters

			_, err := generator.GenerateOTPSecret(email, longAppName)

			require.Error(t, err, "GenerateOTPSecret should return an error for app name longer than 32 characters")
			assert.Contains(t, err.Error(), "app name is too long", "Error message should mention app name is too long")
		})
	})
}

// The URL now stands in for the key everywhere the ceremony used to carry the secret and the
// rendered image, so the correspondence between the three has to be proven rather than reasoned
// about: what a user scans must configure their authenticator with the secret the server later
// verifies against.
//
// Punctuation in the issuer and account is in the table deliberately. The URL encodes both into
// its path and its query, so "&", "+" and spaces are where a serialization that looked right for
// ordinary input would come back as a different key.
func TestKeyURLRoundTrip(t *testing.T) {
	generator := NewOTPSecretGenerator()

	cases := []struct{ appName, email string }{
		{"Goiabada", "a@b.co"},
		{"Goiabada", "someuser@example.com"},
		{"A Long App Name", "a-long-address-inside-the-cap@example.com"},
		{"Acme Ltd & Co", "user+tag@example.com"},
	}

	for _, c := range cases {
		t.Run(c.appName+" / "+c.email, func(t *testing.T) {
			keyURL, err := generator.GenerateOTPSecret(c.email, c.appName)
			require.NoError(t, err)

			secret, err := SecretFromKeyURL(keyURL)
			require.NoError(t, err)
			require.NotEmpty(t, secret)

			// A code an authenticator produces from the URL it scanned validates against the
			// secret this package hands the verifier. That is the whole claim: the two are
			// the same key.
			code, err := totp.GenerateCode(secret, time.Now().UTC())
			require.NoError(t, err)
			assert.True(t, totp.Validate(code, secret),
				"a code from the URL's secret must validate against it")

			base64Image, err := RenderQRCodeImage(keyURL)
			require.NoError(t, err)

			decoded, err := base64.StdEncoding.DecodeString(base64Image)
			require.NoError(t, err, "the rendered QR code must be valid base64")

			img, err := png.Decode(bytes.NewReader(decoded))
			require.NoError(t, err, "the rendered QR code must be a valid PNG")
			assert.Equal(t, qrCodePixels, img.Bounds().Dx(), "QR code width")
			assert.Equal(t, qrCodePixels, img.Bounds().Dy(), "QR code height")

			// Rendering is a pure function of the URL, which is what lets the image be
			// dropped from the ceremony and drawn again on every render.
			again, err := RenderQRCodeImage(keyURL)
			require.NoError(t, err)
			assert.Equal(t, base64Image, again,
				"the same URL must render the same image, byte for byte")
		})
	}
}

// Every case below is one the library accepts: otp.NewKeyFromURL runs url.Parse and validates
// nothing, so without these guards a caller would verify passcodes against an empty secret and
// render a QR code that enrols an authenticator in nothing.
func TestKeyURLRefusals(t *testing.T) {
	cases := []struct {
		name   string
		keyURL string
	}{
		{"empty", ""},
		{"whitespace", "   "},
		{"not an otpauth url", "https://example.com/totp?secret=JBSWY3DPEHPK3PXP"},
		{"hotp rather than totp", "otpauth://hotp/Goiabada:a@b.co?secret=JBSWY3DPEHPK3PXP&counter=1"},
		{"no secret parameter", "otpauth://totp/Goiabada:a@b.co?algorithm=SHA1&digits=6&period=30"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Stated rather than assumed: the guard is this package's job precisely because
			// the library does not refuse these.
			if strings.TrimSpace(c.keyURL) != "" {
				_, err := pquernaotp.NewKeyFromURL(c.keyURL)
				require.NoError(t, err, "the library accepts this URL, which is why the guard exists")
			}

			_, err := SecretFromKeyURL(c.keyURL)
			assert.Error(t, err, "SecretFromKeyURL must refuse %q", c.keyURL)

			_, err = RenderQRCodeImage(c.keyURL)
			assert.Error(t, err, "RenderQRCodeImage must refuse %q", c.keyURL)
		})
	}
}
