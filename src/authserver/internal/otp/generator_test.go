package otp

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyGenerator(t *testing.T) {
	generator := NewKeyGenerator()
	assert.NotNil(t, generator, "NewKeyGenerator should return a non-nil generator")
}

func TestGenerateKeyURL(t *testing.T) {
	generator := NewKeyGenerator()

	t.Run("Valid input", func(t *testing.T) {
		email := "test@example.com"
		appName := "TestApp"

		keyURL, err := generator.GenerateKeyURL(email, appName)

		require.NoError(t, err, "GenerateKeyURL should not return an error for valid input")
		require.NotEmpty(t, keyURL, "the otpauth URL should not be empty")

		// The URL is the whole record of the key, so what it says about the key matters as
		// much as that it parses: an authenticator scanning it configures itself from these
		// parameters, and the server verifies against the same profile.
		parsed, err := url.Parse(keyURL)
		require.NoError(t, err, "the URL should be a valid otpauth URL")
		assert.Equal(t, "otpauth", parsed.Scheme)
		assert.Equal(t, "totp", parsed.Host)
		assert.Equal(t, "/"+appName+":"+email, parsed.Path)
		query := parsed.Query()
		assert.Equal(t, []string{appName}, query["issuer"])
		assert.Equal(t, []string{"SHA1"}, query["algorithm"])
		assert.Equal(t, []string{"6"}, query["digits"])
		assert.Equal(t, []string{"30"}, query["period"])
		require.Len(t, query["secret"], 1)

		// 20 bytes from crypto/rand, 160 bits as RFC 4226 section 4 recommends, written as
		// base32 without padding as the Key URI Format asks.
		secret := query["secret"][0]
		assert.Len(t, secret, 32)
		key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		require.NoError(t, err)
		assert.Len(t, key, 20)
	})

	t.Run("Empty email", func(t *testing.T) {
		_, err := generator.GenerateKeyURL("", "TestApp")

		require.Error(t, err, "GenerateKeyURL should return an error for empty email")
		assert.Contains(t, err.Error(), "email is empty", "Error message should mention empty email")
	})

	t.Run("Whitespace email", func(t *testing.T) {
		_, err := generator.GenerateKeyURL("   ", "TestApp")

		require.Error(t, err, "GenerateKeyURL should return an error for whitespace email")
		assert.Contains(t, err.Error(), "email is empty", "Error message should mention empty email")
	})

	t.Run("Empty app name", func(t *testing.T) {
		_, err := generator.GenerateKeyURL("test@example.com", "")

		require.Error(t, err, "GenerateKeyURL should return an error for empty app name")
		assert.Contains(t, err.Error(), "app name is empty", "Error message should mention empty app name")
	})

	t.Run("Whitespace app name", func(t *testing.T) {
		_, err := generator.GenerateKeyURL("test@example.com", "   ")

		require.Error(t, err, "GenerateKeyURL should return an error for whitespace app name")
		assert.Contains(t, err.Error(), "app name is empty", "Error message should mention empty app name")
	})

	t.Run("Different output for different inputs", func(t *testing.T) {
		url1, err1 := generator.GenerateKeyURL("test1@example.com", "TestApp1")
		require.NoError(t, err1)

		url2, err2 := generator.GenerateKeyURL("test2@example.com", "TestApp2")
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
			// The longest address an account holds, 254 characters (#632).
			email := fake.LetterN(64) + "@" + strings.Repeat("d", 185) + ".com"
			require.Len(t, email, 254)
			appName := fake.LetterN(32)

			keyURL, err := generator.GenerateKeyURL(email, appName)

			require.NoError(t, err, "GenerateKeyURL should not return an error for maximum valid lengths")
			assert.NotEmpty(t, keyURL, "the otpauth URL should not be empty for maximum valid lengths")

			secret, err := SecretFromKeyURL(keyURL)
			require.NoError(t, err)
			assert.NotEmpty(t, secret, "Secret key should not be empty for maximum valid lengths")

			// The QR code still fits the image the enrolling user scans.
			image, err := RenderQRCodeImage(keyURL)
			require.NoError(t, err)
			assert.NotEmpty(t, image)
		})

		t.Run("Email too long", func(t *testing.T) {
			longEmail := fake.LetterN(64) + "@" + strings.Repeat("d", 186) + ".com"
			require.Len(t, longEmail, 255)
			appName := "TestApp"

			_, err := generator.GenerateKeyURL(longEmail, appName)

			require.Error(t, err, "GenerateKeyURL should return an error for email longer than 254 characters")
			assert.Contains(t, err.Error(), "email is too long", "Error message should mention email is too long")
		})

		t.Run("App name too long", func(t *testing.T) {
			email := "test@example.com"
			longAppName := strings.Repeat("b", 33) // 33 characters

			_, err := generator.GenerateKeyURL(email, longAppName)

			require.Error(t, err, "GenerateKeyURL should return an error for app name longer than 32 characters")
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
	generator := NewKeyGenerator()

	cases := []struct{ appName, email string }{
		{"Goiabada", "a@b.co"},
		{"Goiabada", "someuser@example.com"},
		{"A Long App Name", "a-long-address-inside-the-cap@example.com"},
		{"Acme Ltd & Co", "user+tag@example.com"},
	}

	for _, c := range cases {
		t.Run(c.appName+" / "+c.email, func(t *testing.T) {
			keyURL, err := generator.GenerateKeyURL(c.email, c.appName)
			require.NoError(t, err)

			secret, err := SecretFromKeyURL(keyURL)
			require.NoError(t, err)
			require.NotEmpty(t, secret)

			// A code an authenticator produces from the URL it scanned validates against the
			// secret this package hands the verifier. That is the whole claim: the two are
			// the same key. The code comes from otptest, a second implementation, so the
			// verifier is not checked against itself.
			now := pinnedNow()
			step, match := MatchStep(otptest.Code(t, secret, now), secret, now)
			assert.Equal(t, Matched, match, "a code from the URL's secret must validate against it")
			assert.Equal(t, pinnedStep, step, "and name the step it was shown in")

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

// Every case below but the blank ones is one url.Parse accepts, and so was one pquerna/otp's
// NewKeyFromURL accepted, since it checked nothing more. Without these refusals a caller would
// verify passcodes against an empty secret and render a QR code that enrols an authenticator in
// nothing (#247).
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
			_, err := SecretFromKeyURL(c.keyURL)
			require.Error(t, err, "SecretFromKeyURL must refuse %q", c.keyURL)

			_, err = RenderQRCodeImage(c.keyURL)
			assert.Error(t, err, "RenderQRCodeImage must refuse %q", c.keyURL)
		})
	}
}

// An App name of thirty characters, the most the settings take, enrols whatever its script: the
// generator counts characters as the settings do. Counted in bytes, its own bound of 32 refused a
// thirty-character accented name the settings page had accepted, and two-factor enrolment failed.
func TestGenerateKeyURL_AnAccentedAppNameAtTheSettingsBoundEnrols(t *testing.T) {
	keyURL, err := NewKeyGenerator().GenerateKeyURL("josé@example.com", strings.Repeat("é", 30))
	require.NoError(t, err)
	assert.NotEmpty(t, keyURL)
}

// mintedSecretBytes is what the generator reads from its source of randomness in the tests that
// pin a whole URL: RFC 4226's key, whose unpadded base32 is mintedSecret.
const (
	mintedSecretBytes = "12345678901234567890"
	mintedSecret      = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
)

func generatorMinting(secretBytes string) *KeyGenerator {
	return &KeyGenerator{random: strings.NewReader(secretBytes)}
}

// The whole URL for a fixed secret, as literal strings. The unchanged rows are what pquerna/otp
// v1.5.0 wrote for the same App name, email and secret, captured from it, so an ordinary name
// enrols byte-identical to before. The changed rows are written by hand from the rule (#646
// decision 1): the issuer parameter percent-encodes every character outside RFC 3986's unreserved
// set, where the library left "$ & + : = @" bare, and an App name holding a colon leaves the label
// to the email alone, since the Key URI Format allows a label of the account name and forbids a
// colon in the issuer part of one.
func TestGenerateKeyURL_WritesTheKeyURIFormat(t *testing.T) {
	cases := []struct {
		name, appName, email, want string
	}{
		{
			name: "ordinary name, unchanged", appName: "Goiabada", email: "a@b.co",
			want: "otpauth://totp/Goiabada:a@b.co?algorithm=SHA1&digits=6&issuer=Goiabada&period=30&secret=" + mintedSecret,
		},
		{
			name: "spaces, unchanged", appName: "A Long App Name", email: "someuser@example.com",
			want: "otpauth://totp/A%20Long%20App%20Name:someuser@example.com?algorithm=SHA1&digits=6&issuer=A%20Long%20App%20Name&period=30&secret=" + mintedSecret,
		},
		{
			name: "accented name and email, unchanged", appName: "São Paulo Auth", email: "josé@example.com",
			want: "otpauth://totp/S%C3%A3o%20Paulo%20Auth:jos%C3%A9@example.com?algorithm=SHA1&digits=6&issuer=S%C3%A3o%20Paulo%20Auth&period=30&secret=" + mintedSecret,
		},
		{
			name: "email punctuation, unchanged", appName: "Goiabada", email: "o'brien+tag!*()~@example.com",
			want: "otpauth://totp/Goiabada:o%27brien+tag%21%2A%28%29~@example.com?algorithm=SHA1&digits=6&issuer=Goiabada&period=30&secret=" + mintedSecret,
		},
		{
			name: "dollar sign", appName: "A$B", email: "x@y.z",
			want: "otpauth://totp/A$B:x@y.z?algorithm=SHA1&digits=6&issuer=A%24B&period=30&secret=" + mintedSecret,
		},
		{
			name: "ampersand", appName: "Acme Ltd & Co", email: "user+tag@example.com",
			want: "otpauth://totp/Acme%20Ltd%20&%20Co:user+tag@example.com?algorithm=SHA1&digits=6&issuer=Acme%20Ltd%20%26%20Co&period=30&secret=" + mintedSecret,
		},
		{
			name: "plus sign", appName: "A+B", email: "x@y.z",
			want: "otpauth://totp/A+B:x@y.z?algorithm=SHA1&digits=6&issuer=A%2BB&period=30&secret=" + mintedSecret,
		},
		{
			name: "colon, so the label is the email alone", appName: "A:B", email: "x@y.z",
			want: "otpauth://totp/x@y.z?algorithm=SHA1&digits=6&issuer=A%3AB&period=30&secret=" + mintedSecret,
		},
		{
			name: "equals sign", appName: "A=B", email: "x@y.z",
			want: "otpauth://totp/A=B:x@y.z?algorithm=SHA1&digits=6&issuer=A%3DB&period=30&secret=" + mintedSecret,
		},
		{
			name: "at sign", appName: "A@B", email: "x@y.z",
			want: "otpauth://totp/A@B:x@y.z?algorithm=SHA1&digits=6&issuer=A%40B&period=30&secret=" + mintedSecret,
		},
		{
			name: "the unreserved punctuation stays bare", appName: "a-b.c_d~e", email: "x@y.z",
			want: "otpauth://totp/a-b.c_d~e:x@y.z?algorithm=SHA1&digits=6&issuer=a-b.c_d~e&period=30&secret=" + mintedSecret,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keyURL, err := generatorMinting(mintedSecretBytes).GenerateKeyURL(c.email, c.appName)
			require.NoError(t, err)
			assert.Equal(t, c.want, keyURL)

			// What an authenticator reads back is what was given: the App name as its title,
			// whole, and the minted secret.
			parsed, err := url.Parse(keyURL)
			require.NoError(t, err)
			assert.Equal(t, []string{c.appName}, parsed.Query()["issuer"])
			assert.Equal(t, []string{mintedSecret}, parsed.Query()["secret"])
		})
	}
}

// An App name can no longer choose the secret. pquerna/otp wrote this name into the issuer
// parameter bare, so the URL carried two secrets, the name's first, and the server verified every
// new enrolment against the name's (#646, probe injection).
func TestGenerateKeyURL_AnAppNameCannotChooseTheSecret(t *testing.T) {
	keyURL, err := generatorMinting(mintedSecretBytes).GenerateKeyURL("a@b.co", "x&secret=JBSWY3DPEHPK3PXP")
	require.NoError(t, err)

	assert.Equal(t,
		"otpauth://totp/x&secret=JBSWY3DPEHPK3PXP:a@b.co?algorithm=SHA1&digits=6&issuer=x%26secret%3DJBSWY3DPEHPK3PXP&period=30&secret="+mintedSecret,
		keyURL)

	parsed, err := url.Parse(keyURL)
	require.NoError(t, err)
	assert.Equal(t, []string{mintedSecret}, parsed.Query()["secret"], "exactly one secret, the minted one")

	secret, err := SecretFromKeyURL(keyURL)
	require.NoError(t, err)
	assert.Equal(t, mintedSecret, secret)
}

// Each mint draws its own 20 bytes.
func TestGenerateKeyURL_MintsADifferentSecretEachTime(t *testing.T) {
	generator := NewKeyGenerator()
	seen := map[string]bool{}
	for range 8 {
		keyURL, err := generator.GenerateKeyURL("a@b.co", "Goiabada")
		require.NoError(t, err)
		secret, err := SecretFromKeyURL(keyURL)
		require.NoError(t, err)
		assert.Len(t, secret, 32)
		assert.False(t, seen[secret], "secret %s minted twice", secret)
		seen[secret] = true
	}
}

// A source of randomness that runs out is an error, never a key made of whatever was read.
func TestGenerateKeyURL_ARandomSourceThatRunsOutIsAnError(t *testing.T) {
	_, err := generatorMinting("too short").GenerateKeyURL("a@b.co", "Goiabada")
	assert.Error(t, err)
}

// URLs pquerna/otp v1.5.0 wrote, as literal inputs: every enrolment in flight across the upgrade
// carries one, so each must read back the secret it read back before. That includes the URLs the
// library's defect wrote, which still read as they did: the truncated issuer of an "&" name, the
// split label of a colon name, and the double secret of probe injection, whose first secret wins
// as it did, since changing it would change the key of an enrolment the user is midway through.
func TestSecretFromKeyURL_ReadsURLsTheLibraryWrote(t *testing.T) {
	cases := []struct{ name, keyURL, secret string }{
		{
			"ordinary",
			"otpauth://totp/Goiabada:a@b.co?algorithm=SHA1&digits=6&issuer=Goiabada&period=30&secret=JYPXKV26OJFVNKSDS25PL5GIENRKFYW2",
			"JYPXKV26OJFVNKSDS25PL5GIENRKFYW2",
		},
		{
			"surrounding whitespace, which the library trimmed",
			" otpauth://totp/Goiabada:a@b.co?algorithm=SHA1&digits=6&issuer=Goiabada&period=30&secret=JYPXKV26OJFVNKSDS25PL5GIENRKFYW2\n",
			"JYPXKV26OJFVNKSDS25PL5GIENRKFYW2",
		},
		{
			"an ampersand left bare",
			"otpauth://totp/Acme%20Ltd%20&%20Co:user+tag@example.com?algorithm=SHA1&digits=6&issuer=Acme%20Ltd%20&%20Co&period=30&secret=WNMN74PLIQHZ3M5HZSY4FKOH727LSK5V",
			"WNMN74PLIQHZ3M5HZSY4FKOH727LSK5V",
		},
		{
			"a plus sign left bare",
			"otpauth://totp/A+B:x@y.z?algorithm=SHA1&digits=6&issuer=A+B&period=30&secret=L5Y3Y32YSMFPMAEGNBAHAE4PAML2ASCE",
			"L5Y3Y32YSMFPMAEGNBAHAE4PAML2ASCE",
		},
		{
			"a colon in the label",
			"otpauth://totp/A:B:x@y.z?algorithm=SHA1&digits=6&issuer=A:B&period=30&secret=VAQDEKUBKDEPCXJAIARAOREDQAFITJYB",
			"VAQDEKUBKDEPCXJAIARAOREDQAFITJYB",
		},
		{
			"two secrets, the first winning",
			"otpauth://totp/x&secret=JBSWY3DPEHPK3PXP:a@b.co?algorithm=SHA1&digits=6&issuer=x&secret=JBSWY3DPEHPK3PXP&period=30&secret=C7KGFHV6EEWIMQ47AULSHZUVB7LES57E",
			"JBSWY3DPEHPK3PXP",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			secret, err := SecretFromKeyURL(c.keyURL)
			require.NoError(t, err)
			assert.Equal(t, c.secret, secret)

			image, err := RenderQRCodeImage(c.keyURL)
			require.NoError(t, err)
			assert.NotEmpty(t, image)
		})
	}
}

// The QR code for a URL is the image pquerna/otp v1.5.0 drew for it: error correction M,
// automatic mode, scaled to 180 by 180. Each golden in testdata is the library's own PNG, written
// by its Key.Image and image/png before it left the module, so the expected pixels are its answer
// and not this package's. Pixels are compared after decoding rather than PNG bytes, so a Go release
// that compresses differently does not fail this.
func TestRenderQRCodeImage_DrawsWhatTheLibraryDrew(t *testing.T) {
	cases := []struct{ name, keyURL, golden string }{
		{
			"a URL as minted",
			"otpauth://totp/Goiabada:a@b.co?algorithm=SHA1&digits=6&issuer=Goiabada&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			"qr_goiabada.png",
		},
		{
			// The library encoded the URL trimmed, so surrounding whitespace changes nothing.
			"the same URL with surrounding whitespace",
			"  otpauth://totp/Goiabada:a@b.co?algorithm=SHA1&digits=6&issuer=Goiabada&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n",
			"qr_goiabada.png",
		},
		{
			// A URL only the library wrote, which a pending enrolment can still hold: its stored
			// text is what is drawn, double secret and all.
			"a URL the library wrote with two secrets",
			"otpauth://totp/x&secret=JBSWY3DPEHPK3PXP:a@b.co?algorithm=SHA1&digits=6&issuer=x&secret=JBSWY3DPEHPK3PXP&period=30&secret=C7KGFHV6EEWIMQ47AULSHZUVB7LES57E",
			"qr_injection.png",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base64Image, err := RenderQRCodeImage(c.keyURL)
			require.NoError(t, err)
			decoded, err := base64.StdEncoding.DecodeString(base64Image)
			require.NoError(t, err)
			got, err := png.Decode(bytes.NewReader(decoded))
			require.NoError(t, err)

			goldenBytes, err := os.ReadFile(filepath.Join("testdata", c.golden))
			require.NoError(t, err)
			want, err := png.Decode(bytes.NewReader(goldenBytes))
			require.NoError(t, err)

			require.Equal(t, image.Rect(0, 0, qrCodePixels, qrCodePixels), want.Bounds(), "the golden")
			require.Equal(t, want.Bounds(), got.Bounds())
			differing := 0
			for y := range qrCodePixels {
				for x := range qrCodePixels {
					if grayAt(got, x, y) != grayAt(want, x, y) {
						differing++
					}
				}
			}
			assert.Zero(t, differing, "pixels differing from the library's image")
		})
	}
}

func grayAt(img image.Image, x, y int) uint8 {
	return color.GrayModel.Convert(img.At(x, y)).(color.Gray).Y
}
