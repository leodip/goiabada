package otp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"strings"

	"github.com/pkg/errors"
	pquernaotp "github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// qrCodePixels is the width and height of the QR code image an enrolling user scans.
const qrCodePixels = 180

type OTPSecretGenerator struct {
}

func NewOTPSecretGenerator() *OTPSecretGenerator {
	return &OTPSecretGenerator{}
}

// GenerateOTPSecret creates a new TOTP key for a user and returns its otpauth:// URL.
//
// The URL is the library's own canonical serialization of the whole key, carrying the secret
// alongside algorithm=SHA1, digits=6 and period=30 explicitly, so nothing about the key has to
// be inferred by whoever reads it back. SecretFromKeyURL and RenderQRCodeImage are its inverses:
// callers derive the base32 secret and the QR image from it rather than being handed either, so
// there is one value to carry and no second copy that could disagree with it.
//
// Returning the URL instead of a rendered PNG is what keeps an enrolment out of the browser's
// cookie budget: the URL is about 150 bytes against roughly 2.4 KB of base64 image, which is an
// entire cookie chunk and about 5 KB on every request for the duration of the enrolment (#247).
func (g *OTPSecretGenerator) GenerateOTPSecret(email string, appName string) (string, error) {

	if strings.TrimSpace(email) == "" {
		return "", errors.New("email is empty")
	}

	if strings.TrimSpace(appName) == "" {
		return "", errors.New("app name is empty")
	}

	if len(email) > 64 {
		return "", errors.New("email is too long")
	}

	if len(appName) > 32 {
		return "", errors.New("app name is too long")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      appName,
		AccountName: email,
	})
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("unable to generate otp for user %v", email))
	}

	return key.URL(), nil
}

// SecretFromKeyURL returns the base32 TOTP secret carried by an otpauth:// URL, the value
// MatchStep verifies a passcode against and User.SetOTPSecret stores.
func SecretFromKeyURL(keyURL string) (string, error) {
	key, err := parseKeyURL(keyURL)
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}

// RenderQRCodeImage renders the QR code an enrolling user scans, as a base64 PNG, from an
// otpauth:// URL. It is byte-identical to the image the key it came from would have produced.
func RenderQRCodeImage(keyURL string) (string, error) {
	key, err := parseKeyURL(keyURL)
	if err != nil {
		return "", err
	}

	img, err := key.Image(qrCodePixels, qrCodePixels)
	if err != nil {
		return "", errors.Wrap(err, "unable to generate otp png image")
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", errors.Wrap(err, "unable to encode otp png image")
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// parseKeyURL turns an otpauth:// URL back into a key, and is the only place that decides
// whether a stored URL is usable at all.
//
// The checks below are this package's rather than the library's, because otp.NewKeyFromURL
// performs none: it runs url.Parse and keeps whatever comes back, so it accepts the empty
// string and every other non-URL, and the *Key it returns then answers Secret() with "" and
// renders a scannable QR code of nothing. A caller trusting it would verify passcodes against
// an empty secret and show the user a QR code that enrols them in nothing (#247).
func parseKeyURL(keyURL string) (*pquernaotp.Key, error) {
	if strings.TrimSpace(keyURL) == "" {
		return nil, errors.New("otp key url is empty")
	}

	key, err := pquernaotp.NewKeyFromURL(keyURL)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse otp key url")
	}

	if key.Type() != "totp" {
		return nil, errors.New("otp key url is not a totp key")
	}

	if key.Secret() == "" {
		return nil, errors.New("otp key url carries no secret")
	}

	return key, nil
}
