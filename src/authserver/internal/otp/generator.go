package otp

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"image/png"
	"io"
	"net/url"
	"strings"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/inputvalidation"
)

// qrCodePixels is the width and height of the QR code image an enrolling user scans.
const qrCodePixels = 180

// secretBytes is the length of a minted secret, the 160 bits RFC 4226 section 4 (R6) recommends.
const secretBytes = 20

// unpaddedBase32 writes a secret as the Key URI Format asks, its "=" padding omitted.
var unpaddedBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

type KeyGenerator struct {
	// random is where a secret's bytes come from: crypto/rand when nil, which every production
	// generator is, and a fixed reader in the tests that pin a whole URL.
	random io.Reader
}

func NewKeyGenerator() *KeyGenerator {
	return &KeyGenerator{}
}

// GenerateKeyURL creates a new TOTP key for a user and returns its otpauth:// URL.
//
// The URL is the whole key, carrying the secret alongside algorithm=SHA1, digits=6 and
// period=30 explicitly, so nothing about the key has to be inferred by whoever reads it back.
// SecretFromKeyURL and RenderQRCodeImage are its inverses: callers derive the base32 secret and
// the QR image from it rather than being handed either, so there is one value to carry and no
// second copy that could disagree with it.
//
// Returning the URL instead of a rendered PNG is what keeps an enrolment cheap to carry: the URL
// is about 150 bytes against roughly 2.4 KB of base64 image. That was an entire cookie chunk and
// about 5 KB on the wire per request while the session lived in the browser; since it became a
// database row it is the same 2.4 KB written and read on every save for the duration of the
// enrolment, so the saving moved rather than went away (#247, #266).
func (g *KeyGenerator) GenerateKeyURL(email string, appName string) (string, error) {

	if strings.TrimSpace(email) == "" {
		return "", errs.New("email is empty")
	}

	if strings.TrimSpace(appName) == "" {
		return "", errs.New("app name is empty")
	}

	// The longest address an account holds, so every account can enrol (#632).
	if inputvalidation.TextLength(email) > accountvalidation.MaxEmailLength {
		return "", errs.New("email is too long")
	}

	if inputvalidation.TextLength(appName) > 32 {
		return "", errs.New("app name is too long")
	}

	random := g.random
	if random == nil {
		random = rand.Reader
	}
	secret := make([]byte, secretBytes)
	if _, err := io.ReadFull(random, secret); err != nil {
		return "", errs.Wrap(err, "unable to mint an otp secret")
	}

	return keyURL(email, appName, unpaddedBase32.EncodeToString(secret)), nil
}

// keyURL writes a key in the Key URI Format, byte-identical to what pquerna/otp v1.5.0 wrote for
// every App name but those carrying "$ & + : = @" (#646 decision 1).
//
// The label is the App name and the email joined by a colon, escaped as a URL path, as the library
// escaped it. An App name holding a colon leaves the label to the email alone: the format forbids a
// colon in either part, and allows a label of the account name by itself, and an authenticator
// splitting "A:B:x@y.z" at its first colon shows the account as "B:x@y.z". The App name still
// reaches the authenticator whole, in the issuer parameter.
//
// The parameters are in the library's order, algorithm, digits, issuer, period, secret, with the
// fixed values written out. The issuer is percent-encoded per RFC 3986, every character outside
// the unreserved set encoded and a space as %20, as the format requires. The library escaped it as
// a path segment, which leaves "$ & + : = @" bare: "&" cut the title short, "+" read back as a
// space, and an App name of "x&secret=..." put a second secret ahead of the minted one, which the
// server then verified every new enrolment against.
func keyURL(email string, appName string, secret string) string {
	label := appName + ":" + email
	if strings.Contains(appName, ":") {
		label = email
	}
	path := (&url.URL{Path: "/" + label}).EscapedPath()

	return "otpauth://totp" + path +
		"?algorithm=SHA1&digits=6&issuer=" + escapeUnreserved(appName) +
		"&period=30&secret=" + secret
}

// escapeUnreserved percent-encodes every byte of s outside RFC 3986's unreserved set (section
// 2.3: letters, digits, "-", ".", "_" and "~"), in upper-case hex as section 2.1 recommends.
func escapeUnreserved(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0f])
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// SecretFromKeyURL returns the base32 TOTP secret carried by an otpauth:// URL, the value
// MatchStep verifies a passcode against and otpcredential.Establish stores.
func SecretFromKeyURL(keyURL string) (string, error) {
	_, secret, err := parseKeyURL(keyURL)
	if err != nil {
		return "", err
	}
	return secret, nil
}

// RenderQRCodeImage renders the QR code an enrolling user scans, as a base64 PNG, from an
// otpauth:// URL: error correction M, automatic mode, 180 by 180. It encodes the URL's text as
// given, trimmed, so a stored URL draws the image pquerna/otp drew for it.
func RenderQRCodeImage(keyURL string) (string, error) {
	text, _, err := parseKeyURL(keyURL)
	if err != nil {
		return "", err
	}

	img, err := drawQRCode(text)
	if err != nil {
		return "", errs.Wrap(err, "unable to generate otp png image")
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", errs.Wrap(err, "unable to encode otp png image")
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// drawQRCode is what pquerna/otp's Key.Image did: encode, then scale to the image's size.
func drawQRCode(text string) (barcode.Barcode, error) {
	code, err := qr.Encode(text, qr.M, qr.Auto)
	if err != nil {
		return nil, err
	}
	return barcode.Scale(code, qrCodePixels, qrCodePixels)
}

// parseKeyURL reads an otpauth:// URL back, returning its trimmed text and its secret, and is the
// only place that decides whether a stored URL is usable at all.
//
// It refuses exactly what was refused while pquerna/otp read the URL, and reads it as the library
// did: trimmed, through url.Parse, the key type the host, the secret the first "secret" query
// parameter. url.Parse accepts the empty string and most other non-URLs, so without the checks
// below a caller would verify passcodes against an empty secret and show the user a QR code that
// enrols them in nothing (#247). The algorithm, digits and period parameters are not read: every
// URL ever stored or held in a session says SHA1, 6 and 30, which is the profile MatchStep checks.
func parseKeyURL(keyURL string) (text string, secret string, err error) {
	text = strings.TrimSpace(keyURL)
	if text == "" {
		return "", "", errs.New("otp key url is empty")
	}

	parsed, err := url.Parse(text)
	if err != nil {
		return "", "", errs.Wrap(err, "unable to parse otp key url")
	}

	if parsed.Host != "totp" {
		return "", "", errs.New("otp key url is not a totp key")
	}

	secret = parsed.Query().Get("secret")
	if secret == "" {
		return "", "", errs.New("otp key url carries no secret")
	}

	return text, secret, nil
}
