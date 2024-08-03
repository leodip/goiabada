package lib

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"strings"

	"github.com/pkg/errors"
	"github.com/pquerna/otp/totp"
)

type OTPSecretGenerator struct {
}

func NewOTPSecretGenerator() *OTPSecretGenerator {
	return &OTPSecretGenerator{}
}

func (g *OTPSecretGenerator) GenerateOTPSecret(email string, appName string) (string, string, error) {

	// returns: base64 of QR code image, secret key

	if strings.TrimSpace(email) == "" {
		return "", "", errors.New("email is empty")
	}

	if strings.TrimSpace(appName) == "" {
		return "", "", errors.New("app name is empty")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      appName,
		AccountName: email,
	})
	if err != nil {
		return "", "", errors.Wrap(err, fmt.Sprintf("unable to generate otp for user %v", email))
	}

	var buf bytes.Buffer
	img, err := key.Image(180, 180)
	if err != nil {
		return "", "", errors.Wrap(err, fmt.Sprintf("unable to generate otp png image for user %v", email))
	}
	err = png.Encode(&buf, img)
	if err != nil {
		return "", "", errors.Wrap(err, fmt.Sprintf("unable to encode otp png image for user %v", email))
	}
	base64Str := base64.StdEncoding.EncodeToString(buf.Bytes())
	return base64Str, key.Secret(), nil
}
