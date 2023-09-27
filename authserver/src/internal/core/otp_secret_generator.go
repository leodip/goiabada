package core

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"net/http"

	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/pquerna/otp/totp"
)

type OTPSecretGenerator struct {
}

func NewOTPSecretGenerator() *OTPSecretGenerator {
	return &OTPSecretGenerator{}
}

func (g *OTPSecretGenerator) GenerateOTPSecret(user *entities.User, settings *entities.Settings) (string, string, error) {

	// returns: base64 of QR code image, secret key

	if user != nil {
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      settings.AppName,
			AccountName: user.Username,
		})
		if err != nil {
			return "", "", customerrors.NewAppError(err, "", fmt.Sprintf("unable to generate totp for user Id %v: %v", user.ID, err.Error()), http.StatusInternalServerError)
		}

		var buf bytes.Buffer
		img, err := key.Image(180, 180)
		if err != nil {
			return "", "", customerrors.NewAppError(err, "", fmt.Sprintf("unable to generate totp PNG image for user Id %v: %v", user.ID, err.Error()), http.StatusInternalServerError)
		}
		png.Encode(&buf, img)
		base64Str := base64.StdEncoding.EncodeToString(buf.Bytes())
		return base64Str, key.Secret(), nil
	}
	return "", "", customerrors.NewAppError(nil, "", "unable to generate the OTP secret because the user is nil", http.StatusInternalServerError)
}
