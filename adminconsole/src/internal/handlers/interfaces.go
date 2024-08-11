package handlers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/models"
	"github.com/leodip/goiabada/adminconsole/internal/oauth"
	"github.com/leodip/goiabada/adminconsole/internal/users"

	"github.com/leodip/goiabada/adminconsole/internal/communication"

	"github.com/leodip/goiabada/adminconsole/internal/validators"
)

type HttpHelper interface {
	InternalServerError(w http.ResponseWriter, r *http.Request, err error)
	RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) error
	RenderTemplateToBuffer(r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) (*bytes.Buffer, error)
	JsonError(w http.ResponseWriter, r *http.Request, err error)
	EncodeJson(w http.ResponseWriter, r *http.Request, data interface{})
}

type AuthHelper interface {
	GetLoggedInSubject(r *http.Request) string
}

type OtpSecretGenerator interface {
	GenerateOTPSecret(email string, appName string) (string, string, error)
}

type ProfileValidator interface {
	ValidateName(ctx context.Context, name string, nameField string) error
	ValidateProfile(ctx context.Context, input *validators.ValidateProfileInput) error
}

type EmailValidator interface {
	ValidateEmailAddress(ctx context.Context, emailAddress string) error
	ValidateEmailUpdate(ctx context.Context, input *validators.ValidateEmailInput) error
}

type EmailSender interface {
	SendEmail(ctx context.Context, input *communication.SendEmailInput) error
}

type AddressValidator interface {
	ValidateAddress(ctx context.Context, input *validators.ValidateAddressInput) error
}

type PhoneValidator interface {
	ValidatePhone(ctx context.Context, input *validators.ValidatePhoneInput) error
}

type SmsSender interface {
	SendSMS(ctx context.Context, input *communication.SendSMSInput) error
}

type PasswordValidator interface {
	ValidatePassword(ctx context.Context, password string) error
}

type IdentifierValidator interface {
	ValidateIdentifier(identifier string, enforceMinLength bool) error
}

type InputSanitizer interface {
	Sanitize(str string) string
}

type UserCreator interface {
	CreateUser(ctx context.Context, input *users.CreateUserInput) (*models.User, error)
}

type TokenParser interface {
	DecodeAndValidateTokenString(ctx context.Context, token string, pubKey *rsa.PublicKey) (*oauth.JwtToken, error)
	DecodeAndValidateTokenResponse(ctx context.Context, tokenResponse *oauth.TokenResponse) (*oauth.JwtInfo, error)
}
