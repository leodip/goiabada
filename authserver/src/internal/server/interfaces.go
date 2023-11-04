package server

import (
	"context"

	core_authorize "github.com/leodip/goiabada/internal/core/authorize"
	core_senders "github.com/leodip/goiabada/internal/core/senders"
	core_validators "github.com/leodip/goiabada/internal/core/validators"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
)

type otpSecretGenerator interface {
	GenerateOTPSecret(user *entities.User, settings *entities.Settings) (string, string, error)
}

type tokenIssuer interface {
	GenerateTokenForAuthCode(ctx context.Context, code *entities.Code, keyPair *entities.KeyPair,
		baseUrl string) (*dtos.TokenResponse, error)
	GenerateTokenForClientCred(ctx context.Context, client *entities.Client,
		scope string, keyPair *entities.KeyPair) (*dtos.TokenResponse, error)
}

type authorizeValidator interface {
	ValidateScopes(ctx context.Context, scope string) error
	ValidateClientAndRedirectURI(ctx context.Context, input *core_validators.ValidateClientAndRedirectURIInput) error
	ValidateRequest(ctx context.Context, input *core_validators.ValidateRequestInput) error
}

type codeIssuer interface {
	CreateAuthCode(ctx context.Context, input *core_authorize.CreateCodeInput) (*entities.Code, error)
}

type loginManager interface {
	HasValidUserSession(ctx context.Context, userSession *entities.UserSession, requestedMaxAgeInSeconds *int) bool

	MustPerformOTPAuth(ctx context.Context, client *entities.Client, userSession *entities.UserSession,
		targetAcrLevel enums.AcrLevel) bool
}

type tokenValidator interface {
	ValidateTokenRequest(ctx context.Context, input *core_validators.ValidateTokenRequestInput) (*core_validators.ValidateTokenRequestResult, error)
	ValidateJwtSignature(ctx context.Context, tokenResponse *dtos.TokenResponse) (*dtos.JwtInfo, error)
}

type profileValidator interface {
	ValidateName(ctx context.Context, name string, nameField string) error
	ValidateProfile(ctx context.Context, input *core_validators.ValidateProfileInput) error
}

type emailValidator interface {
	ValidateEmailAddress(ctx context.Context, emailAddress string) error
	ValidateEmailUpdate(ctx context.Context, input *core_validators.ValidateEmailInput) error
}

type emailSender interface {
	SendEmail(ctx context.Context, input *core_senders.SendEmailInput) error
}

type addressValidator interface {
	ValidateAddress(ctx context.Context, input *core_validators.ValidateAddressInput) error
}

type phoneValidator interface {
	ValidatePhone(ctx context.Context, input *core_validators.ValidatePhoneInput) error
}

type smsSender interface {
	SendSMS(ctx context.Context, input *core_senders.SendSMSInput) error
}

type passwordValidator interface {
	ValidatePassword(ctx context.Context, password string) error
}

type identifierValidator interface {
	ValidateIdentifier(identifier string, enforceMinLength bool) error
}

type inputSanitizer interface {
	Sanitize(str string) string
}
