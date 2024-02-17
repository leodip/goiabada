package server

import (
	"context"

	"github.com/leodip/goiabada/internal/core"
	core_authorize "github.com/leodip/goiabada/internal/core/authorize"
	core_senders "github.com/leodip/goiabada/internal/core/senders"
	core_token "github.com/leodip/goiabada/internal/core/token"
	core_validators "github.com/leodip/goiabada/internal/core/validators"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/enums"
)

type otpSecretGenerator interface {
	GenerateOTPSecret(user *entitiesv2.User, settings *entitiesv2.Settings) (string, string, error)
}

type tokenIssuer interface {
	GenerateTokenResponseForAuthCode(ctx context.Context, input *core_token.GenerateTokenResponseForAuthCodeInput) (*dtos.TokenResponse, error)
	GenerateTokenResponseForClientCred(ctx context.Context, client *entitiesv2.Client, scope string) (*dtos.TokenResponse, error)
	GenerateTokenResponseForRefresh(ctx context.Context, input *core_token.GenerateTokenForRefreshInput) (*dtos.TokenResponse, error)
}

type authorizeValidator interface {
	ValidateScopes(ctx context.Context, scope string) error
	ValidateClientAndRedirectURI(ctx context.Context, input *core_validators.ValidateClientAndRedirectURIInput) error
	ValidateRequest(ctx context.Context, input *core_validators.ValidateRequestInput) error
}

type codeIssuer interface {
	CreateAuthCode(ctx context.Context, input *core_authorize.CreateCodeInput) (*entitiesv2.Code, error)
}

type loginManager interface {
	HasValidUserSession(ctx context.Context, userSession *entitiesv2.UserSession, requestedMaxAgeInSeconds *int) bool

	MustPerformOTPAuth(ctx context.Context, client *entitiesv2.Client, userSession *entitiesv2.UserSession,
		targetAcrLevel enums.AcrLevel) bool
}

type tokenValidator interface {
	ValidateTokenRequest(ctx context.Context, input *core_validators.ValidateTokenRequestInput) (*core_validators.ValidateTokenRequestResult, error)
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

type userCreator interface {
	CreateUser(ctx context.Context, input *core.CreateUserInput) (*entitiesv2.User, error)
}
