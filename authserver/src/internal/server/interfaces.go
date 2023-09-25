package server

import (
	"context"

	core "github.com/leodip/goiabada/internal/core"
	core_authorize "github.com/leodip/goiabada/internal/core/authorize"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
)

type otpSecretGenerator interface {
	GenerateOTPSecret(user *entities.User, branding *entities.Branding) (string, string, error)
}

type tokenIssuer interface {
	GenerateTokenForAuthCode(ctx context.Context, code *entities.Code, keyPair *entities.KeyPair) (*dtos.TokenResponse, error)
	GenerateTokenForClientCred(ctx context.Context, client *entities.Client,
		scope string, keyPair *entities.KeyPair) (*dtos.TokenResponse, error)
}

type authorizeValidator interface {
	ValidateScopes(ctx context.Context, scope string, user *entities.User) error
	ValidateClientAndRedirectUri(ctx context.Context, input *core_authorize.ValidateClientAndRedirectUriInput) error
	ValidateRequest(ctx context.Context, input *core_authorize.ValidateRequestInput) error
}

type codeIssuer interface {
	CreateAuthCode(ctx context.Context, input *core_authorize.CreateCodeInput) (*entities.Code, error)
	GetUserSessionAcrLevel(ctx context.Context, userSession *entities.UserSession) enums.AcrLevel
}

type loginManager interface {
	HasValidUserSession(ctx context.Context, userSession *entities.UserSession, requestedMaxAgeInSeconds *int) bool
	PerformFirstLevelAuth(ctx context.Context, userSession *entities.UserSession,
		requestedAcrValues []enums.AcrLevel) bool
	PerformSecondLevelAuth(ctx context.Context, userSession *entities.UserSession,
		requestedAcrValues []enums.AcrLevel) bool
}

type tokenValidator interface {
	ValidateScopes(ctx context.Context, scope string, clientIdentifier string) error
	ValidateJwtSignature(ctx context.Context, tokenResponse *dtos.TokenResponse) (*dtos.JwtInfo, error)
}

type profileValidator interface {
	ValidateProfile(ctx context.Context, accountProfile *dtos.AccountProfile) error
}

type emailValidator interface {
	ValidateEmail(ctx context.Context, accountEmail *dtos.AccountEmail) error
}

type emailSender interface {
	SendEmail(ctx context.Context, input *core.SendEmailInput) error
}

type addressValidator interface {
	ValidateAddress(ctx context.Context, accountAddress *dtos.AccountAddress) error
}

type phoneValidator interface {
	ValidatePhone(ctx context.Context, accountPhone *dtos.AccountPhone) error
}

type smsSender interface {
	SendSMS(ctx context.Context, input *core.SendSMSInput) error
}
