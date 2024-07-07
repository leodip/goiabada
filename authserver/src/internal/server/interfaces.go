package server

import (
	"context"

	"github.com/leodip/goiabada/internal/models"
	"github.com/leodip/goiabada/internal/security"
	"github.com/leodip/goiabada/internal/users"

	"github.com/leodip/goiabada/internal/communication"

	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/validators"
)

type otpSecretGenerator interface {
	GenerateOTPSecret(email string, appName string) (string, string, error)
}

type tokenIssuer interface {
	GenerateTokenResponseForAuthCode(ctx context.Context, code *models.Code) (*security.TokenResponse, error)
	GenerateTokenResponseForClientCred(ctx context.Context, client *models.Client, scope string) (*security.TokenResponse, error)
	GenerateTokenResponseForRefresh(ctx context.Context, input *security.GenerateTokenForRefreshInput) (*security.TokenResponse, error)
}

type authorizeValidator interface {
	ValidateScopes(ctx context.Context, scope string) error
	ValidateClientAndRedirectURI(ctx context.Context, input *validators.ValidateClientAndRedirectURIInput) error
	ValidateRequest(ctx context.Context, input *validators.ValidateRequestInput) error
}

type codeIssuer interface {
	CreateAuthCode(ctx context.Context, input *security.CreateCodeInput) (*models.Code, error)
}

type loginManager interface {
	HasValidUserSession(ctx context.Context, userSession *models.UserSession, requestedMaxAgeInSeconds *int) bool

	MustPerformOTPAuth(ctx context.Context, client *models.Client, userSession *models.UserSession,
		targetAcrLevel enums.AcrLevel) bool
}

type tokenValidator interface {
	ValidateTokenRequest(ctx context.Context, input *validators.ValidateTokenRequestInput) (*validators.ValidateTokenRequestResult, error)
}

type profileValidator interface {
	ValidateName(ctx context.Context, name string, nameField string) error
	ValidateProfile(ctx context.Context, input *validators.ValidateProfileInput) error
}

type emailValidator interface {
	ValidateEmailAddress(ctx context.Context, emailAddress string) error
	ValidateEmailUpdate(ctx context.Context, input *validators.ValidateEmailInput) error
}

type emailSender interface {
	SendEmail(ctx context.Context, input *communication.SendEmailInput) error
}

type addressValidator interface {
	ValidateAddress(ctx context.Context, input *validators.ValidateAddressInput) error
}

type phoneValidator interface {
	ValidatePhone(ctx context.Context, input *validators.ValidatePhoneInput) error
}

type smsSender interface {
	SendSMS(ctx context.Context, input *communication.SendSMSInput) error
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
	CreateUser(ctx context.Context, input *users.CreateUserInput) (*models.User, error)
}
