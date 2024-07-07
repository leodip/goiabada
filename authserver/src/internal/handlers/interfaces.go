package handlers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"net/http"

	"github.com/leodip/goiabada/internal/models"
	"github.com/leodip/goiabada/internal/security"
	"github.com/leodip/goiabada/internal/users"

	"github.com/leodip/goiabada/internal/communication"

	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/validators"
)

type HttpHelper interface {
	InternalServerError(w http.ResponseWriter, r *http.Request, err error)
	RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) error
	RenderTemplateToBuffer(r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) (*bytes.Buffer, error)
	JsonError(w http.ResponseWriter, r *http.Request, err error)
}

type AuthHelper interface {
	GetLoggedInSubject(r *http.Request) string
	GetAuthContext(r *http.Request) (*security.AuthContext, error)
	SaveAuthContext(w http.ResponseWriter, r *http.Request, authContext *security.AuthContext) error
	ClearAuthContext(w http.ResponseWriter, r *http.Request) error
}

type OtpSecretGenerator interface {
	GenerateOTPSecret(email string, appName string) (string, string, error)
}

type TokenIssuer interface {
	GenerateTokenResponseForAuthCode(ctx context.Context, code *models.Code) (*security.TokenResponse, error)
	GenerateTokenResponseForClientCred(ctx context.Context, client *models.Client, scope string) (*security.TokenResponse, error)
	GenerateTokenResponseForRefresh(ctx context.Context, input *security.GenerateTokenForRefreshInput) (*security.TokenResponse, error)
}

type AuthorizeValidator interface {
	ValidateScopes(ctx context.Context, scope string) error
	ValidateClientAndRedirectURI(ctx context.Context, input *validators.ValidateClientAndRedirectURIInput) error
	ValidateRequest(ctx context.Context, input *validators.ValidateRequestInput) error
}

type CodeIssuer interface {
	CreateAuthCode(ctx context.Context, input *security.CreateCodeInput) (*models.Code, error)
}

type LoginManager interface {
	HasValidUserSession(ctx context.Context, userSession *models.UserSession, requestedMaxAgeInSeconds *int) bool

	MustPerformOTPAuth(ctx context.Context, client *models.Client, userSession *models.UserSession,
		targetAcrLevel enums.AcrLevel) bool
}

type TokenValidator interface {
	ValidateTokenRequest(ctx context.Context, input *validators.ValidateTokenRequestInput) (*validators.ValidateTokenRequestResult, error)
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
	DecodeAndValidateTokenString(ctx context.Context, token string, pubKey *rsa.PublicKey) (*security.JwtToken, error)
	DecodeAndValidateTokenResponse(ctx context.Context, tokenResponse *security.TokenResponse) (*security.JwtInfo, error)
}

type UserSessionHelper interface {
	StartNewUserSession(w http.ResponseWriter, r *http.Request,
		userId int64, clientId int64, authMethods string, acrLevel string) (*models.UserSession, error)
	BumpUserSession(r *http.Request, sessionIdentifier string, clientId int64) (*models.UserSession, error)
}
