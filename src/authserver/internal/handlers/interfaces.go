package handlers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"net/http"

	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/users"

	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/validators"
)

type HttpHelper interface {
	InternalServerError(w http.ResponseWriter, r *http.Request, err error)
	RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) error
	RenderTemplateToBuffer(r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) (*bytes.Buffer, error)
	JsonError(w http.ResponseWriter, r *http.Request, err error)
	EncodeJson(w http.ResponseWriter, r *http.Request, data interface{})
	GetFromUrlQueryOrFormPost(r *http.Request, key string) string
}

type AuthHelper interface {
	GetAuthContext(r *http.Request) (*oauth.AuthContext, error)
	SaveAuthContext(w http.ResponseWriter, r *http.Request, authContext *oauth.AuthContext) error
	ClearAuthContext(w http.ResponseWriter, r *http.Request) error
	GetLoggedInSubject(r *http.Request) string
}

type OtpSecretGenerator interface {
	GenerateOTPSecret(email string, appName string) (string, string, error)
}

type TokenIssuer interface {
	GenerateTokenResponseForAuthCode(ctx context.Context, code *models.Code) (*oauth.TokenResponse, error)
	GenerateTokenResponseForClientCred(ctx context.Context, client *models.Client, scope string) (*oauth.TokenResponse, error)
	GenerateTokenResponseForRefresh(ctx context.Context, input *oauth.GenerateTokenForRefreshInput) (*oauth.TokenResponse, error)
}

type AuthorizeValidator interface {
	ValidateScopes(ctx context.Context, scope string) error
	ValidateClientAndRedirectURI(ctx context.Context, input *validators.ValidateClientAndRedirectURIInput) error
	ValidateRequest(ctx context.Context, input *validators.ValidateRequestInput) error
}

type CodeIssuer interface {
	CreateAuthCode(ctx context.Context, input *oauth.CreateCodeInput) (*models.Code, error)
}

type UserSessionManager interface {
	HasValidUserSession(ctx context.Context, userSession *models.UserSession, requestedMaxAgeInSeconds *int) bool
	RequiresOTPAuth(ctx context.Context, client *models.Client, userSession *models.UserSession,
		targetAcrLevel enums.AcrLevel) bool
	StartNewUserSession(w http.ResponseWriter, r *http.Request,
		userId int64, clientId int64, authMethods string, acrLevel string) (*models.UserSession, error)
	BumpUserSession(r *http.Request, sessionIdentifier string, clientId int64) (*models.UserSession, error)
}

type TokenValidator interface {
	ValidateTokenRequest(ctx context.Context, input *validators.ValidateTokenRequestInput) (*validators.ValidateTokenRequestResult, error)
}

type InputSanitizer interface {
	Sanitize(str string) string
}

type UserCreator interface {
	CreateUser(input *users.CreateUserInput) (*models.User, error)
}

type TokenParser interface {
	DecodeAndValidateTokenString(ctx context.Context, token string, pubKey *rsa.PublicKey) (*oauth.JwtToken, error)
	DecodeAndValidateTokenResponse(ctx context.Context, tokenResponse *oauth.TokenResponse) (*oauth.JwtInfo, error)
}

type EmailValidator interface {
	ValidateEmailAddress(emailAddress string) error
}

type PasswordValidator interface {
	ValidatePassword(ctx context.Context, password string) error
}

type EmailSender interface {
	SendEmail(ctx context.Context, input *communication.SendEmailInput) error
}

type AuditLogger interface {
	Log(auditEvent string, details map[string]interface{})
}

type PermissionChecker interface {
	UserHasScopePermission(userId int64, scope string) (bool, error)
}
