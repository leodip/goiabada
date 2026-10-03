package handlers

import (
	"bytes"
	"context"
	"net/http"
	"time"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/oauth"

	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
)

// PageRenderer and JSONWriter are the two ways a handler here answers, and a handler is handed
// exactly one of them. The token, userinfo, JWKS and discovery endpoints take JSONWriter alone, so
// an HTML error page on one of them is a compile error rather than a review finding: a client
// parsing those endpoints as JSON got an HTML 500 on 23 fault paths while one port carried both
// writers (#435). Every other handler answers pages and takes PageRenderer. The concrete
// handlerhelpers.HttpHelper satisfies both, so routes.go builds it once.
type PageRenderer interface {
	InternalServerError(w http.ResponseWriter, r *http.Request, err error)
	NotFound(w http.ResponseWriter, r *http.Request)
	RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) error
	RenderTemplateToBuffer(r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) (*bytes.Buffer, error)
}

// JSONWriter answers the JSON endpoints. JsonError writes an ErrorDetail in the RFC 6749 section
// 5.2 shape and anything else as a 500 server_error.
type JSONWriter interface {
	JsonError(w http.ResponseWriter, r *http.Request, err error)
	EncodeJson(w http.ResponseWriter, r *http.Request, data interface{})
}

// CeremonyStore is what the ceremony handlers call on ceremony.Store, which keeps the
// AuthContext in the browser session between hops. UILocales is on the concrete type and not
// here: only the locale middleware reads it, and no handler does (#435).
type CeremonyStore interface {
	GetAuthContext(r *http.Request) (*ceremony.AuthContext, error)
	SaveAuthContext(w http.ResponseWriter, r *http.Request, authContext *ceremony.AuthContext) error
	ClearAuthContext(w http.ResponseWriter, r *http.Request) error
	// RegenerateSession replaces the browser session's identifier without losing its
	// contents, which is what a server-side session store must do at every privilege
	// change to match a cookie store's structural immunity to session fixation (#266).
	RegenerateSession(w http.ResponseWriter, r *http.Request) error
}

type OtpSecretGenerator interface {
	GenerateOTPSecret(email string, appName string) (string, error)
}

// TokenIssuer redeems a validated grant at the token endpoint, one method per grant. Each owns its
// grant from the claim on what is redeemed to the minted tokens, so the handler parses, dispatches,
// audits and answers, and writes nothing of a grant itself (#437).
type TokenIssuer interface {
	IssueAuthorizationCodeGrant(ctx context.Context, settings *models.Settings, code *models.Code) (*oauth.TokenResponse, error)
	IssueClientCredentialsGrant(ctx context.Context, settings *models.Settings, client *models.Client, scope string) (*oauth.TokenResponse, error)
	IssueRefreshTokenGrant(ctx context.Context, settings *models.Settings, input *issuance.RefreshTokenGrantInput) (*oauth.TokenResponse, *issuance.RefreshOutcome, error)
	// IssuePasswordGrant issues the resource owner password credentials grant, RFC 6749 section 4.3.
	// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.
	IssuePasswordGrant(ctx context.Context, settings *models.Settings, input *issuance.ROPCGrantInput) (*oauth.TokenResponse, error)
}

// ImplicitTokenIssuer is the one issuance /auth/issue performs itself: the implicit grant's tokens,
// signed in a transaction that takes the session row first (#197). The token endpoint issues the other
// four grants, through TokenIssuer.
type ImplicitTokenIssuer interface {
	IssueImplicitTx(ctx context.Context, settings *models.Settings, input *issuance.ImplicitGrantInput, issueAccessToken bool, issueIdToken bool) (*issuance.ImplicitGrantResponse, error)
}

type AuthorizeValidator interface {
	ValidateScopes(ctx context.Context, scope string) error
	ValidateClientAndRedirectURI(ctx context.Context, input *protocolvalidation.ValidateClientAndRedirectURIInput) error
	ValidateRequest(input *protocolvalidation.ValidateRequestInput) error
	ValidatePrompt(prompt string) (string, error)
	ValidateUnsupportedRequestParameters(input *protocolvalidation.ValidateUnsupportedRequestParametersInput) error
}

// CodeIssuer issues an authorization code in a transaction of its own, which takes the session row
// before the insert (#139). The handler opens no transaction for it.
type CodeIssuer interface {
	IssueAuthCodeTx(ctx context.Context, input *issuance.CreateCodeInput) (*models.Code, error)
}

type UserSessionManager interface {
	HasValidUserSession(userSession *models.UserSession, idleTimeoutInSeconds int, maxLifetimeInSeconds int, requestedMaxAgeInSeconds *int64) bool
	StartNewUserSession(w http.ResponseWriter, r *http.Request,
		userId int64, clientId int64, authMethods string, acrLevel models.AcrLevel,
		authStateGeneration int64, otpConfigGeneration *int64,
		authenticatedAt *time.Time, ipAddress string,
		replacing *models.UserSession) (*models.UserSession, []models.UserSession, error)

	// BumpUserSession updates an existing session's last accessed time and client list.
	// It also handles ACR/AMR step-up: if the user completed a higher level of authentication
	// (e.g., added OTP to a password-only session), the session's AuthMethods and AcrLevel
	// are upgraded to reflect the stronger authentication that was performed.
	// Note: ACR is only upgraded, never downgraded, during a session's lifetime.
	// A non-empty ipAddress replaces the session's recorded address; empty leaves it.
	BumpUserSession(ctx context.Context, sessionIdentifier string, clientId int64,
		authMethods string, acrLevel models.AcrLevel, ipAddress string) (*models.UserSession, error)
}

type TokenValidator interface {
	ValidateTokenRequest(ctx context.Context, settings *models.Settings, input *protocolvalidation.ValidateTokenRequestInput) (protocolvalidation.TokenGrant, error)
}

type TokenParser interface {
	DecodeAndValidateTokenString(ctx context.Context, token string, withExpirationCheck bool) (*oauth.JwtToken, error)
}

// AuditLogger records one security event. The context is first because every audit event raised
// while serving a request is correlated to that request: the installed slog handler reads chi's
// request id off it, so the console record joins the request's own log line, and the persisted row
// carries the same id. A call that passed context.Background() here would produce exactly the
// uncorrelated record this exists to prevent, which is why guard.AssertAuditLogContext refuses
// one in a request-path package (#328).
type AuditLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}

// CredentialFailureRecorder marks the credential check this request performed as failed, so
// the rate limiter charges the reservation it is holding instead of dropping it.
//
// A handler names no bucket and no key: the limiter chose those before the handler ran, and
// a handler that derived them again would be free to disagree with the limiter about which
// account the request is, which is exactly how the per-account tiers came to be worth
// nothing (#219). *middleware.RateLimiterMiddleware satisfies it, and the call is a
// no-op on a request that carries no reservation.
type CredentialFailureRecorder interface {
	RecordCredentialFailure(r *http.Request)
}

type PermissionChecker interface {
	FilterOutScopesWhereUserIsNotAuthorized(ctx context.Context, scope string, user *models.User) (string, error)
}
