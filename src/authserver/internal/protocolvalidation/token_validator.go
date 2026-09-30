package protocolvalidation

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/leodip/goiabada/core/errs"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/permissions"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/oauth"
)

type PermissionChecker interface {
	UserHasScopePermission(ctx context.Context, userId int64, scope string) (bool, error)
}

type TokenParser interface {
	DecodeAndValidateTokenString(ctx context.Context, token string, withExpirationCheck bool) (*oauth.JwtToken, error)
}

// tokenValidatorDatabase is what the token request validator needs: the client, the grant being
// presented, and the consent and permissions that decide the scope.
type tokenValidatorDatabase interface {
	permissions.ScopeResolverDatabase

	ClientLoadPermissions(ctx context.Context, tx *sql.Tx, client *models.Client) error
	ClientLoadRedirectURIs(ctx context.Context, tx *sql.Tx, client *models.Client) error
	CodeLoadClient(ctx context.Context, tx *sql.Tx, code *models.Code) error
	CodeLoadUser(ctx context.Context, tx *sql.Tx, code *models.Code) error
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*models.Client, error)
	GetCodeByCodeHash(ctx context.Context, tx *sql.Tx, codeHash string, used bool) (*models.Code, error)
	GetConsentByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) (*models.UserConsent, error)
	GetRefreshTokenByJti(ctx context.Context, tx *sql.Tx, jti string) (*models.RefreshToken, error)
	GetUserByEmail(ctx context.Context, tx *sql.Tx, email string) (*models.User, error)
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*models.User, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error)
	IsRefreshTokenFamilyRevoked(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string) (bool, error)
	PermissionsLoadResources(ctx context.Context, tx *sql.Tx, permissions []models.Permission) error
	RefreshTokenLoadClient(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	RefreshTokenLoadCode(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	RefreshTokenLoadUser(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	UserLoadGroups(ctx context.Context, tx *sql.Tx, user *models.User) error
	UserLoadPermissions(ctx context.Context, tx *sql.Tx, user *models.User) error
}

type TokenValidator struct {
	database          tokenValidatorDatabase
	tokenParser       TokenParser
	permissionChecker PermissionChecker
	dataCipher        *encryption.DataCipher
}

func NewTokenValidator(database tokenValidatorDatabase, tokenParser TokenParser,
	permissionChecker PermissionChecker, dataCipher *encryption.DataCipher) *TokenValidator {
	return &TokenValidator{
		database:          database,
		tokenParser:       tokenParser,
		permissionChecker: permissionChecker,
		dataCipher:        dataCipher,
	}
}

type ValidateTokenRequestInput struct {
	GrantType    oidc.GrantType
	Code         string
	RedirectURI  string
	CodeVerifier string
	ClientId     string
	ClientSecret string
	Scope        string
	RefreshToken string
	// Username and Password are used for ROPC grant (RFC 6749 Section 4.3)
	Username string
	Password string
}

// TokenGrant is what a validated token request is: one type per grant, declared beside the method
// that validates it in token_grant_<grant>.go and carrying only what that grant proved. The token
// handler dispatches on the type, where it used to infer the grant from which fields of one shared
// result were filled, the refresh token's shape included, which a nil code entity stood for (#437).
type TokenGrant interface {
	GrantType() oidc.GrantType
}

// ValidateTokenRequest validates a token endpoint request. It checks what every grant shares, the
// client_id, the client and whether it is enabled, and then hands the request to the grant's own
// method, one per grant in token_grant_<grant>.go (#437).
func (val *TokenValidator) ValidateTokenRequest(ctx context.Context, settings *models.Settings,
	input *ValidateTokenRequestInput) (TokenGrant, error) {

	if len(input.ClientId) == 0 {
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"Missing required client_id parameter.", http.StatusBadRequest)
	}

	client, err := val.database.GetClientByClientIdentifier(ctx, nil, input.ClientId)
	if err != nil {
		return nil, err
	}
	// An unknown client and a disabled one are failed client authentications, RFC 6749 section
	// 5.2's invalid_client, whose own example is the unknown client: until #437 they answered
	// invalid_request and invalid_grant at 400. The descriptions are unchanged.
	if client == nil {
		return nil, invalidClientError(clientDoesNotExistErrorMsg)
	}
	if !client.Enabled {
		return nil, invalidClientError(clientDisabledErrorMsg)
	}

	// Whether the grant is redeemed here at all is the grant table's answer, read after the
	// client checks above so an unknown client is still answered first, as it always was (#437).
	if !input.GrantType.AcceptedAtTokenEndpoint() {
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("unsupported_grant_type", "Unsupported grant_type.",
			http.StatusBadRequest)
	}

	switch input.GrantType {
	case oidc.GrantTypeAuthorizationCode:
		return asTokenGrant(val.validateAuthorizationCodeGrant(ctx, client, input))
	case oidc.GrantTypeClientCredentials:
		return asTokenGrant(val.validateClientCredentialsGrant(ctx, client, input))
	case oidc.GrantTypeRefreshToken:
		return asTokenGrant(val.validateRefreshTokenGrant(ctx, settings, client, input))
	case oidc.GrantTypePassword:
		return asTokenGrant(val.validatePasswordGrant(ctx, settings, client, input))
	default:
		// Reachable only if the grant table accepts a grant this switch has no arm for; the
		// validator's tests hold the two in agreement.
		return nil, errs.Errorf("grant type %q is accepted at the token endpoint but has no validation", input.GrantType)
	}
}

// asTokenGrant hands a grant method's answer back as a TokenGrant. A refusal comes back as a nil
// interface, never as an interface holding a nil pointer, which compares unequal to nil and would
// read as a grant to any caller that checked the grant rather than the error.
func asTokenGrant[G TokenGrant](grant G, err error) (TokenGrant, error) {
	if err != nil {
		return nil, err
	}
	return grant, nil
}
