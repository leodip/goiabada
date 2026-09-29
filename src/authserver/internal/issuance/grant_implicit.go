package issuance

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/leodip/goiabada/authserver/internal/models"
)

// ImplicitGrantInput contains the parameters needed to generate tokens for implicit flow.
// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1.
type ImplicitGrantInput struct {
	Client            *models.Client
	User              *models.User
	Scope             string
	AcrLevel          models.AcrLevel
	AuthMethods       string
	SessionIdentifier string
	Nonce             string
	AuthenticatedAt   time.Time
	// AuthStateGeneration comes from the AuthContext. Implicit issues no refresh token,
	// so this ceremony's own generation is the only possible source (#106 decision 13).
	AuthStateGeneration int64
}

// ImplicitGrantResponse contains the tokens generated for implicit flow.
// Per RFC 6749 4.2.2, NO refresh token is issued for implicit flow.
type ImplicitGrantResponse struct {
	AccessToken string
	IdToken     string
	TokenType   string
	ExpiresIn   int64
	Scope       string
}

// GenerateTokenResponseForImplicit creates tokens for the OAuth2/OIDC implicit flow.
// Per RFC 6749 4.2.2, NO refresh token is issued.
// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1.
func (t *TokenIssuer) GenerateTokenResponseForImplicit(ctx context.Context, settings *models.Settings,
	input *ImplicitGrantInput, issueAccessToken bool, issueIdToken bool) (*ImplicitGrantResponse, error) {

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if input.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = input.Client.TokenExpirationInSeconds
	}

	response := &ImplicitGrantResponse{
		TokenType: TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	privKey, keyIdentifier, err := t.loadSigningKey(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	// Load user groups and attributes for token claims
	err = t.database.UserLoadGroups(ctx, nil, input.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(ctx, nil, input.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(ctx, nil, input.User)
	if err != nil {
		return nil, err
	}

	response.Scope = input.Scope

	// Generate access token if requested (response_type contains "token")
	if issueAccessToken {
		accessToken, err := t.generateImplicitAccessToken(ctx, settings, input, now, privKey, keyIdentifier)
		if err != nil {
			return nil, err
		}
		response.AccessToken = accessToken
	}

	// Generate id_token if requested (response_type contains "id_token")
	if issueIdToken {
		// For id_token token response, include at_hash in id_token (OIDC Core 3.2.2.10)
		idToken, err := t.generateImplicitIdToken(ctx, settings, input, now, privKey, keyIdentifier, response.AccessToken)
		if err != nil {
			return nil, err
		}
		response.IdToken = idToken
	}

	return response, nil
}

// generateImplicitAccessToken creates an access token for implicit flow.
func (t *TokenIssuer) generateImplicitAccessToken(ctx context.Context, settings *models.Settings, input *ImplicitGrantInput,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	tokenInput := t.createTokenInputFromImplicit(input)
	return t.generateAccessTokenCore(ctx, settings, tokenInput, now, signingKey, keyIdentifier)
}

// generateImplicitIdToken creates an id_token for implicit flow.
// Per OIDC Core 3.2.2.10, at_hash is REQUIRED when id_token is issued alongside access_token.
func (t *TokenIssuer) generateImplicitIdToken(ctx context.Context, settings *models.Settings, input *ImplicitGrantInput,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string, accessToken string) (string, error) {

	tokenInput := t.createTokenInputFromImplicit(input)
	tokenInput.AccessToken = accessToken // For at_hash claim
	return t.generateIdTokenCore(ctx, settings, tokenInput, now, signingKey, keyIdentifier)
}
