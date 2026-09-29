package issuance

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

type GenerateTokenForRefreshInput struct {
	Code             *models.Code
	ScopeRequested   string
	RefreshToken     *models.RefreshToken
	RefreshTokenInfo *oauth.JwtToken
}

// GenerateTokenForRefreshROPCInput is the input for refreshing ROPC tokens.
// Unlike auth code flow, ROPC tokens have UserId and ClientId directly on the RefreshToken.
type GenerateTokenForRefreshROPCInput struct {
	RefreshToken     *models.RefreshToken
	ScopeRequested   string
	RefreshTokenInfo *oauth.JwtToken
}

func (t *TokenIssuer) GenerateTokenResponseForRefresh(ctx context.Context, settings *models.Settings,
	input *GenerateTokenForRefreshInput) (*oauth.TokenResponse, error) {

	err := t.database.CodeLoadClient(ctx, nil, input.Code)
	if err != nil {
		return nil, err
	}

	scopeToUse := input.Code.Scope
	if len(input.ScopeRequested) > 0 {
		scopeToUse = input.ScopeRequested
	}

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if input.Code.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = input.Code.Client.TokenExpirationInSeconds
	}

	var tokenResponse = oauth.TokenResponse{
		TokenType: TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	privKey, keyIdentifier, err := t.loadSigningKey(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	// access_token -----------------------------------------------------------------------

	err = t.database.CodeLoadUser(ctx, nil, input.Code)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadGroups(ctx, nil, &input.Code.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(ctx, nil, input.Code.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(ctx, nil, &input.Code.User)
	if err != nil {
		return nil, err
	}

	// The PARENT refresh token is the authorizing credential here, not the code.
	accessTokenStr, err := t.generateAccessToken(ctx, settings, input.Code, scopeToUse, now, privKey, keyIdentifier, input.RefreshToken)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = accessTokenStr
	tokenResponse.Scope = scopeToUse

	// id_token ---------------------------------------------------------------------------

	scopes := strings.Split(scopeToUse, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, idTokenErr := t.generateIdToken(ctx, settings, input.Code, scopeToUse, now, privKey, keyIdentifier)
		if idTokenErr != nil {
			return nil, idTokenErr
		}
		tokenResponse.IdToken = idTokenStr
	}

	// refresh_token ----------------------------------------------------------------------

	// RFC 6749 Section 6: New refresh token scope MUST be identical to the original refresh token's scope
	originalRefreshTokenScope := input.RefreshToken.Scope
	refreshToken, refreshExpiresIn, err := t.generateRefreshToken(ctx, settings, input.Code, originalRefreshTokenScope, now, privKey, keyIdentifier, input.RefreshToken)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = refreshToken
	tokenResponse.RefreshExpiresIn = refreshExpiresIn

	return &tokenResponse, nil
}

// GenerateTokenResponseForRefreshROPC generates new tokens for an ROPC refresh token.
// Unlike auth code flow, ROPC tokens have UserId and ClientId directly on the RefreshToken.
func (t *TokenIssuer) GenerateTokenResponseForRefreshROPC(ctx context.Context, settings *models.Settings,
	input *GenerateTokenForRefreshROPCInput) (*oauth.TokenResponse, error) {

	// The token endpoint refuses a token with no instant before it gets here: without one there is
	// no auth_time this refresh could issue that OpenID Connect Core 1.0 section 12.2 allows (#125).
	if !input.RefreshToken.AuthenticatedAt.Valid {
		return nil, errs.New("the ROPC refresh token records no authentication instant")
	}

	// Load the User and Client from the refresh token
	err := t.database.RefreshTokenLoadUser(ctx, nil, input.RefreshToken)
	if err != nil {
		return nil, err
	}

	err = t.database.RefreshTokenLoadClient(ctx, nil, input.RefreshToken)
	if err != nil {
		return nil, err
	}

	scopeToUse := input.RefreshToken.Scope
	if len(input.ScopeRequested) > 0 {
		scopeToUse = input.ScopeRequested
	}

	tokenExpirationInSeconds := settings.TokenExpirationInSeconds
	if input.RefreshToken.Client.TokenExpirationInSeconds > 0 {
		tokenExpirationInSeconds = input.RefreshToken.Client.TokenExpirationInSeconds
	}

	var tokenResponse = oauth.TokenResponse{
		TokenType: TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	privKey, keyIdentifier, err := t.loadSigningKey(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	// Load user groups and attributes for token claims
	err = t.database.UserLoadGroups(ctx, nil, &input.RefreshToken.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(ctx, nil, input.RefreshToken.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(ctx, nil, &input.RefreshToken.User)
	if err != nil {
		return nil, err
	}

	// Create ROPCGrantInput for token generation. The instant is the parent's, so every token of
	// the family reports the password check that started it, not this refresh (#125).
	ropcInput := &ROPCGrantInput{
		Client:          &input.RefreshToken.Client,
		User:            &input.RefreshToken.User,
		Scope:           scopeToUse,
		AuthenticatedAt: input.RefreshToken.AuthenticatedAt.Time,
	}

	// access_token -----------------------------------------------------------------------

	// The parent refresh token authorizes this, not the reloaded user.
	accessTokenStr, err := t.generateROPCAccessToken(ctx, settings, ropcInput, scopeToUse, now, privKey, keyIdentifier, input.RefreshToken)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = accessTokenStr
	tokenResponse.Scope = scopeToUse

	// id_token ---------------------------------------------------------------------------

	scopes := strings.Split(scopeToUse, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, idTokenErr := t.generateROPCIdToken(ctx, settings, ropcInput, scopeToUse, now, privKey, keyIdentifier)
		if idTokenErr != nil {
			return nil, idTokenErr
		}
		tokenResponse.IdToken = idTokenStr
	}

	// refresh_token ----------------------------------------------------------------------

	// RFC 6749 Section 6: New refresh token scope MUST be identical to the original refresh token's scope
	originalRefreshTokenScope := input.RefreshToken.Scope
	refreshToken, refreshExpiresIn, err := t.generateRefreshTokenForROPC(ctx, settings, ropcInput, originalRefreshTokenScope, now, privKey, keyIdentifier, input.RefreshToken)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = refreshToken
	tokenResponse.RefreshExpiresIn = refreshExpiresIn

	return &tokenResponse, nil
}
